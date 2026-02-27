// server.cpp
#include <algorithm>
#include <cctype>
#include <fcntl.h>
#include <regex>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "httplib.h"

struct ExecResult {
  bool ok;
  int exit_code;
  bool timed_out;
  std::string output;
  std::string error;
};

std::string json_escape(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 16);
  for (char c : s) {
    switch (c) {
      case '\"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: out += c; break;
    }
  }
  return out;
}

std::string trim_copy(const std::string &s) {
  size_t start = 0;
  while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) start++;
  size_t end = s.size();
  while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) end--;
  return s.substr(start, end - start);
}

std::string to_lower_copy(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

std::string decode_json_string_like(const std::string &s) {
  if (s.size() < 2 || s.front() != '"' || s.back() != '"') return s;
  std::string out;
  out.reserve(s.size());
  for (size_t i = 1; i + 1 < s.size(); ++i) {
    char c = s[i];
    if (c != '\\') {
      out.push_back(c);
      continue;
    }
    if (i + 1 >= s.size() - 1) break;
    char n = s[++i];
    switch (n) {
      case 'n': out.push_back('\n'); break;
      case 'r': out.push_back('\r'); break;
      case 't': out.push_back('\t'); break;
      case 'b': out.push_back('\b'); break;
      case 'f': out.push_back('\f'); break;
      case '\\': out.push_back('\\'); break;
      case '"': out.push_back('"'); break;
      case '/': out.push_back('/'); break;
      default: out.push_back(n); break;
    }
  }
  return out;
}

bool is_blocked_command(const std::string &command, std::string &reason) {
  const std::string lower = to_lower_copy(command);

  if (lower.find("--no-preserve-root") != std::string::npos) {
    reason = "dangerous rm flag";
    return true;
  }

  static const std::regex kRmRootRf1(
      R"(\brm\b[^;&|]*-[^;&|]*r[^;&|]*f[^;&|]*\s+(/\s*($|[;&|])|/\*\s*($|[;&|])))");
  static const std::regex kRmRootRf2(
      R"(\brm\b[^;&|]*-[^;&|]*f[^;&|]*r[^;&|]*\s+(/\s*($|[;&|])|/\*\s*($|[;&|])))");
  if (std::regex_search(lower, kRmRootRf1) || std::regex_search(lower, kRmRootRf2)) {
    reason = "root filesystem deletion";
    return true;
  }

  static const std::vector<std::pair<std::regex, const char *>> kBlockedPatterns = {
      {std::regex(R"((^|[;&|])\s*(shutdown|reboot|halt|poweroff)\b)"),
       "power control command"},
      {std::regex(R"((^|[;&|])\s*init\s+[06]\b)"), "runlevel switch command"},
      {std::regex(R"((^|[;&|])\s*systemctl\s+(reboot|poweroff|halt)\b)"),
       "system power control command"},
      {std::regex(R"((^|[;&|])\s*(mkfs(\.[a-z0-9_+-]+)?|fdisk|sfdisk|parted|wipefs)\b)"),
       "disk formatting/partition command"},
      {std::regex(R"((^|[;&|])\s*dd\b)"), "raw disk copy command"},
      {std::regex(R"(\b(of|if)=/dev/(sd[a-z]\d*|vd[a-z]\d*|nvme\d+n\d+(p\d+)?)\b)"),
       "block-device access argument"},
      {std::regex(R"((^|[;&|])\s*:\s*>\s*/dev/(sd[a-z]\d*|vd[a-z]\d*|nvme\d+n\d+(p\d+)?)\b)"),
       "block-device overwrite"},
      {std::regex(R"((^|[;&|])\s*kill\s+-9\s+-?1\b)"), "kill-all command"},
  };

  for (const auto &item : kBlockedPatterns) {
    if (std::regex_search(lower, item.first)) {
      reason = item.second;
      return true;
    }
  }
  return false;
}

ExecResult run_command(const std::string &command, int timeout_sec = 20) {
  const std::string trimmed = trim_copy(command);
  if (trimmed.empty()) return {false, -1, false, "", "empty command"};
  if (trimmed.size() > 4096) return {false, -1, false, "", "command too long (max 4096 chars)"};

  std::string blocked_reason;
  if (is_blocked_command(trimmed, blocked_reason)) {
    return {false, -1, false, "", "blocked command: " + blocked_reason};
  }

  int pipefd[2];
  if (pipe(pipefd) != 0) return {false, -1, false, "", "pipe failed"};

  int flags = fcntl(pipefd[0], F_GETFL, 0);
  fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

  pid_t pid = fork();
  if (pid < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    return {false, -1, false, "", "fork failed"};
  }

  if (pid == 0) {
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[0]);
    close(pipefd[1]);

    char *const argv[] = {const_cast<char *>("bash"), const_cast<char *>("-lc"),
                          const_cast<char *>(trimmed.c_str()), nullptr};
    execv("/bin/bash", argv);
    _exit(127);
  }

  close(pipefd[1]);

  std::string output;
  char buf[4096];
  int status = 0;
  bool timed_out = false;
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec);

  while (true) {
    ssize_t n = read(pipefd[0], buf, sizeof(buf));
    if (n > 0) output.append(buf, n);

    pid_t ret = waitpid(pid, &status, WNOHANG);
    if (ret == pid) break;

    if (std::chrono::steady_clock::now() > deadline) {
      timed_out = true;
      kill(pid, SIGKILL);
      waitpid(pid, &status, 0);
      break;
    }
    usleep(50000);
  }

  while (true) {
    ssize_t n = read(pipefd[0], buf, sizeof(buf));
    if (n > 0) output.append(buf, n);
    else break;
  }
  close(pipefd[0]);

  int code = timed_out ? -2 : (WIFEXITED(status) ? WEXITSTATUS(status) : -1);
  return {true, code, timed_out, output, ""};
}

int main() {
  httplib::Server svr;

  svr.Get("/health", [](const httplib::Request &, httplib::Response &res) {
    res.set_content("{\"ok\":true}", "application/json");
  });

  svr.Get("/tasks", [](const httplib::Request &, httplib::Response &res) {
    res.set_content(
        "{\"mode\":\"direct_command\",\"usage\":\"POST /run with raw command body\","
        "\"auth\":\"Authorization: Bearer <token>\"}",
                    "application/json");
  });

  auto parse_authorization = [](const std::string &value) -> std::string {
    std::string auth = trim_copy(value);
    if (auth.empty()) return "";
    std::string lower = to_lower_copy(auth);
    const std::string prefix = "bearer ";
    if (lower.rfind(prefix, 0) == 0) return trim_copy(auth.substr(prefix.size()));
    return auth;
  };

  auto authorize = [parse_authorization](const httplib::Request &req, httplib::Response &res) -> bool {
    const char *token = std::getenv("CMD_SERVICE_TOKEN");
    std::string got = parse_authorization(req.get_header_value("Authorization"));
    if (!token || got != token) {
      res.status = 401;
      res.set_content(
          "{\"error\":\"unauthorized: expected Authorization header (Bearer <token>)\"}",
          "application/json");
      return false;
    }
    return true;
  };

  auto render_result = [](const std::string &command, const ExecResult &r, httplib::Response &res) {
    if (!r.ok) {
      res.status = (r.error.rfind("blocked command:", 0) == 0) ? 403 : 400;
      res.set_content("{\"error\":\"" + json_escape(r.error) + "\"}", "application/json");
      return;
    }

    std::string body = "{\"command\":\"" + json_escape(command) + "\",\"exit_code\":" +
                       std::to_string(r.exit_code) + ",\"timed_out\":" +
                       (r.timed_out ? "true" : "false") + ",\"output\":\"" +
                       json_escape(r.output) + "\"}";
    res.set_content(body, "application/json");
  };

  svr.Post("/run", [authorize, render_result](const httplib::Request &req, httplib::Response &res) {
    if (!authorize(req, res)) return;

    std::string command = trim_copy(req.body);
    command = trim_copy(decode_json_string_like(command));
    if (command.empty()) {
      res.status = 400;
      res.set_content("{\"error\":\"missing command: send command in request body\"}",
                      "application/json");
      return;
    }

    ExecResult r = run_command(command);
    render_result(command, r, res);
  });

  std::cout << "Listening on 0.0.0.0:8081\n";
  svr.listen("0.0.0.0", 8081);
}
