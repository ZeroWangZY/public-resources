// server.cpp
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "httplib.h"

struct ExecResult {
  bool ok;
  int exit_code;
  bool timed_out;
  std::string output;
  std::string error;
};

static const std::unordered_map<std::string, std::vector<std::string>> kTasks = {
    {"date", {"/bin/date"}},
    {"uptime", {"/usr/bin/uptime"}},
    {"df", {"/bin/df", "-h"}},
    {"mem", {"/usr/bin/free", "-m"}},
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

ExecResult run_task(const std::string &task, int timeout_sec = 8) {
  auto it = kTasks.find(task);
  if (it == kTasks.end()) return {false, -1, false, "", "task not allowed"};

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

    std::vector<char *> argv;
    argv.reserve(it->second.size() + 1);
    for (const auto &s : it->second) argv.push_back(const_cast<char *>(s.c_str()));
    argv.push_back(nullptr);

    execv(argv[0], argv.data());
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
    res.set_content("{\"tasks\":[\"date\",\"uptime\",\"df\",\"mem\"]}", "application/json");
  });

  svr.Post(R"(/run/([A-Za-z0-9_-]+))", [](const httplib::Request &req, httplib::Response &res) {
    const char *token = std::getenv("CMD_SERVICE_TOKEN");
    std::string got = req.get_header_value("X-Token");
    if (!token || got != token) {
      res.status = 401;
      res.set_content("{\"error\":\"unauthorized\"}", "application/json");
      return;
    }

    std::string task = req.matches[1];
    ExecResult r = run_task(task);

    if (!r.ok) {
      res.status = 400;
      res.set_content("{\"error\":\"" + json_escape(r.error) + "\"}", "application/json");
      return;
    }

    std::string body = "{\"task\":\"" + json_escape(task) + "\",\"exit_code\":" +
                       std::to_string(r.exit_code) + ",\"timed_out\":" +
                       (r.timed_out ? "true" : "false") + ",\"output\":\"" +
                       json_escape(r.output) + "\"}";
    res.set_content(body, "application/json");
  });

  std::cout << "Listening on 0.0.0.0:8081\n";
  svr.listen("0.0.0.0", 8081);
}
