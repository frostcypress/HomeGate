/* MIT. Temporary version-only launcher; never installed as a service/tool. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t interrupted;
static void stop(int sig) { interrupted = sig; }
static long long monotonic_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static int finish(pid_t child, int result) {
    int status;
    /* WNOWAIT keeps the direct child unreaped: its PID/PGID cannot be reused
     * before these signals. Always clean the group before reaping the child. */
    (void)kill(-child, SIGKILL);
    (void)kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 125;
    }
    return result;
}
int main(int argc, char **argv) {
    const char *path, *name, *arg;
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "--nginx")) {
        path = "./nginx"; name = "nginx"; arg = "-V";
    } else if (!strcmp(argv[1], "--wol")) {
        path = "./wol-send"; name = "wol-send"; arg = "--version";
    } else return 2;
    struct sigaction reaper = {0}, sa = {0};
    reaper.sa_handler = SIG_DFL;
    sigemptyset(&reaper.sa_mask);
    /* An inherited SIGCHLD=SIG_IGN would auto-reap and break PID ownership. */
    if (sigaction(SIGCHLD, &reaper, NULL) || sigprocmask(SIG_SETMASK, &reaper.sa_mask, NULL)) return 125;
    sa.sa_handler = stop;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) || sigaction(SIGTERM, &sa, NULL)) return 125;
    long long start = monotonic_ms();
    if (start < 0) return 125;
    pid_t parent = getpid(), child = fork();
    if (child < 0) return 125;
    if (!child) {
        if (setpgid(0, 0) || prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(126);
        sa.sa_handler = SIG_DFL;
        if (sigaction(SIGINT, &sa, NULL) || sigaction(SIGTERM, &sa, NULL)) _exit(126);
        execl(path, name, arg, (char *)NULL);
        perror("component exec");
        _exit(127);
    }
    if (setpgid(child, child) && getpgid(child) != child) {
        /* No component was allowed to exec without its own process group. */
        (void)kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        return 125;
    }
    for (;;) {
        siginfo_t info = {0};
        if (waitid(P_PID, child, &info, WEXITED | WNOHANG | WNOWAIT)) {
            if (errno == EINTR) continue;
            return finish(child, 125);
        }
        if (info.si_pid == child) {
            int result = info.si_code == CLD_EXITED ? info.si_status : 128 + info.si_status;
            return finish(child, result);
        }
        if (interrupted) return finish(child, 128 + interrupted);
        long long now = monotonic_ms();
        if (now < 0) return finish(child, 125);
        if (now - start >= 10000) {
            fputs("component version probe timed out (10s)\n", stderr);
            return finish(child, 124);
        }
        struct timespec pause = {0, 10000000};
        (void)nanosleep(&pause, NULL);
    }
}
