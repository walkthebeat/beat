// The seccomp filters for sandboxes in a pod (sensor/src/bwrap.rs), as BPF on stdout for bwrap --seccomp FD:
//   mk            a question's: systemd's RestrictAddressFamilies=AF_UNIX AF_NETLINK: socket() and socketpair() with
//                 any other family fail with EAFNOSUPPORT
//   mk capture    capture()'s tcpdump's, as its unit (capture.rs CAPTURE_UNIT): AF_PACKET and AF_UNIX only, and
//                 sendto, sendmsg, sendmmsg fail with EPERM (defence in depth: write() on a packet socket also sends)
// Native architecture only: any other (i386 on x86_64) is killed (libseccomp's default).
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
int main(int argc, char **argv) {
    int capture = argc > 1 && strcmp(argv[1], "capture") == 0;
    int other = capture ? AF_PACKET : AF_NETLINK;
    scmp_filter_ctx c = seccomp_init(SCMP_ACT_ALLOW);
    if (!c) return 1;
    int sys[] = {SCMP_SYS(socket), SCMP_SYS(socketpair)};
    for (int i = 0; i < 2; i++) {
        for (int f = 0; f < AF_MAX; f++) {
            if (f == AF_UNIX || f == other) continue;
            if (seccomp_rule_add(c, SCMP_ACT_ERRNO(EAFNOSUPPORT), sys[i], 1, SCMP_A0(SCMP_CMP_EQ, f))) return 2;
        }
        if (seccomp_rule_add(c, SCMP_ACT_ERRNO(EAFNOSUPPORT), sys[i], 1, SCMP_A0(SCMP_CMP_GE, AF_MAX))) return 3;
    }
    if (capture) {
        int send[] = {SCMP_SYS(sendto), SCMP_SYS(sendmsg), SCMP_SYS(sendmmsg)};
        for (int i = 0; i < 3; i++)
            if (seccomp_rule_add(c, SCMP_ACT_ERRNO(EPERM), send[i], 0)) return 4;
    }
    return seccomp_export_bpf(c, fileno(stdout)) ? 5 : 0;
}
