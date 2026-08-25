#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/prctl.h>
int main(void) {
  char buf[256];
  int fd, n, i;
  FILE *out;
  prctl(PR_SET_NAME, "E1C6RD", 0, 0, 0);
  for (;;) {
    if (access("/data/local/tmp/readnow", F_OK) == 0) {
      out = fopen("/data/local/tmp/e1c6_slot.txt", "w");
      if (out) {
        fprintf(out, "pid=%d\n", getpid());
        for (i = 0; i < 40; i++) {
          fd = open("/proc/sys/vm/user_reserve_kbytes", O_RDONLY);
          if (fd >= 0) {
            n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n > 0) {
              buf[n] = 0;
              fprintf(out, "%s", buf);
              if (buf[n-1] != '\n') fputc('\n', out);
            }
          }
        }
        fclose(out);
      }
      unlink("/data/local/tmp/readnow");
    }
    usleep(200000);
  }
}