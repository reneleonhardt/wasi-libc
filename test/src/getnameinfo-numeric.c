#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <string.h>

static int fail_ntop;

const char *__real_inet_ntop(int af, const void *src, char *dst,
                             socklen_t size);
const char *__wrap_inet_ntop(int af, const void *src, char *dst,
                             socklen_t size);
const char *__wrap_inet_ntop(int af, const void *src, char *dst,
                             socklen_t size) {
  if (fail_ntop) {
    errno = ENOSPC;
    return NULL;
  }
  return __real_inet_ntop(af, src, dst, size);
}

static void check(const struct sockaddr *sa, socklen_t len, int flags,
                  const char *expected_host, const char *expected_serv) {
  char host[80], serv[32];
  assert(getnameinfo(sa, len, host, sizeof(host), serv, sizeof(serv), flags) ==
         0);
  assert(strcmp(host, expected_host) == 0);
  assert(strcmp(serv, expected_serv) == 0);
}

int main(void) {
  struct sockaddr_in a4 = {.sin_family = AF_INET, .sin_port = htons(65535)};
  struct sockaddr_in6 a6 = {.sin6_family = AF_INET6, .sin6_port = htons(4242)};
  const struct sockaddr *sa = (const void *)&a4;
  const struct sockaddr *sa6 = (const void *)&a6;
  const int numeric = NI_NUMERICHOST | NI_NUMERICSERV;
  char host[80], serv[32];
  assert(inet_pton(AF_INET, "192.0.2.1", &a4.sin_addr) == 1);
  assert(inet_pton(AF_INET6, "::1", &a6.sin6_addr) == 1);
  check(sa, sizeof(a4), numeric, "192.0.2.1", "65535");
  check(sa6, sizeof(a6), numeric, "::1", "4242");
  a6.sin6_scope_id = UINT32_MAX;
  check(sa6, sizeof(a6), numeric | NI_NUMERICSCOPE, "::1%4294967295", "4242");
  check(sa6, sizeof(a6), NI_NOFQDN, "::1%4294967295", "4242");
  a6.sin6_scope_id = 0;
  assert(inet_pton(AF_INET6, "::ffff:192.0.2.1", &a6.sin6_addr) == 1);
  check(sa6, sizeof(a6), numeric, "::ffff:192.0.2.1", "4242");
  assert(inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                   &a6.sin6_addr) == 1);
  a6.sin6_scope_id = UINT32_MAX;
  const char *long_host = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295";
  check(sa6, sizeof(a6), numeric, long_host, "4242");

  for (socklen_t n = 0; n <= strlen(long_host) + 1; n++) {
    memset(host, '#', sizeof(host));
    memset(serv, '#', sizeof(serv));
    int ret = getnameinfo(sa6, sizeof(a6), host, n, serv, 6, numeric);
    assert(ret == (n > 0 && n <= strlen(long_host) ? EAI_OVERFLOW : 0));
    assert(host[n] == '#');
    if (ret != 0 || n == 0)
      assert(host[0] == '#');
    if (ret != 0)
      assert(serv[0] == '#');
    else {
      assert(strcmp(serv, "4242") == 0);
      if (n != 0)
        assert(strcmp(host, long_host) == 0);
    }
  }
  for (socklen_t n = 0; n <= 6; n++) {
    memset(host, '#', sizeof(host));
    memset(serv, '#', sizeof(serv));
    int ret = getnameinfo(sa, sizeof(a4), host, sizeof(host), serv, n, numeric);
    assert(ret == (n > 0 && n < 6 ? EAI_OVERFLOW : 0));
    assert(serv[n] == '#');
    if (ret != 0 || n == 0)
      assert(serv[0] == '#');
    if (ret != 0)
      assert(host[0] == '#');
    else {
      assert(strcmp(host, "192.0.2.1") == 0);
      if (n != 0)
        assert(strcmp(serv, "65535") == 0);
    }
  }

  a4.sin_port = htons(80);
  check(sa, sizeof(a4), 0, "192.0.2.1", "http");
  check(sa, sizeof(a4), NI_DGRAM, "192.0.2.1", "http");
  check(sa, sizeof(a4), numeric, "192.0.2.1", "80");
  a4.sin_port = htons(21);
  check(sa, sizeof(a4), 0, "192.0.2.1", "ftp");
  check(sa, sizeof(a4), NI_DGRAM, "192.0.2.1", "21");
  a4.sin_port = htons(20);
  check(sa, sizeof(a4), 0, "192.0.2.1", "ftp-data");
  a4.sin_port = htons(53);
  check(sa, sizeof(a4), NI_DGRAM, "192.0.2.1", "domain");
  a4.sin_port = 0;
  check(sa, sizeof(a4), 0, "192.0.2.1", "0");

  assert(getnameinfo(sa, sizeof(a4), host, sizeof(host), NULL, 0,
                     NI_NAMEREQD) == EAI_NONAME);
  assert(getnameinfo(sa, sizeof(a4), host, sizeof(host), NULL, 0,
                     numeric | NI_NAMEREQD) == EAI_NONAME);
  assert(getnameinfo(sa, sizeof(a4), host, 0, serv, sizeof(serv),
                     NI_NAMEREQD) == 0);
  assert(strcmp(serv, "0") == 0);
  assert(getnameinfo(sa, sizeof(a4), NULL, 99, serv, sizeof(serv), numeric) ==
         0);
  assert(getnameinfo(sa, sizeof(a4), host, sizeof(host), NULL, 99, numeric) ==
         0);
  assert(getnameinfo(sa, sizeof(a4), NULL, 0, NULL, 0, numeric) == EAI_NONAME);
  assert(getnameinfo(sa, sizeof(a4), host, 0, serv, 0, numeric) == EAI_NONAME);
  assert(getnameinfo(sa, sizeof(a4), host, sizeof(host), serv, sizeof(serv),
                     0x8000) == EAI_BADFLAGS);
  assert(getnameinfo(NULL, 0, host, sizeof(host), serv, sizeof(serv),
                     numeric) == EAI_FAMILY);
  for (socklen_t n = 0; n < sizeof(a4); n++)
    assert(getnameinfo(sa, n, host, sizeof(host), serv, sizeof(serv),
                       numeric) == EAI_FAMILY);
  for (socklen_t n = 0; n < sizeof(a6); n++)
    assert(getnameinfo(sa6, n, host, sizeof(host), serv, sizeof(serv),
                       numeric) == EAI_FAMILY);
  a4.sin_family = AF_UNSPEC;
  assert(getnameinfo(sa, sizeof(a4), host, sizeof(host), serv, sizeof(serv),
                     numeric) == EAI_FAMILY);
  a6.sin6_family = AF_UNSPEC;
  assert(getnameinfo(sa6, sizeof(a6), host, sizeof(host), serv, sizeof(serv),
                     numeric) == EAI_FAMILY);
  const void *end = (void *)(__builtin_wasm_memory_size(0) * 65536);
  assert(getnameinfo(end, 0, host, sizeof(host), serv, sizeof(serv), numeric) ==
         EAI_FAMILY);
  a4.sin_family = AF_INET;
  memset(host, '#', sizeof(host));
  memset(serv, '#', sizeof(serv));
  fail_ntop = 1;
  assert(getnameinfo(sa, sizeof(a4), host, sizeof(host), serv, sizeof(serv),
                     numeric) == EAI_SYSTEM);
  assert(errno == ENOSPC);
  for (size_t i = 0; i < sizeof(host); i++)
    assert(host[i] == '#');
  for (size_t i = 0; i < sizeof(serv); i++)
    assert(serv[i] == '#');
}
