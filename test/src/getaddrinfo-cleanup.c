#include <assert.h>
#include <netdb.h>
#include <stdlib.h>
#include <wasi/wasip2.h>

static int mode, step, stream_live, pollable_live, fail_malloc;
enum { STREAM = 0x70000000, POLLABLE };

void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size) {
  if (fail_malloc) {
    fail_malloc = 0;
    return NULL;
  }
  return __real_malloc(size);
}

bool __wrap_ip_name_lookup_resolve_addresses(
    ip_name_lookup_borrow_network_t network, wasip2_string_t *name,
    ip_name_lookup_own_resolve_address_stream_t *ret,
    ip_name_lookup_error_code_t *err) {
  assert(!stream_live && !pollable_live);
  stream_live = 1;
  step = 0;
  ret->__handle = STREAM;
  return true;
}

bool __wrap_ip_name_lookup_method_resolve_address_stream_resolve_next_address(
    ip_name_lookup_borrow_resolve_address_stream_t self,
    ip_name_lookup_option_ip_address_t *ret, ip_name_lookup_error_code_t *err) {
  assert(self.__handle == STREAM && stream_live);
  if (step++ == 0 && mode < 3) {
    *err = NETWORK_ERROR_CODE_WOULD_BLOCK;
    return false;
  }
  if (mode % 3 == 1) {
    *err = NETWORK_ERROR_CODE_TEMPORARY_RESOLVER_FAILURE;
    return false;
  }
  *ret = (ip_name_lookup_option_ip_address_t){0};
  ret->is_some = step == (mode < 3 ? 2 : 1);
  ret->val.tag = NETWORK_IP_ADDRESS_IPV4;
  ret->val.val.ipv4.f0 = 127;
  ret->val.val.ipv4.f3 = 1;
  if (mode % 3 == 2)
    fail_malloc = 1;
  return true;
}

ip_name_lookup_own_pollable_t
__wrap_ip_name_lookup_method_resolve_address_stream_subscribe(
    ip_name_lookup_borrow_resolve_address_stream_t self) {
  assert(self.__handle == STREAM && stream_live && !pollable_live);
  pollable_live = 1;
  return (ip_name_lookup_own_pollable_t){POLLABLE};
}

void __wrap_ip_name_lookup_resolve_address_stream_drop_own(
    ip_name_lookup_own_resolve_address_stream_t self) {
  assert(self.__handle == STREAM && stream_live && !pollable_live);
  stream_live = 0;
}

void __real_poll_pollable_drop_own(poll_own_pollable_t self);
void __wrap_poll_pollable_drop_own(poll_own_pollable_t self) {
  if (self.__handle != POLLABLE) {
    __real_poll_pollable_drop_own(self);
    return;
  }
  assert(stream_live && pollable_live);
  pollable_live = 0;
}

void __real_poll_method_pollable_block(poll_borrow_pollable_t self);
void __wrap_poll_method_pollable_block(poll_borrow_pollable_t self) {
  if (self.__handle != POLLABLE) {
    __real_poll_method_pollable_block(self);
    return;
  }
  assert(stream_live && pollable_live);
}

int main(void) {
  struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
  for (int i = 0; i < 192; i++) {
    struct addrinfo *addresses = NULL;
    mode = i % 6;
    int ret = getaddrinfo("cleanup.invalid", "443", &hints, &addresses);
    assert(ret == (mode % 3 == 1 ? EAI_AGAIN : mode % 3 == 2 ? EAI_MEMORY : 0));
    assert(!stream_live && !pollable_live && !fail_malloc);
    if (mode % 3 == 0)
      assert(addresses != NULL && addresses->ai_family == AF_INET);
    freeaddrinfo(addresses);
  }
}
