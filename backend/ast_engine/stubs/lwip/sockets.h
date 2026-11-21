// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct sockaddr { uint8_t sa_len; uint8_t sa_family; char sa_data[14]; };
struct addrinfo { int ai_flags; int ai_family; int ai_socktype; int ai_protocol; struct sockaddr *ai_addr; struct addrinfo *ai_next; };
typedef uint32_t socklen_t;
#define AF_INET 2
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
int socket(int domain, int type, int protocol);
int connect(int s, const struct sockaddr *name, socklen_t namelen);
int send(int s, const void *dataptr, size_t size, int flags);
int sendto(int s, const void *dataptr, size_t size, int flags, const struct sockaddr *to, socklen_t tolen);
int recv(int s, void *mem, size_t len, int flags);
int close(int s);
int getaddrinfo(const char *nodename, const char *servname, const struct addrinfo *hints, struct addrinfo **res);
#ifdef __cplusplus
}
#endif
