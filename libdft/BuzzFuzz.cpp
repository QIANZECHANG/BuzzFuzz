#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>

#include <map>
#include <string>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/net.h>

#include "pin.H"

#include "branch_pred.h"
#include "libdft_api.h"
#include "syscall_desc.h"
#include "tagmap.h"

extern syscall_desc_t syscall_desc[SYSCALL_MAX];

#define MAX_COLOR 0x80

void
alert(uintptr_t addr, uint8_t tag)
{
  fprintf(stderr, "\n(BuzzFuzz) !!!!!!! ADDRESS 0x%x IS TAINTED (tag=0x%02x), ABORTING !!!!!!!\n",
          addr, tag);
  exit(1);
}

/* ------- TAINT SOURCES ------- */
static void
post_read_hook(syscall_ctx_t *ctx)
{
  int fd     =    (int)ctx->arg[SYSCALL_ARG0];
  void *buf  =  (void*)ctx->arg[SYSCALL_ARG1];
  size_t len = (size_t)ctx->ret;
  uint8_t color;
  static uint8_t next_color = 0x01;

  if(unlikely(len <= 0)) {
    return;
  }

  fprintf(stderr, "(BuzzFuzz) read: %zu bytes from fd %u\n", len, fd);

  color = tagmap_getb((uintptr_t)buf);
  if(!color) {
    color = next_color;
    fprintf(stderr, "(BuzzFuzz_read) tainting bytes %p -- 0x%x with color 0x%x\n", 
            buf, (uintptr_t)buf+len, color);

    tagmap_setn((uintptr_t)buf, len, color);
    if(next_color < MAX_COLOR) next_color <<= 1;
  } else {
    alert((uintptr_t)buf,color);
   }
}

static void
post_mmap_hook(syscall_ctx_t *ctx){
  size_t len = (size_t)ctx->arg[SYSCALL_ARG1];
  void *addr = (void*)ctx->ret;
  uint8_t color;
  void* len_addr=&len;

  color = tagmap_getb((uintptr_t)len_addr);
  if(color){
    fprintf(stderr, "(BuzzFuzz_mmap) tainting bytes %p -- 0x%x with color 0x%x\n",
            addr, (uintptr_t)addr+len, color);
    tagmap_setn((uintptr_t)addr,len,color);
  }else{
    fprintf(stderr, "(BuzzFuzz_mmap) clearing taint on bytes %p -- 0x%x\n",
            addr, (uintptr_t)addr+len);
    tagmap_clrn((uintptr_t)addr,len);
  }
}

int
main(int argc, char **argv)
{
  PIN_InitSymbols();

  if(unlikely(PIN_Init(argc, argv))) {
    return 1;
  }

  if(unlikely(libdft_init() != 0)) {
    libdft_die();
    return 1;
  }

  syscall_set_post(&syscall_desc[__NR_read], post_read_hook);
  syscall_set_post(&syscall_desc[__NR_mmap], post_mmap_hook);

  PIN_StartProgram();
	
  return 0;
}

