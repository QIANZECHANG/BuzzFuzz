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

void
alert(uintptr_t addr, uint8_t tag)
{
  printf("\n(BuzzFuzz) !!!!!!! ADDRESS 0x%x IS TAINTED (tag=0x%02x), ABORTING !!!!!!!\n",
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
  uint8_t color=0x01;

  if(unlikely(len <= 0)) {
    return;
  }

  printf("(BuzzFuzz) read: %zu bytes from fd %u\n", len, fd);
  printf("(BuzzFuzz_read) tainting bytes %p -- 0x%x with color 0x%x\n", 
          buf, (uintptr_t)buf+len, color);

  tagmap_setn((uintptr_t)buf, len, color); 
}
static void
post_mmap2_hook(syscall_ctx_t *ctx){
  size_t len = (size_t)ctx->arg[SYSCALL_ARG1];
  uint8_t color;

  printf("map_len_addr : %p\n",&ctx->arg[SYSCALL_ARG1]);
  color = tagmap_getb((uintptr_t)&len);
  if(color){
    alert((uintptr_t)&len,color);
  }else{
    return;
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
  syscall_set_pre(&syscall_desc[__NR_mmap2], post_mmap2_hook);

  PIN_StartProgram();
	
  return 0;
}

