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
extern REG thread_ctx_ptr;
size_t length;

typedef struct n{
    ADDRINT addr;
    struct n *left;
    struct n *right;
}node;

node* tree_head=NULL;

typedef struct _n{
    struct _n *next;
    struct n *node;
}node_list;

node* make_tree(ADDRINT addr,node* left,node* right){
    node* s;
    s=(node*)malloc(sizeof(node));
    s->addr=addr;
    s->left=left;
    s->right=right;
    return s;
}

node_list* node_list_head=NULL;

void add_node(node* node){
    node_list* s=node_list_head;

    while(s->next!=NULL)s=s->next;
    
    s->next=(node_list*)malloc(sizeof(node_list));
    s->next->next=NULL;
    s->next->node=node;
} 

node* check_node(ADDRINT addr){
    node_list* s;
    if(node_list_head==NULL){
        node_list_head=(node_list*)malloc(sizeof(node_list));
        node_list_head->next=NULL;
        node_list_head->node=NULL;
    }

    for(s=node_list_head->next;s!=NULL;s=s->next){
        if(s->node->addr==addr){
            return s->node;  
        }  
    }

    return NULL;
}

void print_addr(node* node){
    if(node->left==NULL&&node->right==NULL){
      printf("(print_addr) need to fuzz byte addr 0x%08x\n",node->addr);
      return;
    }
    print_addr(node->left);
    print_addr(node->right);
    
}

node* first=NULL;
node* second=NULL;

//jpegファイルの全部のバイトにcolorを付ける
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

  printf("(BuzzFuzz_read) read: %zu bytes from fd %u\n", len, fd);
  printf("(BuzzFuzz_read) tainting bytes %p -- 0x%x with color 0x%x\n", 
          buf, (uintptr_t)buf+len, color);

  tagmap_setn((uintptr_t)buf, len, color); 
  
}
/*
32bitでmmapがmmap２となる

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
第二引数（length）を注目する。colorがあるかどうかをcheck

*/

static void
pre_mmap2_hook(syscall_ctx_t *ctx){
  
  size_t len=ctx->arg[SYSCALL_ARG1];
  
  if(len==length){
    printf("(mmap2) /////////////Tainted!!! length : 0x%x\n",len);
    print_addr(tree_head);
    tree_head=NULL;
  }else{
    return;
  }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL
check_read_mem(ADDRINT addr)
{
        uint8_t color;
        color=tagmap_getb(addr);
        if(color){
            node* find_node=check_node(addr);
            if(find_node==NULL){
                node* new_node;
                new_node=make_tree(addr,NULL,NULL);
                second=first;
                first=new_node;
                add_node(new_node);
            }else{
                second=first;
                first=find_node;
            }
        }
        //printf("(check_mem) color : 0x%x , ADDR : %p\n",color,addr);
}

static ADDRINT PIN_FAST_ANALYSIS_CALL
check_write_mem(thread_ctx_t *thread_ctx, uint32_t reg,ADDRINT addr)
{
        uint8_t color;
        color=thread_ctx->vcpu.gpr[reg];
        if(color){
            node* new_node;
            new_node=make_tree(addr,first,second);
            add_node(new_node);
            tree_head=new_node;
        }
}


static ADDRINT PIN_FAST_ANALYSIS_CALL
check_reg(thread_ctx_t *thread_ctx, uint32_t reg,size_t value)
{
        uint8_t color;
	color=thread_ctx->vcpu.gpr[reg];
        if(color){
           length=value;
           //printf("(check_eax) color : 0x%x , value : 0x%x\n",color,value); 
        }
}

static void
dta(INS ins,void* v)
{
	IMG img = IMG_FindByAddress(INS_Address(ins));
        if(!IMG_Valid(img)||!IMG_IsMainExecutable(img))return;
        char* s;
        REG reg;
       // if(INS_OperandIsReg(ins,0)&&INS_OperandIsMemory(ins,1)){
       // if(INS_IsMemoryWrite(ins)){
       //         s=const_cast<char*>(/*INS_Mnemonic*/INS_Disassemble(ins).c_str());
               // printf("%s\n",s);

        //}
        /*if (INS_OperandIsReg(ins, 0)) {
         	reg = INS_OperandReg(ins, 0);
                
		INS_InsertCall(ins,
			IPOINT_BEFORE,
                        (AFUNPTR)taint_eax,
			IARG_REG_VALUE, reg,
			IARG_END);
	}*/
        s=const_cast<char*>(INS_Mnemonic(ins).c_str());
        /* read memory */
        if(INS_OperandIsReg(ins,0)&&INS_OperandIsMemory(ins,1)&&INS_IsMemoryRead(ins)){
                INS_InsertCall(ins,
                    IPOINT_BEFORE,
                    (AFUNPTR)check_read_mem,
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
        }

        /* write memory */
        if(INS_OperandIsReg(ins,1)&&INS_OperandIsMemory(ins,0)&&INS_IsMemoryWrite(ins)){
                reg= INS_OperandReg(ins,1);
                INS_InsertCall(ins,
                    IPOINT_BEFORE,
                    (AFUNPTR)check_write_mem,
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_REG_VALUE, thread_ctx_ptr,
                    IARG_UINT32, REG32_INDX(reg),
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
        }
       
 
        if(/*!(strcmp(s,"IMUL"))&&*/INS_OperandIsReg(ins,0)){//&&INS_OperandIsMemory(ins,1)&&INS_IsMemoryRead(ins)){
                s=const_cast<char*>(/*INS_Mnemonic*/INS_Disassemble(ins).c_str());
                //printf("%s\n",s);
                reg = INS_OperandReg(ins, 0);
                /*INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)check_mem,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,                        
			IARG_END);
               */
                if(INS_HasFallThrough(ins))
                INS_InsertCall(ins,
			IPOINT_AFTER,
			(AFUNPTR)check_reg,
			IARG_FAST_ANALYSIS_CALL,
			IARG_REG_VALUE, thread_ctx_ptr,
			IARG_UINT32, REG32_INDX(reg),
                        IARG_REG_VALUE,reg,
			IARG_END);
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
  syscall_set_pre(&syscall_desc[__NR_mmap2], pre_mmap2_hook);
  //ins_set_pre(&ins_desc[XED_ICLASS_MOVZX],dta_eax);
  INS_AddInstrumentFunction(dta,NULL);
 
  PIN_StartProgram();
 
  return 0;
}

