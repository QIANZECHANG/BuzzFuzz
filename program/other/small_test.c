#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<fcntl.h>
#include<sys/types.h>
#include<sys/mman.h>
#include<sys/stat.h>
#include<string.h>

int main(int argc,char* argv[]){
    
    int fd = open(argv[1],O_RDONLY); 
    
    unsigned char buf[4];
   
    char* text;
    
    read(fd,buf,4);

    text=mmap(NULL,buf[2],PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    
   
    memset(text,'a',1);
    printf("%s\n",text);
    close(fd);
}
