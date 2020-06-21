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
    
    unsigned char buf[4096*5];
    int i;
    char* text;
    int width=0;
    int height=0;
    int size=0;
    int len;
    len=read(fd,buf,4096*5);
    for(i=0;i<len;i++){
        if(buf[i]==0xff&&buf[i+1]==0xc0){ 
            height=buf[i+5]*256+buf[i+6];
            width=buf[i+7]*256+buf[i+8];
            size=height*width;
            text=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
            break;
        } 
    }
   
    memset(text,'a',10);
    printf("%s\n",text);
    close(fd);
}
