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
    int a=10;
    int b=10;
    len=read(fd,buf,4096*5);
    for(i=0;i<len;i++){
        if(buf[i]==0xff&&buf[i+1]==0xc0){ 
            
            height=buf[i+5]*256+buf[i+6];
            width=buf[i+7]*256+buf[i+8];
            if(height>50000){
                height=1;
            }else if(width>50000){
                width=1;
            }else if(height+width>10000&&height+width<95000){
                width=1;
            }else{
                a=height;
                b=width;
            }
            size=a*b;
            text=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
            break;
        } 
    }
   
    memset(text,'a',10);
    printf("%s\n",text);
    close(fd);
}
