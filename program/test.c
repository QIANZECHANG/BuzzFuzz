/*
jpegファイルからimageのwidthとheight情報を保存するバイトを検出して（簡単のため、こちらでwidthだけを注目）、
width分の空間をmmap関数で作成し、そこに'aaaaaaaaaa'を書き込む。
*/
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
    
    //入力するjpegファイルのバイト数が16,000ぐらいので、簡単にするためにsizeが4096*5であるbufを定義
    unsigned char buf[4096*5];
    int i;
    char* text;
    //int width=0;
    //int height=0;
    int len;
    len=read(fd,buf,4096*5);
    for(i=0;i<len;i++){
        if(buf[i]==0xff&&buf[i+1]==0xc0){ // jpegファイルフォーマットにより、widthとheightを検出
            //height=buf[i+5]*256+buf[i+6];
            //width=buf[i+7]*256+buf[i+8];
            
            //かけ算を回避するために、widthの一つのバイトを入力するだけ
            text=mmap(NULL,buf[i+8],PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
            //printf("i+7 : %p\ni+8 : %p\n",&buf[i+7],&buf[i+8]);
            break;
        } 
    }
    memset(text,'a',10);
    close(fd);
}
