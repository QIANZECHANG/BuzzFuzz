#include<stdio.h>

int main(){
  int a=0xfff7;
  int b=0xc801;
  int c=a*b;
  unsigned int d=a*b;
  printf("a(0xa112):%d\nb(0xcb71):%d\nc(a*b):%d\nd(unsigned):%u\n",a,b,c,d);  
}
