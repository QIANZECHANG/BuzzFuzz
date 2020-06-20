#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>

typedef struct n{
    char* addr;
    struct n *left;
    struct n *right;
}node;

node* make_tree(char* addr,node* left,node* right){
    node* start;
    start=(node *)malloc(sizeof(node));
    start->addr=addr;
    start->left=left;
    start->right=right;
    return start;
}
typedef struct _n{
    struct _n *next;
    node *node;
}node_list;

node_list* node_list_head=NULL;

void add_node(node* node){
    if(node_list_head==NULL){
        node_list_head=(node_list*)malloc(sizeof(node_list));
        node_list_head->next=NULL;
        node_list_head->node=NULL;
    }
    node_list* node_list=node_list_head;

    while(node_list->next!=NULL)node_list=node_list->next;
    
    //node_list=(node_list*)malloc(sizeof(node_list));
    node_list->next=(struct _n*)malloc(sizeof(node_list));
    node_list->next->next=NULL;
    node_list->next->node=node;
} 
node* check_node(char* addr){
    node_list* node_list=node_list_head->next;
    for(node_list;node_list!=NULL;node_list=node_list->next){
        if(node_list->node->addr==addr){
            return node_list->node;  
        }  
    }
    return NULL;
}

void print_byte(node* node){
    if(node->left==NULL&&node->right==NULL){
      printf("%s\n",node->addr);
      return;
    }
    print_byte(node->left);
    print_byte(node->right);
    
}

int main(){
    node* a;
    node* b;
    node* d;
    node_list* c;
    c=(node_list*)malloc(sizeof(node_list));
    
    a=make_tree("aaaa",NULL,NULL);
    b=make_tree("bbbb",NULL,NULL);
    d=make_tree("cccc",a,b);
    print_byte(d);
    c->next=NULL;
    c->node=b;
    add_node(b);
    //node* d;
    //d=check_node("a");
    //if(d==NULL)printf("//////");
    //printf("%s\n",d->left->addr);
    //printf("%s\n",node_list_head->next->node->left->addr);
}
