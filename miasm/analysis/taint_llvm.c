#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include "../jitter/compat_py23.h"
#include "../jitter/bn.h"
#include "../jitter/queue.h"
#include "../jitter/vm_mngr.h"
#include "../jitter/vm_mngr_py.h"
#include "../jitter/JitCore.h"
#include "../jitter/interval_tree/interval_tree.h"
#include "../jitter/interval_tree/rbtree.h"

#include "taint.h"
#include "taint_llvm.h"


struct taint_t* 
get_taint_pointer(JitCpu* jitter){
  printf("taint address %p\n", jitter->taint->taint);
  return jitter->taint->taint;
} 

struct rb_root*
simple_llvm(struct taint_t* colors){
  printf("\tsimple llvm\n");
  printf("addr colors %p\n", colors);
  struct rb_root* canari;
  printf("sizeof(rb_root) = %d\n",sizeof(struct rb_root));
  printf("sizeof(bn_t) = %d\n",sizeof(bn_t));
  return canari;
}


void taint_create_rb(char* ptr){
    struct rb_root tmp = interval_tree_new();
    struct interval interval;
    interval.start = 6;
    interval.last = 7;
    interval_tree_add(&tmp, interval);
    interval.start = 2;
    interval.last = 5;
    interval_tree_add(&tmp, interval);
    memcpy(ptr, (char*)&tmp, 4); 
}

void
taint_llvm_test(char* ptr){
    struct rb_root tmp;
    memcpy(&tmp, ptr, 4);
    interval_tree_print(&tmp); 
}

void
interval_tree_new_llvm(char* ptr){
    struct rb_root interval_tree;
    interval_tree = interval_tree_new();
    memcpy(ptr, (char*) &interval_tree, 4);
}


void
taint_llvm_get_register_color(JitCpu* jitter, uint64_t color_index,
						                  uint64_t register_index, struct interval interval,
                              char* ptr)
{
    printf("Doing some tests inside this function\n");
    printf("color_index = %" PRIu64 "\n", color_index);
    printf("reg_index = %" PRIu64 "\n", register_index);
    printf("interval start = %lu\n", interval.start);
    printf("interval stop = %lu\n", interval.last);
    printf("addr of taint %p\n", jitter->taint->taint);
    if (jitter == NULL){
      printf("thats kinda weird\n");
    }
    else{
      printf("now we cooking\n");
    }
    struct rb_root ret;
    ret = taint_get_register_color(jitter->taint->taint, color_index, register_index, interval);
    memcpy(ptr, (char*)&ret, 4);
}

void
taint_merge_interval_tree(JitCpu* jitter, uint64_t register_index, uint64_t color_index, signed long offset, char* ptr)
{
   struct rb_root* reg = jitter->taint->taint->colors[color_index].registers[register_index];
   struct rb_root bytes_tainted;
   bytes_tainted = interval_tree_new();
   memcpy(&bytes_tainted, ptr, 4);
   
   interval_tree_merge(reg, &bytes_tainted, offset);

}


void 
get_generic_structure(JitCpu* jitter,
                      uint64_t color_index,
                      uint64_t register_index,
                      struct interval interval,
                      uint64_t type,
                      char* ptr)
{
    struct rb_root structure_interval_tree;
    if(type == REG)
        structure_interval_tree = taint_get_register_color(jitter->taint->taint,
                                                           color_index,
                                                           register_index,
                                                           interval);
    else if(type == MEM)
        structure_interval_tree = taint_get_memory(jitter->taint->taint,
                                                   color_index,
                                                   interval);
    else
    {
        fprintf(stderr, "Can't get an other structure than registers or memory\n");
        exit(1);
    }
    memcpy(ptr, (char*)&structure_interval_tree,4); 

}

void
taint_generic_structure(uint64_t fully_tainted,
                        uint64_t index_or_addr,
                        uint64_t structure_size,
                        uint64_t current_color,
                        JitCpu* jitter,
                        vm_mngr_t* vm_mngr,
                        uint64_t type,
                        char* ptr_before,
                        char* ptr_new)
{
    struct rb_root taint_interval_tree_before;
    struct rb_root taint_interval_tree_new;
    memcpy(&taint_interval_tree_before, ptr_before, 4);
    memcpy(&taint_interval_tree_new, ptr_new, 4);
    if(type == REG) 
        taint_register(fully_tainted,
                       index_or_addr,
                       structure_size,
                       current_color, 
                       jitter->taint->taint, 
                       vm_mngr, 
                       &taint_interval_tree_before, 
                       &taint_interval_tree_new);
    else if (type == MEM)
        taint_memory(fully_tainted, 
                     index_or_addr,
                     structure_size, 
                     current_color, 
                     jitter->taint->taint, 
                     vm_mngr, 
                     &taint_interval_tree_before, 
                     &taint_interval_tree_new);
    else
    {
        fprintf(stderr, "Can't taint other than registers and memory\n");
        exit(1);
    }
    interval_tree_free(&taint_interval_tree_before);
    interval_tree_free(&taint_interval_tree_new);

}

uint64_t check_fully_tainted(char* ptr)
{
    uint64_t fully_tainted;
    struct rb_root interval_tree;
    memcpy(&interval_tree, ptr,4);
    if(rb_first(&interval_tree)!= NULL){
        fully_tainted = 1;
    }
    return fully_tainted;
}
