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



struct rb_root 
taint_llvm_test(struct taint_t* colors,uint64_t color_index, uint64_t register_index, struct interval interval){
  printf("\tTest function\n");
  printf("interval start = %lu\n", interval.start);
  printf("interval stop = %lu\n", interval.last);
  printf("register index %"PRIu64 "\n", register_index);
  printf("color index %"PRIu64 "\n", color_index);
//  printf("addr of jitter %p\n",&jitter);
//  printf("jitter ob base %d\n", jitter.ob_base);
//  printf("addr of jitter pyvm %p\n",jitter.pyvm);
//  printf("addr of jitter taint %p\n", jitter.taint);
//  printf("addr of jitter jitter %p\n", jitter.jitter);
//  printf("addr of jitter vmcpu %p\n", jitter.cpu);
//  printf("addr of jitter taint ob_base %p\n", jitter.taint->ob_base);
//  printf("addr of jitter taint taint %p\n", jitter.taint->taint);
  printf("nb colors %"PRIu64 "\n", colors->nb_colors);
//  printf("jitter nb colors %"PRIu64"\n", jitter->taint->taint->nb_colors);
//  printf("nb register %"PRIu64"\n",colors->nb_registers);
  //printf("max register size %"PRIu32"\n",colors->max_register_size);
//  printf("addr of jitter %p\n",jitter);
//  printf("addr of jitter ob base %p\n", &jitter->ob_base);
//  printf("addr of jitter pyvm %p\n",jitter->pyvm);
//  printf("addr of jitter taint %p\n", jitter->taint);
//  printf("addr of jitter jitter %p\n", jitter->jitter);
//  printf("addr of jitter vmcpu %p\n", jitter->cpu);
//  printf("addr of jitter taint ob_base %p\n", &jitter->taint->ob_base);
//  printf("addr of jitter taint taint %p\n", jitter->taint->taint);
//  printf("addr of jitter_taint %p\n",jitter_taint);
//  printf("addr of jitter_taint ob base %p\n", &jitter_taint->ob_base);
//  printf("addr of jitter_taint pyvm %p\n",jitter_taint->pyvm);
//  printf("addr of jitter_taint taint %p\n", jitter_taint->taint);
//  printf("addr of jitter_taint jitter %p\n", jitter_taint->jitter);
//  printf("addr of jitter_taint vmcpu %p\n", jitter_taint->cpu);
//  printf("addr of jitter_taint taint ob_base %p\n", &jitter_taint->taint->ob_base);
//  printf("addr of jitter_taint taint taint %p\n", jitter_taint->taint->taint);
  printf("addr colors %p\n",&colors);
  printf("addr color_index %p\n",&color_index);
  printf("addr register_index %p\n", &register_index);
  printf("add interval %p \n", &interval);
//  printf("sizeof JitCpu %d ob_base %d pyvm %d taint %d jitter %d vmcpu %d\n", sizeof(JitCpu), sizeof(jitter.ob_base), sizeof(jitter.pyvm), sizeof(jitter.taint), sizeof(jitter.jitter), sizeof(jitter.cpu));

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
