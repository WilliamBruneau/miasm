#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include "taint_llvm.h"

void 
hackprintfi8(uint64_t myvalue){
   printf("this is my constant value %" PRIu64 "\n",myvalue);
}

struct rb_root*
taint_llvm_get_register_color(struct JitCpu *JitCpu, uint64_t color_index,
						            uint64_t register_index, uint64_t start_interval,
                              uint64_t stop_interval)
{
   struct interval interval;
   struct rb_root* bits_checked;
   struct taint_colors_t* colors;
   colors = JitCpu->colors;
   interval.start = start_interval;
   interval.stop = stop_interval;
   *bits_checked = taint_get_register_color(colors, color_index, register_index, interval);
   return bits_checked;
}
