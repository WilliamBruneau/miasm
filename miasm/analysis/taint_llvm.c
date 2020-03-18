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

struct rb_root*
taint_llvm_get_register_color(JitCpu* jitter, uint64_t color_index,
						                  uint64_t register_index, uint64_t start_interval,
                              uint64_t stop_interval)
{
   struct interval interval;
   struct rb_root* bits_checked = malloc(sizeof(struct rb_root));
   struct taint_colors_t* colors;
   colors = jitter->taint_analysis;
   interval.start = start_interval;
   interval.last = stop_interval;
   *bits_checked = taint_get_register_color(colors, color_index, register_index, interval);
   return bits_checked;
}
