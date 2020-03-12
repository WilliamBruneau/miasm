#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include "taint_llvm.h"

void 
hackprintfi8(uint64_t myvalue){
   printf("this is my constant value %" PRIu64 "\n",myvalue);
}
