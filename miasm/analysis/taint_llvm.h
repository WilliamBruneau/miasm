#include "../jitter/interval_tree/interval_tree.h"
#include "../jitter/vm_mngr.h"
#include "../jitter/arch/JitCore_x86.h"
#if _WIN32
#define _MIASM_EXPORT __declspec(dllexport)
#else
#define _MIASM_EXPORT
#endif

/**
Check if the bits start_interval - stop_interval of the register are tainted with the colour "color_index"
This function is a wrapper of "taint_get_register_color", made specifically to be use in an llvm IR (with a builder.call)

@param jitter A Jitter class, we will only use the object jitter->colors that record all taint informations
@param color_index the index of which color we want to check
@param register_index the index of the register we want to check
@param start_interval The first bit of the register from where the checking will start
@param stop_interval The bit number to stop the checking
@return Returns a pointer to a rb_root structure containing the bits checked 
*/
_MIASM_EXPORT void taint_llvm_get_register_color(JitCpu* jitter,
                                                 uint64_t color_index,
                                                 uint64_t register_index,
                                                 struct interval interval,
                                                 char* ptr);

_MIASM_EXPORT struct rb_root taint_llvm_test( struct taint_t* colors, uint64_t color_index,uint64_t register_index, struct interval interval);
_MIASM_EXPORT struct rb_root* simple_llvm(struct taint_t *colors);
_MIASM_EXPORT struct taint_t* get_taint_pointer( JitCpu *jitter);
