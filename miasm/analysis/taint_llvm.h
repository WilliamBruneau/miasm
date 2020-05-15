#include "../jitter/interval_tree/interval_tree.h"
#include "../jitter/vm_mngr.h"
#include "../jitter/arch/JitCore_x86.h"
#if _WIN32
#define _MIASM_EXPORT __declspec(dllexport)
#else
#define _MIASM_EXPORT
#endif

#define REG 1
#define MEM 2

/**
Check if the bytes start_interval -> stop_interval of the *register_index* are tainted with the color *color_index*
This function is a wrapper of "taint_get_register_color", made specifically to be used in an llvm IR (with a builder.call)

@param jitter A Jitter class, we will only use the object jitter->taint->taint that record all taint informations
@param color_index The index of the color checked
@param register_index The index of the register checked
@param start_interval The first bit of the register from where the checking will start
@param stop_interval The bit number to stop the checking
@param ptr A pointer to save the rb_root struct returned from taint_get_register_color
*/
_MIASM_EXPORT void taint_llvm_get_register_color(JitCpu* jitter,
                                                 uint64_t color_index,
                                                 uint64_t register_index,
                                                 struct interval interval,
                                                 char* ptr);

_MIASM_EXPORT void taint_llvm_test(char* ptr);
_MIASM_EXPORT void taint_create_rb(char* ptr);
_MIASM_EXPORT struct rb_root* simple_llvm(struct taint_t *colors);
_MIASM_EXPORT struct taint_t* get_taint_pointer( JitCpu *jitter);
_MIASM_EXPORT void interval_tree_new_llvm(char* ptr);
/**
 * Wrapper for interval_tree_merge. 
 * This function uses the trick described in llvmconvert by fabrice and camille
 *
 * @param *jitter A Jitcpu object to retrive the tain_t structure
 * @param register_index The index of the register
 * @param color_index The index of the color
 * @param offset The offset ...
 * @param *ptr The pointer of the memory space containing the rb_root 
*/
_MIASM_EXPORT void taint_merge_interval_tree(JitCpu *jitter, uint64_t register_index, uint64_t color_index, signed long offset, char* ptr);

/**
 * Taint wether a register or a range of the memory
 * Wraps the functions taint_register and taint_memory from taint.c
 * 
 * @param fully_tainted Needed to optimize the taint process, an uint64_t value
 * @param index_or_addr Can be and index or an adress depending of the structure
 * @param structure_size The size of the register, or the range of the memory
 * @param current_color Index of the current color
 * @param jitter A jitter class. Used to retrieve the taint_t object
 * @param vm_mngr The vm manager 
 * @param ptr_before A pointer to retrieve the rb_root of interval_tree_before
 * @param ptr_new A pointer to retrieve the rb_root of interval_tree_new
 * @param type The type of the structure
*/
_MIASM_EXPORT void taint_generic_structure(uint64_t fully_tainted,
                                           uint64_t index_or_addr,
                                           uint64_t structure_size,
                                           uint64_t current_color,
                                           JitCpu* jitter,
                                           vm_mngr_t* vm_mngr,
                                           uint64_t type,
                                           char* ptr_before,
                                           char* ptr_new);

_MIASM_EXPORT void get_generic_structure(JitCpu* jitter,
                                         uint64_t color_index,
                                         uint64_t register_index,
                                         struct interval interval,
                                         uint64_t type,
                                         char* ptr);

_MIASM_EXPORT uint64_t check_fully_tainted(char* ptr);
