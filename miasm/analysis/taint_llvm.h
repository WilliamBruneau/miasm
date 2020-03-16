#if _WIN32
#define _MIASM_EXPORT __declspec(dllexport)
#else
#define _MIASM_EXPORT
#endif

/*TODO : remove this function
Function to add to the context of a LLVMFunction
Useless
*/
_MIASM_EXPORT void hackprintfi8(uint64_t myvalue);
/**
Check if the bits start_interval - stop_interval of the register are tainted with the colour "color_index"
This function is a wrapper of "taint_get_register_color", made specifically to be use in an llvm IR (with a builder.call)

@param colors The structure containing all informations about the current state of the taint_analysis.
@param color_index the index of which color we want to check
@param register_index the index of the register we want to check
@param start_interval The first bit of the register from where the checking will start
@param stop_interval The bit number to stop the checking
@return Returns a pointer to a rb_root structure containing the bits checked 
*/
_MIASM_EXPORT struct rb_root *taint_llvm_get_register_color(struct taint_colors_t *colors,
						    uint64_t color_index,
						    uint64_t register_index,
						    uint64_t start_interval,
                uint64_t stop_interval);
