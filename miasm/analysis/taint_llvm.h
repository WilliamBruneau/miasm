#if _WIN32
#define _MIASM_EXPORT __declspec(dllexport)
#else
#define _MIASM_EXPORT
#endif

_MIASM_EXPORT void hackprintfi8(uint64_t myvalue);
