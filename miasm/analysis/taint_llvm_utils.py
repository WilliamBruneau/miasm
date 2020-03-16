import pdb
from miasm.jitter.llvmconvert import LLVMFunction, LLVMType, LLVMContext_JIT
from miasm.expression.expression import ExprId
from llvmlite import ir as llvm_ir

class LLVMFunction_Taint(LLVMFunction):
#TODO comments
  def __init__(self, llvm_context, name="fc", new_module=True):
    LLVMFunction.__init__(self, llvm_context, name, new_module)

  def PrintHello(self):
    builder = self.builder
    fc_ptr = self.mod.get_global("hackprintfi8")
    ret = builder.alloca(LLVMType.IntType(64)) 
    builder.store(LLVMType.IntType(64)(420), ret)
    addr = builder.load(ret)
    pdb.set_trace()
    builder.call(fc_ptr, [addr]) 

  def init_fc(self):
    super(LLVMFunction_Taint, self).init_fc()
    self.PrintHello()
    t_size = LLVMType.IntType(64)
    colors_addr = []
    i = 0
    while(i < self.llvm_context.nb_colors):
      ptr = self.builder.alloca(t_size)
      addr = builder.store(t_size(i), ptr)
      colors_addr.append(addr)
      i += 1
    self.colors_addr = colors_addr
    interval_bit_addr = []
    for(i=0; i<=8; i+=1){
      addr = builder.zext(t_size(i),t_size)
      interval_bit_addr.append(addr)
    }
    self.interval_bit_addr = interval_bit_addr
  
  def add_ir(expr):
    #Only handle ExprId and ExprSlice for now
    builder = self.builder
    if expr.is_id():
      fc_ptr = self.mod.get_global("taint_llvm_get_register_color")
      i = 0
      while i < self.nb_colors:
        current_color = builder.load(self.colors_addr[0])
        reg_index = self.llvm_context.regs_index[expr.name]
        reg_index_computed = builder.zext(LLVMType.IntType(64)(reg_index))
        start = self.interval_bit_addr[0]
        stop = self.interval_bit_addr[8]
        bits_checked = builder.call(fc_ptr, [local_vars["JitCpu"], current_color, reg_index_computed, start, stop])
        
        i += 1
        
    elif expr.is_slice():
      fc_ptr = self.mod.get_global("taint_llvm_get_register_color")
      i = 0
      while i < self.nb_colors:
        current_color = builder.load(self.colors_addr[0])
        reg_index = self.llvm_context.regs_index[expr.name]
        reg_index_computed = builder.zext(LLVMType.IntType(64)(reg_index))
        start = self.interval_bit_addr[expr.start]
        stop = self.interval_bit_addr[expr.stop]
        bits_checked = builder.call(fc_ptr, [local_vars["JitCpu"], current_color, reg_index_computed, start, stop])
        
        i += 1
      
class LLVMContext_JIT_Taint(LLVMContext_JIT): 
  def __init__(self, libs, arch):
    LLVMContext_JIT.__init__(self, libs, arch)      

  def add_hackfunc(self):
    fc = {"hackprintfi8":{"ret":llvm_ir.VoidType(),"args":[LLVMType.IntType(64)]}}
    super(LLVMContext_JIT_Taint, self).add_fc(fc, readonly = True) 
    
  def add_taint_functions(self):
    i8 = LLVMType.IntType(8)
    p8 = llvm_ir.PointerType(i8)
    itype = LLVMType.IntType(64)
    ftype = llvm_ir.FloatType()
    dtype = llvm_ir.DoubleType()
    fc = {"taint_llvm_get_register_color":{"ret":p8,"args":[p8, itype, itype, itype, itype]}}
    super(LLVMContext_JIT_Taint, self).add_fc(fc, readonly = True) 

  def add_op(self): 
    self.add_hackfunc()
    self.add_taint_functions()
    super(LLVMContext_JIT_Taint, self).add_op()
    
def init_registers_index(jitter):
    """ Associate register names with an index (needed during JiT) """

    regs_index = dict()
    regs_name = dict()
    index = 0
    for reg in jitter.arch.regs.all_regs_ids_byname.keys():
        regs_index[reg] = index
        regs_name[index] = reg
        index += 1
    jitter.jit.context.regs_index = regs_index
    jitter.jit.context.regs_name = regs_name
    return len(regs_index)
  
def enable_taint_analysis(jitter, nb_colors = 1):
  jitter.jit.context.nb_colors = nb_colors
  init_registers_index(jitter)
