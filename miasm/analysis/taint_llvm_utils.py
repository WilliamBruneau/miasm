import pdb, sys
from future.utils import viewitems
from miasm.jitter.llvmconvert import LLVMFunction, LLVMType, LLVMContext_JIT
from miasm.expression.expression import ExprId
from llvmlite import ir as llvm_ir

class LLVMFunction_Taint(LLVMFunction):
#TODO comments
  def __init__(self, llvm_context, name="fc", new_module=True):
    LLVMFunction.__init__(self, llvm_context, name, new_module)


  def init_fc(self):
    super(LLVMFunction_Taint, self).init_fc()
    t_size = LLVMType.IntType(64)
    # Alloc a memory, to store and retrieve the current color
    self.ptrColor = self.CreateEntryBlockAlloca(t_size, default_value=t_size(0))
     
    #Save the value 0 to 7 in ssa vars. To use in intervals
    interval_bit_ptr = []
    for bit_index in range(0,8):
      ptr = self.CreateEntryBlockAlloca(t_size, default_value=t_size(bit_index))
      interval_bit_ptr.append(ptr)
    self.interval_bit_ptr = interval_bit_ptr
  
  def gen_get_register_taint(self, color_index, reg_name, start_check, stop_check):
    builder = self.builder
    fc_ptr = self.mod.get_global("taint_llvm_get_register_color")
    builder.store(LLVMType.IntType(64)(color_index), self.ptrColor)
    current_color = builder.load(self.ptrColor)
    reg_index = self.llvm_context.regs_index[reg_name]
    ptr = self.CreateEntryBlockAlloca(LLVMType.IntType(64), default_value=LLVMType.IntType(64)(reg_index))
    reg_index_computed = builder.load(ptr)
    #In this case we will check the whole register
    start = builder.load(self.interval_bit_ptr[int(start_check)])
    stop = builder.load(self.interval_bit_ptr[int(stop_check)])
    ret = builder.call(fc_ptr, [self.local_vars["jitcpu"], current_color, reg_index_computed, start, stop])
    return ret

  def taint_add_ir(self, expr):
    #Only handle ExprId and ExprSlice for now
    builder = self.builder
    color_index = 0
    if expr.is_id():
      while color_index < self.llvm_context.nb_colors:
        bits_checked = self.gen_get_register_taint(color_index, expr.name, 0, 7) 
        color_index += 1
        return bits_checked
        
    elif expr.is_slice():
      while color_index < self.llvm_context.nb_colors:
        if isinstance(expr.arg, ExprId):
          bits_checked = self.gen_get_register_taint(color_index, str(expr.arg),expr.start/8, expr.stop/8-1) 
        else:
          bits_checked = "Not yet implemented"
        color_index += 1
        return bits_checked
    else : 
      #Cases not yet implemented
        return "Nothing"
     
  def gen_irblock(self, instr_attrib, attributes, instr_offsets, irblock):
    """ Overload of LLVMFunction.gen_irblock to use taint engine

    """ 

    for index, assignblk in enumerate(irblock):
      print(self)
      for dst, src in viewitems(assignblk):
        if dst != self.llvm_context.ir_arch.IRDst:
          bits_checked = self.taint_add_ir(src)

    super(LLVMFunction_Taint, self).gen_irblock(instr_attrib, attributes, instr_offsets, irblock)
 
class LLVMContext_JIT_Taint(LLVMContext_JIT): 
  def __init__(self, libs, arch):
    LLVMContext_JIT.__init__(self, libs, arch)      

    
  def add_taint_functions(self):
    i8 = LLVMType.IntType(8)
    p8 = llvm_ir.PointerType(i8)
    itype = LLVMType.IntType(64)
    ftype = llvm_ir.FloatType()
    dtype = llvm_ir.DoubleType()
    fc = {"taint_llvm_get_register_color":{"ret":p8,"args":[p8, itype, itype, itype, itype]}}
    super(LLVMContext_JIT_Taint, self).add_fc(fc, readonly = True) 

  def add_op(self): 
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
  """method to initalize the taint analysis
     @jitter : the jitter should used llvm as a back-end
     @nb_colors : number of colors that will be used to taint, should be superior to 1 """

  if nb_colors < 1:
    raise "At least 1 color is required to enable taint analysis"
  try:
    nb_regs = init_registers_index(jitter)
    jitter.taint.init_taint_analysis(nb_colors, nb_regs)
    jitter.jit.context.nb_colors = nb_colors
  except:
    print("No LLVMContext created, the jitter should be set to llvm")
    sys.exit(0)
