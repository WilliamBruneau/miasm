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

class LLVMContext_JIT_Taint(LLVMContext_JIT): 
  def __init__(self, libs, arch):
    LLVMContext_JIT.__init__(self, libs, arch)      

  def add_hackfunc(self):
    fc = {"hackprintfi8":{"ret":llvm_ir.VoidType(),"args":[LLVMType.IntType(64)]}}
    super(LLVMContext_JIT_Taint, self).add_fc(fc, readonly = True) 

  def add_op(self): 
    self.add_hackfunc()
    super(LLVMContext_JIT_Taint, self).add_op()
