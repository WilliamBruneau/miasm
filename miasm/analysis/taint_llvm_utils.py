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

    builder = self.builder
    interval_ptr = builder.alloca(self.llvm_context.interval_type)

    # Get a pointer to the taint_t structure from pointer jitcpu
    # It contains all the taint informations
    # Save it in the local_vars
    # Does not work every time :(

    jitcpu_struct_ptr = builder.alloca(self.llvm_context.jitcpu_type)
    jitcpu_casted = builder.bitcast(self.local_vars["jitcpu"], self.llvm_context.jitcpu_type.as_pointer())
    jitcpu_value = builder.load(jitcpu_casted)
    builder.store(jitcpu_value, jitcpu_struct_ptr)
    PyTaint_ptr_ptr = builder.gep(
        jitcpu_struct_ptr,
        [
            self.cst2llvmcst(0),
            self.cst2llvmcst(2)
        ]
    )
    PyTaint_ptr = builder.load(PyTaint_ptr_ptr)
    taint_t_ptr_ptr = builder.gep(
        PyTaint_ptr,
        [
            self.cst2llvmcst(0),
            self.cst2llvmcst(1)
        ]
    )
    taint_t_ptr = builder.load(taint_t_ptr_ptr) 
    
    
    self.local_vars["taint_t"] = taint_t_ptr
    self.local_vars["interval_ptr"] = interval_ptr

    # Alloc some  memory, to store and retrieve : 
    #  the current color
    #  the reg_index
    #  the offset to merge 2 rb_root
    t_size = LLVMType.IntType(64)
    self.ptrColor = self.CreateEntryBlockAlloca(t_size, default_value=t_size(0))
    self.ptr_reg_index = self.CreateEntryBlockAlloca(t_size) 
    self.offset = self.CreateEntryBlockAlloca(t_size)
  
  
  def gen_get_register_taint(self, color_index, reg_name, start_check, stop_check):
    """ Generation of llvm code, to get the intervals tainted with color_index of the register
    @param color_index the color that will be checked in the register, an i32
    @param reg_name the name of the register to checked, a string
    @param start_check start of the interval to check, casted to int
    @param stop_check end of the interval to cehck, casted to int
    @return A pointer to an rb_root containing all intervals tainted

    """

    builder = self.builder
    fc_ptr = self.mod.get_global("taint_llvm_get_register_color")
    fc_simple = self.mod.get_global("simple_llvm")

    # Casted to 64 bits to use William functions
    builder.store(LLVMType.IntType(64)(color_index), self.ptrColor)
    current_color = builder.load(self.ptrColor)

    # Get the index of the register
    reg_index = self.llvm_context.regs_index[reg_name]
    ptr = self.CreateEntryBlockAlloca(LLVMType.IntType(64), default_value=llvm_ir.Constant(LLVMType.IntType(64),reg_index))
    reg_index_computed = builder.load(ptr)

    # Update the interval structure
    start_ptr = builder.gep(self.local_vars["interval_ptr"],[self.cst2llvmcst(0),self.cst2llvmcst(0)]) 
    stop_ptr = builder.gep(self.local_vars["interval_ptr"],[self.cst2llvmcst(0),self.cst2llvmcst(1)])
    builder.store(llvm_ir.Constant(LLVMType.IntType(32),(int(5))), start_ptr)
    builder.store(llvm_ir.Constant(LLVMType.IntType(32),(int(8))), stop_ptr)
    interval_struct = builder.load(self.local_vars["interval_ptr"])

    # memory allocated to store the rb_root from taint_get_register
    # trick from llvmconvert.py 
    rb_root_ptr = builder.alloca(llvm_ir.IntType(32))
    rb_root_ptr_u8 = builder.bitcast(
          rb_root_ptr,
          llvm_ir.IntType(8).as_pointer()
        )

    # Bitcast test
    taint_t_cast = builder.bitcast(self.local_vars["taint_t"],llvm_ir.IntType(8).as_pointer())    
 
    #Call functions
    builder.call(fc_simple, [taint_t_cast])
    builder.call(
        fc_ptr, 
        [
            self.local_vars["jitcpu"], 
            current_color, 
            reg_index_computed, 
            interval_struct, 
            rb_root_ptr_u8 
        ]
    )
    ret = builder.load(rb_root_ptr)
    return ret

  def taint_add_ir(self, expr):
    #TODO comments
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
          bits_checked = self.gen_get_register_taint(
              color_index, 
              str(expr.arg),
              expr.start/8, 
              expr.stop/8-1
          ) 
        else:
          #TODO
          bits_checked = self.llvm_context.rb_root_type
        color_index += 1
        return bits_checked
    else : 
      #Cases not yet implemented
        return self.llvm_context.rb_root_type
     
  def cst2llvmcst(self, value):
    """ Wrapper around llvm_ir.Constant
    @param value Must be an int value
    @return an LLVM Constant of type LLVMType.IntType
    """

    return llvm_ir.Constant(LLVMType.IntType(),value)

  def get_register_tree(self, reg_name):
    """ Get the register tree rb_root object from it's name
    @param reg_name the name of the register
    @return An llvm pointer to an rb_root
    """
    # Not used currently
    reg_index = self.llvm_context.regs_index[reg_name]
    color_index = self.builder.load(self.ptrColor)
    color_index_cast = self.builder.trunc(color_index, LLVMType.IntType(32))
    ptr_taint_t = self.local_vars["taint_t"]
    taint_t_load = self.builder.load(ptr_taint_t)    
    ptr_colors = self.builder.gep(taint_t_load,[self.cst2llvmcst(0),self.cst2llvmcst(2)])
    colors_load = self.builder.load(ptr_colors)
    registers_ptr = self.builder.gep(colors_load,[color_index_cast,self.cst2llvmcst(0)])
    registers_load = self.builder.load(registers_ptr)
    register_tree = self.builder.gep(registers_load,[self.cst2llvmcst(0),self.cst2llvmcst(reg_index)])
    
    return register_tree

  def gen_irblock(self, instr_attrib, attributes, instr_offsets, irblock):
    """ Overload of LLVMFunction.gen_irblock to use taint engine

    """ 

    for index, assignblk in enumerate(irblock):
      # dst is whether an ExprId or an ExprMem
      for dst, src in viewitems(assignblk):
        if dst != self.llvm_context.ir_arch.IRDst:
          # Need the intervals tainted to taint the dst with interval_tree_merge
          ptr_intervals_tainted_tree = self.taint_add_ir(src)
          #  COMMENTED to test the use of intervals struct in taint_add_ir

         # if isinstance(dst, ExprId):
         #   fc_ptr = self.mod.get_global("interval_tree_merge")
         #   # We fetch the interval tree of the register to merge in the intervals tainted
         #   # Offset is 0 here because no compose
         #   self.builder.store(LLVMType.IntType(64)(0), self.offset)
         #   offset = self.builder.load(self.offset)
         #   ptr_register_tree = self.get_register_tree(dst.name) 
         #   print(ptr_register_tree)
         #   self.builder.call(
         #               fc_ptr,
         #               [
         #                 ptr_intervals_tainted_tree, 
         #                 ptr_register_tree, 
         #                 offset
         #               ]
         #             )
         # else:
         #   print("Not implemented")
          

    super(LLVMFunction_Taint, self).gen_irblock(instr_attrib, attributes, instr_offsets, irblock)
 
class LLVMContext_JIT_Taint(LLVMContext_JIT): 
#TODO comments
  def __init__(self, libs, arch):
    LLVMContext_JIT.__init__(self, libs, arch)      

  def add_taint_structures(self):
    i8 = LLVMType.IntType(8)
    i32 = LLVMType.IntType(32)
    i64 = LLVMType.IntType(64)
    p8 = llvm_ir.PointerType(i8)
    p32 = llvm_ir.PointerType(i32)
    dtype = llvm_ir.DoubleType()
    self.rb_root_type = llvm_ir.LiteralStructType([p8]) 

    self.taint_color_t_type = llvm_ir.LiteralStructType(
                                                    [
                                                      llvm_ir.PointerType(llvm_ir.PointerType(self.rb_root_type)), #rb_root** register
                                                      llvm_ir.PointerType(self.rb_root_type), # rb_root* memory
                                                      i32 # *callbacks
                                                    ]
                                                  )
    self.taint_t_type = llvm_ir.LiteralStructType(
                                              [
                                                self.taint_color_t_type.as_pointer(),
                                                LLVMType.IntType(64),
                                                LLVMType.IntType(64),
                                                LLVMType.IntType(32)
                                            ]
                                          )
    self.interval_type = llvm_ir.LiteralStructType( 
                                              [
                                                LLVMType.IntType(32), # start_interval
                                                LLVMType.IntType(32) # stop_interval
                                              ]
                                            )
                                          
    self.PyTaint_type = llvm_ir.LiteralStructType(
                                            [
                                              LLVMType.IntType(64), #PyObject_HEAD
                                              llvm_ir.PointerType(self.taint_t_type)  # taint_t*
                                          ]
                                        )
    # this type might depend on the version of python
    # PyObjectHead extends differently
    # TODO for python2
    self.jitcpu_type = llvm_ir.LiteralStructType(
                                            [
                                              i64, #PyObject_HEAD
                                              p8, # VmMngr*
                                              self.PyTaint_type.as_pointer(), # PyTaint*
                                              p8, # PyObject *jitter 
                                              p8 # vm_cpu*
                                            ]
                                          )
  def add_taint_functions(self):
    i8 = LLVMType.IntType(8)
    p8 = llvm_ir.PointerType(i8)
    i32 = LLVMType.IntType(32)
    p32 = llvm_ir.PointerType(i32)
    itype = LLVMType.IntType(64)
    ftype = llvm_ir.FloatType()
    dtype = llvm_ir.DoubleType()
    fc = {"taint_llvm_get_register_color": {"ret":llvm_ir.VoidType(), 
                                      "args":[ 
                                              p8,  
                                              itype,
                                              itype, 
                                              self.interval_type,
                                              p8]},
          "interval_tree_merge": {"ret":llvm_ir.VoidType(),
                                 "args":[self.rb_root_type, 
                                         self.rb_root_type, 
                                         itype]},
          "taint_get_register_color": {"ret":self.rb_root_type, 
                                      "args":[ 
                                              self.taint_t_type.as_pointer(), 
                                              itype,
                                              itype, 
                                              self.interval_type]},
          "taint_llvm_test" : {"ret": self.rb_root_type,
                              "args" : [
                                        p8,
                                        itype, 
                                        itype,
                                        self.interval_type] },
          "simple_llvm" : {"ret": self.rb_root_type.as_pointer(),
                          "args" : [
                                    p8
                                    ]}
        }
    super(LLVMContext_JIT_Taint, self).add_fc(fc, readonly = False) 

  def add_op(self): 
    self.add_taint_structures()
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
