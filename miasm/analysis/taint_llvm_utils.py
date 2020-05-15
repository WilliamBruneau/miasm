import pdb, sys
from future.utils import viewitems
from miasm.jitter.llvmconvert import LLVMFunction, LLVMType, LLVMContext_JIT
from miasm.analysis.taint_codegen import get_detailed_read_elements
from miasm.expression.expression import ExprId, ExprSlice
from llvmlite import ir as llvm_ir

class LLVMFunction_Taint(LLVMFunction):
#TODO comments
    def __init__(self, llvm_context, name="fc", new_module=True):
        LLVMFunction.__init__(self, llvm_context, name, new_module)


    def init_fc(self):
        super(LLVMFunction_Taint, self).init_fc()

        builder = self.builder
        interval_ptr = builder.alloca(self.llvm_context.interval_type)
        self.local_vars["interval_ptr"] = interval_ptr


    def gen_get_taint_generic(self, name, color_index, get_type, start_check, stop_check):
        """ Generation of llvm code, to get the intervals tainted with color_index of the register
            @param color_index the color that will be checked in the register, an i32
             @param reg_name the name of the register to checked, a string
             @param start_check start of the interval to check, an llvm value
             @param stop_check end of the interval to check, an llvm value
             @return A pointer to an rb_root containing all intervals tainted

             """

        builder = self.builder
        if get_type == "reg":
            reg_index = self.llvm_context.regs_index[name]
            get_type = 1
        elif get_type == "mem":
            reg_index = 0
            get_type = 2


        # Update the interval structure
        start_ptr = builder.gep(self.local_vars["interval_ptr"],[pyt2llvm(32, 0),pyt2llvm(32, 0)]) 
        stop_ptr = builder.gep(self.local_vars["interval_ptr"],[pyt2llvm(32, 0),pyt2llvm(32, 1)])
        builder.store(start_check, start_ptr)
        builder.store(stop_check, stop_ptr)
        interval_struct = builder.load(self.local_vars["interval_ptr"])

        # memory allocated to store the rb_root from taint_get_register
        # trick from llvmconvert.py 
        rb_root_ptr = builder.alloca(llvm_ir.IntType(32))
        rb_root_ptr_u8 = builder.bitcast(
            rb_root_ptr,
            llvm_ir.IntType(8).as_pointer()
        )
        fc_ptr = self.mod.get_global("get_generic_structure")
        interval_tree = externalCall(fc_ptr,
                                    [
                                        self.local_vars["jitcpu"], 
                                        color_index, 
                                        pyt2llvm(64, reg_index), 
                                        interval_struct, 
                                        pyt2llvm(64, get_type)
                                    ],
                                    self.builder)
        #Call functions
        return interval_tree

    

    def add_ir_taint(self, elements, full = False, current_compose_start = 0):
        #TODO comments
        #Only handle ExprId and ExprSlice for now
        builder = self.builder
        color_index = 0
        if not elements : 
            return pyt2llvm(64, 0)
        for element in elements:
            if element != self.llvm_context.ir_arch.IRDst:
                if element.is_slice():
                    interval_tree = self.gen_get_taint_generic(str(element.arg), pyt2llvm(64, color_index), "reg", pyt2llvm(32, element.start), pyt2llvm(32, element.stop))
                elif element.is_mem():
                    start = self.add_ir(element)
                    size = pyt2llvm(32, int(element.size/8))
                    stop = builder.add(start, size)
                    interval_tree = self.gen_get_taint_generic(element, pyt2llvm(64, color_index), "mem", start, stop)
                elif element.is_id():
                    interval_tree = self.gen_get_taint_generic(str(element.name), pyt2llvm(64, color_index), "reg", pyt2llvm(32, 0), pyt2llvm(32, element.size) )
            if full:
                fc_ptr = self.mod.get_global("check_fully_tainted")
                fully_tainted = builder.call(fc_ptr, [interval_tree])
            else:
                fc_ptr = self.mod.get_global("taint_merge_interval_tree")
                interval_start_ptr = builder.gep(self.local_vars["interval_ptr"], [pyt2llvm(32, 0), pyt2llvm(32, 0)])
                interval_start = builder.load(interval_start_ptr)
                offset = builder.sub(pyt2llvm(32, current_compose_start), interval_start)
                builder.call(fc_ptr, [self.interval_tree_new, interval_tree, offset])
                fully_tainted = pyt2llvm(64, 0)

        return fully_tainted

    def gen_taint_from_all_read_elements(self, read_elements):
        if not read_elements :
            return pyt2llvm(64, 0)
        for composant in read_elements:
            fully_tainted = self.add_ir_taint(composant["full"], full = True)
            predicat = self.builder.trunc(fully_tainted, LLVMType.IntType(1))
            with self.builder.if_then(self.builder.not_(predicat)) as then_block: 
                # fully_tainted always value to 0
                fully_tainted = self.add_ir_taint(composant["elements"], current_compose_start = composant["start"])
            if "composition" in composant:
                fully_tainted = self.gen_taint_from_all_read_elements(composant["composition"])
                
        return fully_tainted
        



    def gen_irblock(self, instr_attrib, attributes, instr_offsets, irblock):
        """ Overload of LLVMFunction.gen_irblock to use taint engine

        """ 
        current_block = self.builder.block
        if self.not_branched is not None:
            self.builder.position_at_end(self.not_branched)
            self.builder.branch(self.bb_list[current_block.name][current_block.name + "_taint_0"])
            self.not_branched = None
            self.builder.position_at_start(current_block)
    
        for index, assignblk in enumerate(irblock):
        # dst is whether an ExprId or an ExprMem
            line_nb = 0
            for dst, src in viewitems(assignblk):
                #TODO gérer le cache
                print("Analysing %s = %s" % (dst,src))
                if dst != self.llvm_context.ir_arch.IRDst:
                    if line_nb == 0:
                        self.builder.position_at_start(self.bb_list[current_block.name][current_block.name +"_taint_0"])
                # Need the intervals tainted in the src to taint the dst with interval_tree_merge
                    color_index = 0
                    #XXX Maybe this loop will be made in llvm with the function phi
                    while color_index < self.llvm_context.nb_colors:
                        self.current_color = pyt2llvm(64, color_index)
                        read_elements = get_detailed_read_elements(dst, src)
                        fc_ptr = self.mod.get_global("taint_generic_structure")
                        fc_new = self.mod.get_global("interval_tree_new_llvm")
                        self.interval_tree_new = externalCall(fc_new, [], self.builder) 
                        if dst.is_mem():
                            # Find the range of the mem being targeted
                            addr_start_32 = self.add_ir(dst.ptr)
                            addr_end = self.builder.add(addr_start_32, pyt2llvm(32, int(dst.size/8 - 1)))
                            print(addr_end)
                            
                            #Initialization of some variables
                            interval_tree_before = self.gen_get_taint_generic(dst, self.current_color, "mem", addr_start_32, addr_end)
                            
                            fully_tainted = self.gen_taint_from_all_read_elements([read_elements])
                            index_or_addr = self.builder.zext(addr_start_32, LLVMType.IntType(64))
                            structure_size = pyt2llvm(64, int(dst.size/8 - 1))
                            structure_type = pyt2llvm(64, 2)
                        else:
                            #Initialize some variables 
                            structure_size_32 = pyt2llvm(32, dst.size)
                            structure_type = pyt2llvm(64, 1)
                            index_or_addr = pyt2llvm(64, self.llvm_context.regs_index[str(dst)])
                            start_interval = self.builder.gep(self.local_vars["interval_ptr"],[pyt2llvm(32, 0),pyt2llvm(32, 0)]) 
                            stop_interval = self.builder.gep(self.local_vars["interval_ptr"],[pyt2llvm(32, 0),pyt2llvm(32, 1)]) 
                            self.builder.store(pyt2llvm(32, 0), start_interval)
                            self.builder.store(structure_size_32, stop_interval)
                            interval_tree_before = self.gen_get_taint_generic(str(dst), self.current_color,"reg" , pyt2llvm(32, 0), structure_size_32)
                            fully_tainted = self.gen_taint_from_all_read_elements([read_elements])
                            structure_size = self.builder.zext(structure_size_32, LLVMType.IntType(64))
                        self.builder.call(fc_ptr,
                                          [fully_tainted,
                                           index_or_addr,
                                           structure_size,
                                           self.current_color,
                                           self.local_vars["jitcpu"],
                                           self.local_vars["vmmngr"],
                                           structure_type,
                                           interval_tree_before,
                                           self.interval_tree_new ])  
                        color_index+=1
                    line_nb+=1
                    label = current_block.name + "_taint_%d" % line_nb
                    try:
                        self.builder.branch(self.bb_list[current_block.name][label])
                        self.builder.position_at_start(self.bb_list[current_block.name][label])
                    except:
                        pass
                else:
                    case2dst, evaluated = self.expr2cases(src)
                    if case2dst[0].is_int():
                        loc = self.llvm_context.ir_arch.loc_db.getby_offset_create(int(dst))
                        dst = ExprLoc(loc, dst.size)
                    assert case2dst[0].is_loc()
                    bbl = self.get_basic_block_by_loc_key(case2dst[0].loc_key)
                    # External jump
                    if not bbl:
                        self.builder.branch(current_block)
                        self.builder.position_at_start(current_block)
                        self.not_branched = self.bb_list[current_block.name][current_block.name + "_taint_%d" % (line_nb-1)]
                    else:
                        self.builder.branch(self.bb_list[bbl.name][bbl.name + "_taint_0"])
                        self.builder.position_at_start(current_block)
                    

        self.builder.position_at_start(current_block)
        print(self)
        super(LLVMFunction_Taint, self).gen_irblock(instr_attrib, attributes, instr_offsets, irblock)

class LLVMContext_JIT_Taint(LLVMContext_JIT): 
     #TODO comments
    def __init__(self, libs, arch):
        self.taint = True
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
         fc = {"get_generic_structure": {"ret":llvm_ir.VoidType(), 
                                        "args":[p8,  
                                                itype,
                                                itype, 
                                                self.interval_type,
                                                itype,
                                                p8]},
            "taint_merge_interval_tree": {"ret":llvm_ir.VoidType(),
                                        "args":[p8, 
                                                p8, 
                                                i32]},
            "taint_generic_structure": {"ret":llvm_ir.VoidType(), 
                                        "args":[itype, 
                                                itype,
                                                itype,
                                                itype, 
                                                p8,
                                                p8,
                                                itype,
                                                p8,
                                                p8]},
            "taint_llvm_test" : {"ret": llvm_ir.VoidType(),
                                 "args" : [p8]},
            "taint_create_rb" : {"ret": llvm_ir.VoidType(),
                                 "args" : [p8]},
            "interval_tree_new_llvm" : {"ret": llvm_ir.VoidType(),
                                        "args" : [p8]},
            "check_fully_tainted" : {"ret": LLVMType.IntType(64),
                                     "args": [p8]},
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



# API functions
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
        @nb_colors : number of colors that will be used to taint, should be superior to 1 
    """

    if nb_colors < 1:
        raise "At least 1 color is required to enable taint analysis"
    try:
        nb_regs = init_registers_index(jitter)
        jitter.taint.init_taint_analysis(nb_colors, nb_regs)
        jitter.jit.context.nb_colors = nb_colors
    except:
        print("No LLVMContext created, the jitter should be set to llvm")
        sys.exit(0)

#Function utils
def pyt2llvm(size, value):
    return llvm_ir.Constant(LLVMType.IntType(size),value)

def externalCall(name, args, builder):
    rb_root_pointer = builder.alloca(LLVMType.IntType(32))
    rb_root_u8 = builder.bitcast(rb_root_pointer,llvm_ir.IntType(8).as_pointer())
    args.append(rb_root_u8)
    builder.call(name,args)
    return rb_root_u8
