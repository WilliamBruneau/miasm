import pdb, sys
from future.utils import viewitems, viewvalues
from miasm.jitter.llvmconvert import LLVMFunction, LLVMType, LLVMContext_JIT
from miasm.analysis.taint_codegen import get_detailed_read_elements
from miasm.expression.expression import ExprId, ExprSlice, ExprLoc
from miasm.expression.expression_helper import possible_values
from llvmlite import ir as llvm_ir

class LLVMFunction_Taint(LLVMFunction):
#TODO comments
    def __init__(self, llvm_context, name="fc", new_module=True):
        LLVMFunction.__init__(self, llvm_context, name, new_module)


    def init_fc(self):
        super(LLVMFunction_Taint, self).init_fc()

        builder = self.builder

        # Initialize the interval and get both the pointer of
        # interval.start and interval.last
        interval_ptr = builder.alloca(self.llvm_context.interval_type)
        self.local_vars["interval_ptr"] = interval_ptr
        self.start_ptr = builder.gep(self.local_vars["interval_ptr"],[pyt2llvm(32, 0),pyt2llvm(32, 0)]) 
        self.stop_ptr = builder.gep(self.local_vars["interval_ptr"],[pyt2llvm(32, 0),pyt2llvm(32, 1)])


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
        builder.store(start_check, self.start_ptr)
        builder.store(stop_check, self.stop_ptr)
        interval_struct = builder.load(self.local_vars["interval_ptr"])

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
        return interval_tree

    def gen_jump(self, expr_loc):
        #TODO Comments
        """Generate the jump to the expr_loc
        """
        assert expr_loc.is_loc() == True
        
    
        try:
            # Making an internal jump
            label = str(expr_loc.loc_key) + "_taint_0"
            self.builder.branch(self.bb_list[str(expr_loc.loc_key)][label])
            return
        except:
            self.builder.branch(self.first_label)
            return
        aeraz

        #XXX This part should be erased (Kept until there are no segfault)
        # Might be external jump
        if isinstance(case2dst[0], ExprLoc): 
            if len(case2dst) > 1:
                #Check if we are doing an external jump
                i = 0
                external_jump = False
                while i < len(case2dst):
                    bbl = self.get_basic_block_by_loc_key(case2dst[i].loc_key) 
                    i += 1
                    if bbl is None:
                        external_jump = True
                if external_jump:
                        self.builder.branch(self.first_label)
                        self.builder.position_at_start(self.first_label)
                else:
                    if label == "":
                        label = self.builder.block.name + "_taint_0"
                    self.not_branched = self.bb_list[current_block.name][label]
            else:
                bbl = self.get_basic_block_by_loc_key(case2dst[0].loc_key)
                # External jump
                if not bbl:
                    self.builder.branch(self.first_label)
                    self.builder.position_at_start(self.first_label)
                # Internal Jump
                else:
                    self.builder.branch(self.bb_list[bbl.name][bbl.name + "_taint_0"])
                    self.builder.position_at_start(current_block)
        #External Jump (special case, Idst = loc_key in two IR instructions)
        else:
            self.builder.branch(self.first_label)
            self.builder.position_at_start(self.first_label)
                
    
    def gen_branch(self, dst, src, current_block, label = ""):
        # We always come here if dst is an IRDst
        # There is a special case where there might be IRDst = Expr(...)
        # In this case we dont know yet what to do

        # Evaluation of the IRDst = Expr(...) to know the branching
        # Do I need to remake the expr2cases for my bbls?
        case2dst, evaluated = self.expr2cases(src)
        
        # A jump to one assignblk, without needing to evaluate
        if len(case2dst) ==1:
            self.gen_jump(next(iter(viewvalues(case2dst))))
            
        # A jump to multiple assignblk, must be handled to analyze only the code really executed
        else:
            current_bbl = self.builder.block
            print(dst, src)
            # Gen the out cases of the assignblks
            case2bbl = {}
            for case, dst in list(viewitems(case2dst)):
                name = "switch_%s_case_%d" % (label, case)
                bbl = self.append_basic_block(name)
                case2bbl[case] = bbl
                self.builder.position_at_start(bbl)
                self.gen_jump(dst)
            self.builder.position_at_end(current_bbl)
            switch = self.builder.switch(evaluated, case2bbl[0])
            for i, bbl in viewitems(case2bbl):
                if i==0:
                    continue
                switch.add_case(i,bbl)
             
        

    def add_ir_taint(self, elements, full = False, current_compose_start = 0):
        #TODO comments
        
        # If there is no elements which fully taint
        if not elements : 
            return pyt2llvm(64, 0)

        builder = self.builder

        # For now, but should be handled TODO
        color_index = 0

        # Initially we do not want to fully taint the dst
        is_fully_tainted = pyt2llvm(64, 0)

        for element in elements:
            if element.is_mem():
                # Infos on the element
                start = self.add_ir(element.ptr)
                start_32 = self.builder.zext(start, LLVMType.IntType(32))
                size = pyt2llvm(32, int(element.size/8))
                stop = builder.add(start_32, size)

                # Get the interval_tree of the element
                interval_tree = self.gen_get_taint_generic(element, pyt2llvm(64, color_index), "mem", start_32, stop)

            elif element.is_slice():
                interval_tree = self.gen_get_taint_generic(str(element.arg), pyt2llvm(64, color_index), "reg", pyt2llvm(32, element.start), pyt2llvm(32, element.stop))

            elif element.is_id():
                interval_tree = self.gen_get_taint_generic(str(element.name), pyt2llvm(64, color_index), "reg", pyt2llvm(32, 0), pyt2llvm(32, element.size) )

            if full:
                fc_ptr = self.mod.get_global("check_rb_tree_not_empty")
                fully_tainted = builder.call(fc_ptr, [interval_tree])
                is_fully_tainted = builder.or_(is_fully_tainted, fully_tainted)
            else:
                fc_ptr = self.mod.get_global("taint_merge_interval_tree")
                interval_start_ptr = builder.gep(self.local_vars["interval_ptr"], [pyt2llvm(32, 0), pyt2llvm(32, 0)])
                interval_start = builder.load(interval_start_ptr)
                offset = builder.sub(pyt2llvm(32, int(current_compose_start)), interval_start)
                interval_merged = builder.call(fc_ptr, [offset,
                                                        self.interval_tree_new,
                                                        interval_tree])
                is_fully_tainted = pyt2llvm(64, 0)
            

        return is_fully_tainted

    def gen_taint_from_all_read_elements(self, read_elements):
        #TODO comments

        # The base case of recursion, we return 0 as fully_tainted
        if not read_elements :
            return pyt2llvm(64, 0)
        for composant in read_elements:
            # Analyze the full composants 
            fully_tainted = self.add_ir_taint(composant["full"], full = True)
            if not composant["elements"]:
                pass
            else:
                # If not fully_tainted analyze the other elements
                predicat = self.builder.trunc(fully_tainted, LLVMType.IntType(1))
                with self.builder.if_then(self.builder.not_(predicat)) as then_block: 
                    fully_tainted = self.add_ir_taint(composant["elements"], current_compose_start = composant["start"])
            if composant["composition"]:
                is_fully_tainted = self.gen_taint_from_all_read_elements(composant["composition"])
                self.builder.or_(fully_tainted, is_fully_tainted)
                
        return fully_tainted
        



    def gen_irblock(self, instr_attrib, attributes, instr_offsets, irblock):
        """ Overload of LLVMFunction.gen_irblock to use taint engine

        """ 

        current_block = self.builder.block
        label = current_block.name + "_taint_0"
    
        # Cycling through each assignblock of the irblock
        for index, assignblk in enumerate(irblock):
            line_nb = 0 # Correspond to the ExprAssign number

            # Cycling through each ExprAssign of the assignblk 
            for dst, src in viewitems(assignblk):
                #TODO gérer le cache

                #print("Analysing %s = %s" % (dst,src)) #XXX commented to debug
                # Analysing the ExprAssign with the taint engine if the dst is not an IRDst
                if dst != self.llvm_context.ir_arch.IRDst :
                    # Special case, dont know if it will be kept, 
                    # of form - IRdst = Expr(...),
                    #         - Expr(...) = loc_key
                    # We can also chose to not do anything in this case
                    if src == self.llvm_context.ir_arch.IRDst :
                        print("Analysing %s = %s, Special case" % (dst, src))
                        self.gen_branch(dst, src, current_block, label = label)
                        continue
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
                            
                            # Get the interval_tree of the dst
                            interval_tree_before = self.gen_get_taint_generic(dst, self.current_color, "mem", addr_start_32, addr_end)

                           
                            # Generate the code to analyze all the elements 
                            fully_tainted = self.gen_taint_from_all_read_elements([read_elements])

                            # Infos on the structure that is going to be tainted
                            index_or_addr = self.builder.zext(addr_start_32, LLVMType.IntType(64))
                            structure_size = pyt2llvm(64, int(dst.size/8 - 1))
                            structure_type = pyt2llvm(64, 2)
                            is_equal= self.builder.icmp_signed("==",addr_start_32, pyt2llvm(32, 4198424))
                            with self.builder.if_then(is_equal) as (then_block):
                                self.printf("This one is wrong\n")
                                self.printf(str(dst))
                                self.builder.ret(pyt2llvm(64, -1))


                        # The dst is a register in this case
                        else:
                            # Infos on the structure going to be tainted
                            structure_size_32 = pyt2llvm(32, dst.size)
                            structure_type = pyt2llvm(64, 1)
                            index_or_addr = pyt2llvm(64, self.llvm_context.regs_index[str(dst)])

                            # Get the interval_tree of the dst
                            interval_tree_before = self.gen_get_taint_generic(str(dst), self.current_color,"reg" , pyt2llvm(32, 0), structure_size_32)

                            # Generate the llvm code
                            fully_tainted = self.gen_taint_from_all_read_elements([read_elements])

                            structure_size = self.builder.zext(structure_size_32, LLVMType.IntType(64))

                        # Calling the taint function
                        color_index+=1
                        self.builder.call(fc_ptr,
                                          [fully_tainted,
                                           index_or_addr,
                                           structure_size,
                                           self.current_color,
                                           self.local_vars["jitcpu"],
                                           self.local_vars["vmmngr"],
                                           structure_type,
                                           interval_tree_before,
                                           self.interval_tree_new
                                           ])  

                    # Update the line_nb and the label
                    line_nb += 1
                    label = current_block.name + "_taint_%d" % line_nb
                    
                    try:
                        # Trying to branch to the next ExprAssign, if not succesful it means we're jumping on another assignblk
                        self.builder.branch(self.bb_list[current_block.name][label])
                        self.builder.position_at_start(self.bb_list[current_block.name][label])
                    except:
                        # The next dst should be an IRDst
                        continue

                # Make the branching for the next assignblk
                else:
                    self.gen_branch(dst, src, current_block, label = label)
                    

        self.builder.position_at_start(current_block)
        super(LLVMFunction_Taint, self).gen_irblock(instr_attrib, attributes, instr_offsets, irblock)

class LLVMContext_JIT_Taint(LLVMContext_JIT): 
     #TODO comments
    def __init__(self, libs, arch):
        LLVMContext_JIT.__init__(self, libs, arch)      

    def add_taint_structures(self):
        self.interval_type = llvm_ir.LiteralStructType( 
            [
                LLVMType.IntType(32), # interval.start
                LLVMType.IntType(32) # interval.last
            ]
        )

    def add_taint_functions(self):
         i8 = LLVMType.IntType(8)
         p8 = llvm_ir.PointerType(i8)
         i32 = LLVMType.IntType(32)
         itype = LLVMType.IntType(64)
         fc = {"get_generic_structure": {"ret":llvm_ir.VoidType(), 
                                        "args":[p8,  
                                                itype,
                                                itype, 
                                                self.interval_type,
                                                itype,
                                                p8]},
            "taint_merge_interval_tree": {"ret":llvm_ir.VoidType(),
                                        "args":[i32,
                                                p8,
                                                p8 ]},
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
            "interval_tree_new_llvm" : {"ret": llvm_ir.VoidType(),
                                        "args" : [p8]},
            "check_rb_tree_not_empty" : {"ret": itype,
                                     "args": [p8]}
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
