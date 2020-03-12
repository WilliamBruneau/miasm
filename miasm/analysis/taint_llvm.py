import os
import tempfile
import pdb

from miasm.jitter.jitcore_llvm import JitCore_LLVM

def enable_taint_analysis(jitter, nb_colors=1):
  """method to initalize the taint analysis
     @jitter : the jitter should used llvm as a back-end
     @nb_colors : number of colors that will be used to taint, should be superior to 1 """

  if not isinstance(jitter.jit, JitCore_LLVM):
    raise "The jitter should be set to llvm"
  if nb_colors < 1:
    raise "At least 1 color is required to enable taint analysis"

  print("Start taint analysis engine")
