import os
import tempfile
import pdb

from miasm.jitter.jitcore_llvm import JitCore_LLVM

def enable_taint_analysis(jitter, nb_colors=1):

  print("Start taint analysis engine")
