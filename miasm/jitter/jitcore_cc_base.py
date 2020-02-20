#-*- coding:utf-8 -*-

import os
import tempfile
import platform
import sysconfig
from distutils.sysconfig import get_python_inc

from miasm.jitter.jitcore import JitCore
from miasm.core.utils import keydefaultdict

is_win = platform.system() == "Windows"

def gen_core(arch, attrib, taint):
    lib_dir = os.path.dirname(os.path.realpath(__file__))

    txt = ""
    txt += '#include "%s/queue.h"\n' % lib_dir
    txt += '#include "%s/op_semantics.h"\n' % lib_dir
    txt += '#include "%s/vm_mngr.h"\n' % lib_dir
    txt += '#include "%s/bn.h"\n' % lib_dir
    txt += '#include "%s/vm_mngr_py.h"\n' % lib_dir
    txt += '#include "%s/JitCore.h"\n' % lib_dir
    if taint:
        txt += '#include "%s/analysis/taint_analysis.h"\n' % os.path.dirname(lib_dir)
        txt += '#include "%s/interval_tree/interval_tree.h"\n' % lib_dir
    txt += '#include "%s/arch/JitCore_%s.h"\n' % (lib_dir, arch.name)

    txt += r'''
#define RAISE(errtype, msg) {PyObject* p; p = PyErr_Format( errtype, msg ); return p;}
'''
    return txt


class myresolver(object):

    def __init__(self, offset):
        self.offset = offset

    def ret(self):
        return "return PyLong_FromUnsignedLongLong(0x%X);" % self.offset


class resolver(object):

    def __init__(self):
        self.resolvers = keydefaultdict(myresolver)

    def get_resolver(self, offset):
        return self.resolvers[offset]


class JitCore_Cc_Base(JitCore):
    "JiT management, abstract class using a C compiler as backend"

    def __init__(self, ir_arch, bin_stream, taint=False):
        self.jitted_block_delete_cb = self.deleteCB
        super(JitCore_Cc_Base, self).__init__(ir_arch, bin_stream)
        self.resolver = resolver()
        self.ir_arch = ir_arch
        self.states = {}
        self.taint = taint
        if self.taint:
            self.tempdir = os.path.join(tempfile.gettempdir(), "miasm_cache_taint")
        else:
            self.tempdir = os.path.join(tempfile.gettempdir(), "miasm_cache")
        try:
            os.mkdir(self.tempdir, 0o755)
        except OSError:
            pass
        if not os.access(self.tempdir, os.R_OK | os.W_OK):
            raise RuntimeError(
                'Cannot access cache directory %s ' % self.tempdir)
        self.exec_wrapper = None
        self.libs = None
        self.include_files = None

    def deleteCB(self, offset):
        raise NotImplementedError()

    def load(self):
        lib_dir = os.path.dirname(os.path.realpath(__file__))
        ext = sysconfig.get_config_var('EXT_SUFFIX')
        if ext is None:
            ext = ".so" if not is_win else ".lib"

        libs = [
            os.path.join(lib_dir, "VmMngr" + ext),
            os.path.join(
                lib_dir,
                "arch",
                "JitCore_%s%s" % (self.ir_arch.arch.name,
                                  "_taint" + ext if self.taint else ext)
            )
        ]

        include_files = [
            os.path.dirname(__file__),
            get_python_inc()
        ]
        self.include_files = include_files
        self.libs = libs

    def init_codegen(self, codegen):
        """
        Get the code generator @codegen
        @codegen: an CGen instance
        """
        self.codegen = codegen

    def gen_c_code(self, block):
        """
        Return the C code corresponding to the @irblocks
        @irblocks: list of irblocks
        """
        f_declaration = '_MIASM_EXPORT int %s(block_id * BlockDst, JitCpu* jitcpu)' % self.FUNCNAME
        out = self.codegen.gen_c(
            block,
            log_mn=self.log_mn,
            log_regs=self.log_regs
        )
        out = [f_declaration + '{'] + out + ['}\n']
        c_code = out

        return self.gen_C_source(self.ir_arch, c_code, self.taint)

    @staticmethod
    def gen_C_source(ir_arch, func_code, taint):
        raise NotImplementedError()
