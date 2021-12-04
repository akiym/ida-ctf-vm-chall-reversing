# Processor module template script by (c) Hex-Rays
from typing import Optional

import ida_auto
import ida_bytes
import ida_frame
import ida_funcs
import ida_idaapi
import ida_nalt
import ida_offset
import ida_ua
import ida_xref
from ida_funcs import func_t
from ida_idaapi import BADADDR
from ida_idp import ASB_BINF4, ASH_HEXF3, AS_COLON, AS_N2CHR, AS_UNEQU, CF_CHG1, CF_JUMP, CF_STOP, CF_USE1, \
    CF_USE2, \
    PRN_HEX, \
    PR_ASSEMBLE, \
    PR_DEFSEG32, \
    PR_RNAMESOK, \
    PR_SEGS, \
    PR_USE32, \
    processor_t
from ida_ua import OOFW_IMM, dt_byte, dt_word, insn_t, o_imm, o_near, o_reg, o_void, op_t, outctx_t
from ida_xref import dr_R, fl_CN, fl_F, fl_JN


class fallenlap_t(processor_t):
    """
    Processor module classes must derive from idaapi.processor_t

    A processor_t instance is, conceptually, both an IDP_Hooks and
    an IDB_Hooks. This means any callback from those two classes
    can be implemented. Below, you'll find a handful of those
    as an example (e.g., ev_out_header(), ev_newfile(), ...)
    Also note that some IDP_Hooks callbacks must be implemented
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 1

    # Processor features
    flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['fallenlap']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['fallen lap ray']

    # size of a segment register in bytes
    segreg_size = 0

    # Array of typical code start sequences (optional)
    codestart = []

    # Array of 'return' instruction opcodes (optional)
    retcodes = ['\x02\x20\x00\x00']

    # Array of instructions. Since this is only a template,
    # this list will be extremely limited.
    instruc = [
        {'name': 'imm', 'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'stk', 'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'add', 'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'stm', 'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'ldm', 'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'jmp_if', 'feature': CF_USE1 | CF_USE2},
        {'name': 'cmp', 'feature': CF_USE1 | CF_USE2},
        {'name': 'sys', 'feature': CF_USE1 | CF_USE2},

        # alias:
        # stk 0, $reg
        {'name': 'push', 'feature': CF_USE1},
        # stk $reg, 0
        {'name': 'pop', 'feature': CF_USE1 | CF_CHG1},
        # stk $ip, 0
        {'name': 'ret', 'feature': CF_STOP},
        # jmp 0x0, $reg
        {'name': 'jmp', 'feature': CF_USE1 | CF_JUMP | CF_STOP},
        # jmp_if 0x1, $reg
        {'name': 'jg', 'feature': CF_USE1 | CF_JUMP},
        # jmp_if 0x2, $reg
        {'name': 'jl', 'feature': CF_USE1 | CF_JUMP},
        # jmp_if 0x4, $reg
        {'name': 'je', 'feature': CF_USE1 | CF_JUMP},
        # jmp_if 0x8, $reg
        {'name': 'jne', 'feature': CF_USE1 | CF_JUMP},
        # jmp_if 0x10, $reg
        {'name': 'jz', 'feature': CF_USE1 | CF_JUMP},
    ]

    # icode of the first instruction
    instruc_start = 0

    # icode of the last instruction + 1
    instruc_end = len(instruc)

    # Size of long double (tbyte) for this processor (meaningful only if ash.a_tbyte != NULL) (optional)
    tbyte_size = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 7, 15, 0)

    # only one assembler is supported
    assembler = {
        # flag
        'flag': ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        'uflag': 0,

        # Assembler name (displayed in menus)
        'name': "My processor module bytecode assembler",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        'header': ["Line1", "Line2"],

        # org directive
        'origin': "org",

        # end directive
        'end': "end",

        # comment string (see also cmnt2)
        'cmnt': ";",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': "db",

        # byte directive
        'a_byte': "db",

        # word directive
        'a_word': "dw",

        # remove if not allowed
        'a_dword': "dd",

        # remove if not allowed
        'a_qword': "dq",

        # remove if not allowed
        'a_oword': "xmmword",

        # remove if not allowed
        'a_yword': "ymmword",

        # float;  4bytes; remove if not allowed
        'a_float': "dd",

        # double; 8bytes; NULL if not allowed
        'a_double': "dq",

        # long double;    NULL if not allowed
        'a_tbyte': "dt",

        # packed decimal real; remove if not allowed (optional)
        'a_packreal': "",

        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': "#d dup(#v)",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "%s dup ?",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "public",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "weak",

        # "extrn"  name keyword
        'a_extrn': "extrn",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': "align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # %  mod     assembler time operation
        'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # ~  bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string) (optional)
        'a_sizeof_fmt': "size %s",

        'flag2': 0,

        # comment close string (optional)
        # this is used to denote a string which closes comments, for example, if the comments are represented with (* ... *)
        # then cmnt = "(*" and cmnt2 = "*)"
        'cmnt2': "",

        # low8 operation, should contain %s for the operand (optional fields)
        'low8': "",
        'high8': "",
        'low16': "",
        'high16': "",

        # the include directive (format string) (optional)
        'a_include_fmt': "include %s",

        # if a named item is a structure and displayed  in the verbose (multiline) form then display the name
        # as printf(a_strucname_fmt, typename)
        # (for asms with type checking, e.g. tasm ideal)
        # (optional)
        'a_vstruc_fmt': "",

        # 'rva' keyword for image based offsets (optional)
        # (see nalt.hpp, REFINFO_RVA)
        'a_rva': "rva"
    }  # Assembler

    def itype(self, name: str) -> int:
        for i, x in enumerate(self.instruc):
            if x['name'] == name:
                return i
        raise ValueError(f'unknown itype: {name}')

    def ireg(self, name: str) -> int:
        for i, x in enumerate(self.reg_names):
            if x == name:
                return i
        raise ValueError(f'unknown reg: {name}')

    def find_reg(self, value: int) -> int:
        return {
            0x0: self.ireg('flags'),
            0x1: self.ireg('reg1'),
            0x2: self.ireg('reg2'),
            0x4: self.ireg('reg3'),
            0x8: self.ireg('reg4'),
            0x10: self.ireg('sp'),
            0x20: self.ireg('ip'),
        }[value]

    def prev_insn(self, insn: Optional[insn_t]) -> Optional[insn_t]:
        if insn is None:
            return None
        prev = insn_t()
        if ida_ua.decode_prev_insn(prev, insn.ea):
            return prev
        return None

    def load_mem(self, addr: int) -> int:
        return ida_idaapi.as_signed(ida_bytes.get_qword(addr), 64)

    def is_itype(self, insn: insn_t, name: str) -> bool:
        return insn.itype == self.itype(name)

    #
    # IDP_Hooks callbacks
    #

    def add_stkpnt(self, pfn: func_t, insn: insn_t, v: int):
        if pfn:
            end = insn.ea + insn.size
            if not ida_nalt.is_fixed_spd(end):
                ida_frame.add_auto_stkpnt(pfn, end, v)

    def trace_sp(self, insn: insn_t):
        pfn = ida_funcs.get_func(insn.ea)
        if not pfn:
            return

        spofs = 0
        if insn.itype == self.itype('push'):
            spofs = -8
        elif insn.itype == self.itype('pop'):
            spofs = 8
        elif insn.itype == self.itype('add') and \
                insn.Op1.is_reg(self.ireg('sp')):
            prev1 = self.prev_insn(insn)
            prev2 = self.prev_insn(prev1)
            # imm $reg, 0xabc
            # ldm $reg, $reg
            # add $sp, $reg
            if prev1 and prev2 and \
                    self.is_itype(prev2, 'imm') and prev2.Op1.is_reg(prev1.Op2.reg) and \
                    self.is_itype(prev1, 'ldm') and prev1.Op1.is_reg(insn.Op2.reg):
                spofs = ida_idaapi.as_signed(ida_bytes.get_qword(prev2.Op2.value), 64)
        elif self.is_itype(insn, 'jmp'):  # call
            spofs = 8

        if spofs != 0:
            self.add_stkpnt(pfn, insn, spofs)

    def ev_emu_insn(self, insn: insn_t):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'insn' structure.
        If zero is returned, the kernel will delete the instruction.
        """

        feature = insn.get_canon_feature()

        is_call = False
        if feature & CF_JUMP:
            prev1 = self.prev_insn(insn)
            prev2 = self.prev_insn(prev1)
            prev3 = self.prev_insn(prev2)
            # imm $reg, 0xabc
            # push $reg
            # imm $reg, 0xdef
            # jmp $reg
            if prev1 and prev2 and prev3 and \
                    self.is_itype(prev3, 'imm') and prev3.Op1.is_reg(prev2.Op1.reg) and \
                    self.is_itype(prev2, 'push') and \
                    self.is_itype(prev1, 'imm') and prev1.Op1.is_reg(insn.Op1.reg) and \
                    self.is_itype(insn, 'jmp'):
                ida_xref.add_cref(insn.ea, prev1.Op2.value, fl_CN)
                ida_xref.add_cref(insn.ea, prev3.Op2.value, fl_JN)
                ida_offset.op_plain_offset(prev1.ea, 1, insn.cs)
                ida_offset.op_plain_offset(prev3.ea, 1, insn.cs)
                is_call = True
            # imm $reg, 0xabc
            # jl $reg
            # je $reg
            # ...
            else:
                candidates = [insn.ea]
                prev = self.prev_insn(insn)
                while True:
                    if prev and \
                            prev.get_canon_feature() & CF_JUMP and \
                            prev.Op1.is_reg(insn.Op1.reg):
                        candidates.append(prev.ea)
                        prev = self.prev_insn(prev)
                    else:
                        break
                if prev and \
                        self.is_itype(prev, 'imm') and prev.Op1.is_reg(insn.Op1.reg):
                    ida_offset.op_plain_offset(prev.ea, 1, insn.cs)
                    for addr in candidates:
                        ida_xref.add_cref(addr, prev.Op2.value, fl_JN)

        flow = feature & CF_STOP == 0
        if flow:
            ida_xref.add_cref(insn.ea, insn.ea + insn.size, fl_F)

        if self.is_itype(insn, 'imm'):
            ida_xref.add_dref(insn.ea, insn.Op2.value, dr_R)

        if ida_auto.may_trace_sp():
            if flow or is_call:
                self.trace_sp(insn)
            else:
                ida_frame.recalc_spd(insn.ea)

        # imm $reg, 0xabc
        # ldm $reg, $reg
        if self.is_itype(insn, 'ldm'):
            prev = self.prev_insn(insn)
            if prev and \
                    self.is_itype(prev, 'imm') and prev.Op1.is_reg(insn.Op2.reg):
                v = self.load_mem(prev.Op2.value)
                ida_bytes.set_cmt(prev.ea, f'{v:#x}', 0)

        return True

    def ev_out_operand(self, ctx: outctx_t, op: op_t):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: success
        """
        if op.type == o_reg:
            ctx.out_register('$' + self.reg_names[op.reg])
        elif op.type == o_imm:
            ctx.out_value(op, OOFW_IMM)
        elif op.type == o_near:
            ctx.out_name_expr(op, op.addr, BADADDR)
        else:
            return False
        return True

    def ev_out_insn(self, ctx: outctx_t):
        """
        Generate text representation of an instruction in 'ctx.insn' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: nothing
        """
        ctx.out_mnemonic()

        for i in range(0, 2):
            op = ctx.insn[i]
            if op.type == o_void:
                break
            if i > 0:
                ctx.out_symbol(',')
                ctx.out_char(' ')
            ctx.out_one_operand(i)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()
        return True

    def simplify(self, insn: insn_t):
        maptbl = {
            self.itype('stk'): [
                (lambda: insn.Op1.reg == 0, self.itype('push'), 2),
                (lambda: insn.Op2.reg == 0 and insn.Op1.reg == self.ireg('ip'), self.itype('ret'), 0),
                (lambda: insn.Op2.reg == 0, self.itype('pop'), 1),
            ],
            self.itype('jmp_if'): [
                (lambda: insn.Op1.value == 0x0, self.itype('jmp'), 2),
                (lambda: insn.Op1.value == 0x1, self.itype('jg'), 2),
                (lambda: insn.Op1.value == 0x2, self.itype('jl'), 2),
                (lambda: insn.Op1.value == 0x4, self.itype('je'), 2),
                (lambda: insn.Op1.value == 0x8, self.itype('jne'), 2),
                (lambda: insn.Op1.value == 0x10, self.itype('jz'), 2),
            ],
        }

        if insn.itype in maptbl:
            for m in maptbl[insn.itype]:
                fn, itype, n = m
                if fn():
                    insn.itype = itype
                    if n == 0:
                        insn.Op1.type = o_void
                    elif n == 2:
                        insn.Op1.assign(insn.Op2)
                    insn.Op2.type = o_void
                    break

    def ev_ana_insn(self, insn: insn_t):
        """
        Decodes an instruction into insn
        Returns: insn.size (=the size of the decoded instruction) or zero
        """
        b = insn.get_next_byte()
        if b == 0x1:
            reg = insn.get_next_byte()
            v = insn.get_next_word()
            insn.itype = self.itype('imm')
            insn.Op1.type = o_reg
            insn.Op1.reg = self.find_reg(reg)
            insn.Op2.type = o_imm
            insn.Op2.dtype = dt_word
            insn.Op2.value = v
            insn.Op2.addr = v
        elif b == 0x2:
            reg1 = self.find_reg(insn.get_next_byte())
            reg2 = self.find_reg(insn.get_next_byte())
            insn.get_next_byte()
            insn.itype = self.itype('stk')
            insn.Op1.type = o_reg
            insn.Op1.reg = reg1
            insn.Op2.type = o_reg
            insn.Op2.reg = reg2
        elif b == 0x4:
            reg1 = self.find_reg(insn.get_next_byte())
            reg2 = self.find_reg(insn.get_next_byte())
            insn.get_next_byte()
            insn.itype = self.itype('add')
            insn.Op1.type = o_reg
            insn.Op1.reg = reg1
            insn.Op2.type = o_reg
            insn.Op2.reg = reg2
        elif b == 0x8:
            reg1 = self.find_reg(insn.get_next_byte())
            reg2 = self.find_reg(insn.get_next_byte())
            insn.get_next_byte()
            insn.itype = self.itype('stm')
            insn.Op1.type = o_reg
            insn.Op1.reg = reg1
            insn.Op2.type = o_reg
            insn.Op2.reg = reg2
        elif b == 0x10:
            reg1 = self.find_reg(insn.get_next_byte())
            reg2 = self.find_reg(insn.get_next_byte())
            insn.get_next_byte()
            insn.itype = self.itype('ldm')
            insn.Op1.type = o_reg
            insn.Op1.reg = reg1
            insn.Op2.type = o_reg
            insn.Op2.reg = reg2
        elif b == 0x20:
            v = insn.get_next_byte()
            reg = self.find_reg(insn.get_next_byte())
            insn.get_next_byte()
            insn.itype = self.itype('jmp_if')
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = v
            insn.Op2.type = o_reg
            insn.Op2.reg = reg
        elif b == 0x40:
            reg1 = self.find_reg(insn.get_next_byte())
            reg2 = self.find_reg(insn.get_next_byte())
            insn.get_next_byte()
            insn.itype = self.itype('cmp')
            insn.Op1.type = o_reg
            insn.Op1.reg = reg1
            insn.Op2.type = o_reg
            insn.Op2.reg = reg2
        elif b == 0x80:
            v = insn.get_next_byte()
            reg = self.find_reg(insn.get_next_byte())
            insn.get_next_byte()
            insn.itype = self.itype('sys')
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = v
            insn.Op2.type = o_reg
            insn.Op2.reg = reg

            nr = {
                0x2: 'read',
                0x8: 'write',
                0x20: 'exit',
            }
            ida_bytes.set_cmt(insn.ea, nr[v], 0)
        else:
            assert 0

        self.simplify(insn)

        return True

    def init_instructions(self):
        # icode (or instruction number) of return instruction. It is ok to give any of possible return
        # instructions
        self.icode_return = self.itype('ret')

    def init_registers(self):
        # register names
        self.reg_names = [
            "flags",
            "reg1",
            "reg2",
            "reg3",
            "reg4",
            "sp",
            "ip",
            # Fake segment registers
            "CS",
            "DS",
        ]

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        self.reg_first_sreg = self.ireg('CS')
        self.reg_last_sreg = self.ireg('DS')

        # You should define 2 virtual segment registers for CS and DS.

        # number of CS/DS registers
        self.reg_code_sreg = self.ireg('CS')
        self.reg_data_sreg = self.ireg('DS')

    def __init__(self):
        processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()


def PROCESSOR_ENTRY():
    return fallenlap_t()
