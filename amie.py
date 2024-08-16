import inspect
import json
import os
import re
import struct
import sys

import idaapi
import ida_allins
import ida_bytes
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_lines
import ida_segregs
import ida_ua


class Arch(object):
    @staticmethod
    def output_insn(outctx, mne, dst_reg, src_reg=None):
        outctx.out_custom_mnem(mne.upper(), 16)
        outctx.out_register(dst_reg)
        if src_reg:
            outctx.out_printf(", ")
            outctx.out_register(src_reg)
        outctx.flush_outbuf()
        return True

    def __init__(self, file_name):
        cur_file = inspect.getsourcefile(lambda: 0)
        cur_path = os.path.dirname(os.path.abspath(cur_file))

        def unicode_to_str(data, ignore_dicts=False):
            if isinstance(data, unicode):
                return data.encode("utf-8")
            if isinstance(data, list):
                return [unicode_to_str(item, True) for item in data]
            if isinstance(data, dict) and not ignore_dicts:
                return {unicode_to_str(key): unicode_to_str(value, True)
                        for key, value in data.iteritems()}
            return data

        with open(os.path.join(cur_path, file_name), "r") as fd:
            hook = unicode_to_str if sys.version_info[0] < 3 else None
            self.data = json.loads(fd.read(), object_hook=hook)

        self.regs, self.regs_enc = {}, {}
        for regs_group, regs in self.data["registers"].items():
            if regs_group == "encodings":
                self.regs_enc = regs
            else:
                self.regs.update(regs)

        self.insns, self.insns_enc = {}, {}
        for insns_group, insns in self.data["instructions"].items():
            if insns_group == "encodings":
                self.insns_enc = insns
            else:
                self.insns.update(insns)

    def matches(self, op, reg_op):
        op_str = "{:0{size}b}".format(op, size=len(reg_op))[: len(reg_op)]
        for i in range(len(op_str)):
            if op_str[i] != reg_op[i] and reg_op[i] != "x":
                return False
        return True

    def find_reg_enc(self, enc_type, ops):
        for cp_reg_name, reg_ops in self.regs_enc[enc_type].items():
            for i in range(len(ops)):
                if not self.matches(ops[i], reg_ops[i]):
                    break
            else:
                return cp_reg_name
        print("[AMIE] %s encoding not found for: %s" % (enc_type, ops))

    def find_insn_enc(self, enc_type, insn_bs, insn_mne):
        for insn_name, insn_encs in self.insns_enc[enc_type].items():
            for tmpl_name, insn_enc in insn_encs.items():
                match = self.matches(insn_bs, insn_enc[0])
                for enc in insn_enc[1:]:
                    match = match and not self.matches(insn_bs, enc)
                if not match:
                    continue

                for tmpls in self.insns[insn_name]["templates"].values():
                    for tmpl in tmpls:
                        mne = tmpl.split(" ")[0]
                        mne = re.sub("{[^}]}", "", mne)
                        mne = re.sub("<[^>]>", "", mne)
                        if mne.startswith(insn_mne):
                            return insn_name, tmpl_name
        print("[AMIE] %s encoding not found for: %s" % (enc_type, insn_mne))

    def output(self, outctx):
        raise False

    def hint(self, ea, tag, val):
        val = val.strip()
        if not val:
            return None

        if tag == ida_lines.SCOLOR_REG:
            if val.split(".")[0] in self.regs:
                register = self.regs[val.split(".")[0]]
                return register["long_name"], register["purpose"]

        elif tag == ida_lines.SCOLOR_INSN:
            insn = ida_ua.insn_t()
            ida_ua.decode_insn(insn, ea)
            insn_bs = ida_bytes.get_bytes(insn.ea, insn.size)
            fmt = {2: "<H", 4: "<I", 8: "<Q"}
            insn_bs = struct.unpack(fmt.get(len(insn_bs)), insn_bs)[0]

            enc_type = "A64"
            if isinstance(self, AArch32):
                enc_type = "A32"
                if ida_segregs.get_sreg(ea, 20) > 0:
                    enc_type = "T32"

            insn_enc = enc_type, insn_bs, insn.get_canon_mnem()
            insn_enc = self.find_insn_enc(*insn_enc)
            if not insn_enc:
                return
            insn_name, tmpl_name = insn_enc
            insn = self.insns[insn_name]

            desc = insn["authored"]
            if tmpl_name and tmpl_name in insn["templates"]:
                desc += "\n\n" + "\n".join(insn["templates"][tmpl_name])
            return insn["heading"], desc

        elif tag == ida_lines.SCOLOR_KEYWORD:
            if val in self.data["keywords"]:
                return val, self.data["keywords"][val]


class AArch32(Arch):
    def __init__(self):
        super(AArch32, self).__init__("aarch32.json")

    def decode_mcr_mrc(self, insn):
        cp = insn.ops[0].specflag1
        op1 = insn.ops[0].value
        rt = insn.ops[1].reg
        crn = insn.ops[1].specflag1
        crm = insn.ops[1].specflag2
        op2 = insn.ops[2].value

        ops = [cp, op1, crn, crm, op2]
        gp_reg = ida_idp.ph.regnames[rt]
        cp_reg = self.find_reg_enc("MCR|MRC", ops)
        return cp_reg, gp_reg

    def output(self, outctx):
        insn = outctx.insn
        mne = ida_ua.print_insn_mnem(insn.ea)

        if insn.itype in [ida_allins.ARM_mcr, ida_allins.ARM_mrc]:
            cp_reg, gp_reg = self.decode_mcr_mrc(insn)
            if cp_reg:
                if insn.itype == ida_allins.ARM_mcr:
                    return Arch.output_insn(outctx, mne, cp_reg, gp_reg)
                else:
                    return Arch.output_insn(outctx, mne, gp_reg, cp_reg)

        if insn.itype in [ida_allins.ARM_mcrr, ida_allins.ARM_mrrc]:
            cp = insn.ops[0].specflag1
            op3 = insn.ops[0].value
            rt = insn.ops[1].reg
            rt2 = insn.ops[1].specflag1
            crm = insn.ops[1].specflag2

            ops = [cp, op3, crm]
            gp_reg = "%s%s%s:%s%s%s" % (
                ida_idp.ph.regnames[rt2],
                ida_lines.SCOLOR_OFF,
                ida_lines.SCOLOR_REG,
                ida_lines.SCOLOR_ON,
                ida_lines.SCOLOR_REG,
                ida_idp.ph.regnames[rt],
            )
            cp_reg = self.find_reg_enc("MCRR|MRRC", ops)
            if cp_reg:
                if insn.itype == ida_allins.ARM_mcrr:
                    return Arch.output_insn(outctx, mne, cp_reg, gp_reg)
                else:
                    return Arch.output_insn(outctx, mne, gp_reg, cp_reg)

        return False


class AArch64(Arch):
    def __init__(self):
        super(AArch64, self).__init__("aarch64.json")

    def decode_msr_mrs(self, insn):
        x = ida_bytes.get_wide_dword(insn.ea)
        op0 = 2 + ((x >> 19) & 1)
        if insn.itype == ida_allins.ARM_msr:
            i, xt = 0, insn.ops[4].reg
        else:
            xt, i = insn.ops[0].reg, 1
        op1 = insn.ops[i].value
        crn = insn.ops[i + 1].reg
        crm = insn.ops[i + 2].reg
        op2 = insn.ops[i + 3].value

        ops = [op0, op1, crn, crm, op2]
        gp_reg = ida_idp.ph.regnames[xt]
        cp_reg = self.find_reg_enc("MSR|MRS", ops)
        return cp_reg, gp_reg

    def output(self, outctx):
        insn = outctx.insn
        mne = ida_ua.print_insn_mnem(insn.ea)

        if insn.itype in [ida_allins.ARM_msr, ida_allins.ARM_mrs]:
            if insn.ops[2].type > 0:
                cp_reg, gp_reg = self.decode_msr_mrs(insn)
                if cp_reg:
                    if insn.itype == ida_allins.ARM_msr:
                        return Arch.output_insn(outctx, mne, cp_reg, gp_reg)
                    else:
                        return Arch.output_insn(outctx, mne, gp_reg, cp_reg)

            else:
                fields = {5: "SPSel", 6: "DAIFSet", 7: "DAIFClr"}
                pstatefield = fields.get(insn.ops[0].value, None)
                if pstatefield:
                    outctx.out_custom_mnem(mne.upper(), 16)
                    outctx.out_register(pstatefield)
                    outctx.out_printf(", ")
                    imm = ida_ua.print_operand(insn.ea, 1)
                    outctx.out_printf(imm)
                    outctx.flush_outbuf()
                    return True

        if insn.itype == ida_allins.ARM_sys:
            op1 = insn.ops[0].value
            crn = insn.ops[1].reg
            crm = insn.ops[2].reg
            op2 = insn.ops[3].value
            xt = insn.ops[4].reg

            ops = [1, op1, crn, crm, op2]
            gp_reg = ida_idp.ph.regnames[xt]
            cp_reg = self.find_reg_enc("SYS", ops)
            if cp_reg:
                mne, op = cp_reg.split()
                if xt == 160:
                    return Arch.output_insn(outctx, mne, op)
                else:
                    return Arch.output_insn(outctx, mne, op, gp_reg)

        return False


class AMIE(ida_idaapi.plugin_t, ida_idp.IDP_Hooks, ida_kernwin.UI_Hooks):
    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_DRAW
    comment = "A Minimalist Instruction Extender"
    help = ""
    wanted_name = "AMIE"
    wanted_hotkey = ""
    version = "0.8.6"

    @staticmethod
    def extract_item(viewer, stripped=False):
        cnt = ida_kernwin.get_custom_viewer_place(viewer, True)[1]
        line = ida_kernwin.get_custom_viewer_curline(viewer, True)

        tags = [ida_lines.SCOLOR_ON, ida_lines.SCOLOR_OFF]
        expr = re.compile("[A-Z0-9_]")

        def find_pos(line, pos, inc):
            while 0 <= pos < len(line):
                if not stripped and line[pos] in tags:
                    break
                if stripped and not expr.match(line[pos]):
                    break
                pos += inc
            return pos

        pos = ida_lines.tag_advance(line, cnt)
        if pos < 0 or pos >= len(line):
            return
        while line[pos] in [ida_lines.SCOLOR_ON, ida_lines.SCOLOR_OFF]:
            pos += 2
            if pos < 0 or pos >= len(line):
                return

        prev_pos, next_pos = find_pos(line, pos, -1), find_pos(line, pos, +1)
        if stripped:
            return None, line[prev_pos + 1:next_pos].strip()
        return line[prev_pos + 1], line[prev_pos + 2:next_pos].strip()

    @staticmethod
    def format_hint(title, content):
        def tag_append(s, t):
            return ida_lines.SCOLOR_ON + t + s + ida_lines.SCOLOR_OFF + t

        text = " " + "\n ".join([tag_append(line, ida_lines.SCOLOR_LOCNAME)
                                 for line in title.split("\n")])
        if content:
            text += "\n"
            for line in content.split("\n"):
                text += "\n " + tag_append(line, ida_lines.SCOLOR_AUTOCMT)
        return text, len(text.split("\n"))

    def __init__(self):
        ida_idp.IDP_Hooks.__init__(self)
        ida_kernwin.UI_Hooks.__init__(self)
        self.hexrays_support = False

    def init(self):
        if idaapi.ph_get_id() != idaapi.PLFM_ARM:
            return ida_idaapi.PLUGIN_SKIP

        ida_kernwin.UI_Hooks.hook(self)
        ida_idp.IDP_Hooks.hook(self)
        print("[AMIE] Plugin v%s initialized" % AMIE.version)
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        ida_idp.IDP_Hooks.unhook(self)
        ida_kernwin.UI_Hooks.unhook(self)
        if self.hexrays_support:
            ida_hexrays.remove_hexrays_callback(self.hxe_callback)
            ida_hexrays.term_hexrays_plugin()
        print("[AMIE] Plugin v%s terminated" % AMIE.version)

    def run(self, _):
        return False

    def database_inited(self, *_):
        if ida_ida.inf_is_64bit():
            print("[AMIE] Using AArch64 architecture")
            self.arch = AArch64()
        else:
            print("[AMIE] Using AArch32 architecture")
            self.arch = AArch32()

    def plugin_loaded(self, plugin_info):
        if plugin_info.name == "Hex-Rays Decompiler":
            if ida_hexrays.init_hexrays_plugin():
                self.hexrays_support = True
                ida_hexrays.install_hexrays_callback(self.hxe_callback)
                print("[AMIE] Hex-Rays decompiler is supported")

    def ev_out_insn(self, outctx):
        return self.arch.output(outctx)

    def get_custom_viewer_hint(self, viewer, place):
        widget_type = ida_kernwin.get_widget_type(viewer)
        if widget_type != ida_kernwin.BWN_DISASM:
            return

        flags = ida_bytes.get_flags(place.toea()) if place else 0
        if not ida_bytes.is_code(flags):
            return

        item = AMIE.extract_item(viewer)
        if not item:
            return
        tag, val = item

        hint = self.arch.hint(place.toea(), tag, val)
        if not hint:
            return

        return AMIE.format_hint(*hint)

    def hxe_callback(self, event, *args):
        if event == ida_hexrays.hxe_maturity:
            cfunc, new_maturity = args
            if new_maturity != ida_hexrays.CMAT_FINAL:
                return 0
            plugin = self

            class Visitor(ida_hexrays.ctree_visitor_t):
                def visit_expr(self, e):
                    if not e.x or e.x.op != ida_hexrays.cot_helper:
                        return 0

                    insn = ida_ua.insn_t()
                    ida_ua.decode_insn(insn, e.ea)

                    def make_reg(cp_reg):
                        reg = ida_hexrays.carg_t()
                        reg.op = ida_hexrays.cot_helper
                        reg.helper = cp_reg
                        reg.exflags = ida_hexrays.EXFL_ALONE
                        return reg

                    if e.x.helper in ["__mcr", "__mrc"]:
                        cp_reg = plugin.arch.decode_mcr_mrc(insn)[0]
                        if cp_reg:
                            if e.x.helper == "__mcr":
                                e.x.helper = "_WriteStatusReg"
                                val = ida_hexrays.carg_t()
                                e.a[2].swap(val)
                                e.a.clear()
                                e.a.push_back(make_reg(cp_reg))
                                e.a.push_back(val)

                            else:
                                e.x.helper = "_ReadStatusReg"
                                e.a.clear()
                                e.a.push_back(make_reg(cp_reg))

                    elif e.x.helper == "ARM64_SYSREG":
                        cp_reg = plugin.arch.decode_msr_mrs(insn)[0]
                        if cp_reg:
                            e.replace_by(make_reg(cp_reg))

                    return 0

            visitor = Visitor(ida_hexrays.CV_PARENTS)
            visitor.apply_to_exprs(cfunc.body, None)

        elif event == ida_hexrays.hxe_create_hint:
            hint = None

            e = args[0].item.e
            if e and e.op == ida_hexrays.cot_helper:
                hint = self.arch.hint(e.ea, ida_lines.SCOLOR_REG, e.helper)

            elif e and e.op == ida_hexrays.cit_asm:
                item = AMIE.extract_item(args[0].ct, True)
                if item and item[1]:
                    if item[1] in self.arch.regs:
                        tag = ida_lines.SCOLOR_REG
                    else:
                        insn = ida_ua.insn_t()
                        ida_ua.decode_insn(insn, e.ea)
                        if item[1].startswith(insn.get_canon_mnem()):
                            tag = ida_lines.SCOLOR_INSN
                        else:
                            tag = ida_lines.SCOLOR_KEYWORD
                    hint = self.arch.hint(e.ea, tag, item[1])

            if hint:
                return (1,) + AMIE.format_hint(*hint)

        return 0


def PLUGIN_ENTRY():
    return AMIE()
