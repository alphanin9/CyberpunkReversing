import ida_allins
import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import ida_ua

import idaapi
import idautils
import idc

CLASS_CTOR_ADDR = ida_name.get_name_ea(idc.BADADDR, "CClass::Ctor")

RTTI_CONSTRUCT_CLS_VTABLE_OFFSET = 0xd8
RTTI_DESTRUCT_CLS_VTABLE_OFFSET = 0xe0
RTTI_ASSIGN_CLS_VTABLE_OFFSET = 0x50

print("CClass ctor @", hex(CLASS_CTOR_ADDR))

class_ctor_calls = idautils.CodeRefsTo(CLASS_CTOR_ADDR, 1)

string_map = {}

string_obj = idautils.Strings()
string_obj.setup(minlen=2, display_only_existing_strings=False)

for string in string_obj:
    string_map[string.ea] = str(string)

rdata = ida_segment.get_segm_by_name(".rdata")
pdata = ida_segment.get_segm_by_name(".pdata")

def rtti_func_xrefs_are_ok(func_ea):
    has_rdata_xref = False

    for xref in idautils.DataRefsTo(func_ea):
        seg_ptr = ida_segment.getseg(xref)
        if not seg_ptr:
            continue
        if seg_ptr.name == pdata.name:
            # fix: exception stuff causing things to meltdown
            continue
        elif seg_ptr.name == rdata.name:
            if has_rdata_xref:
                return False
            has_rdata_xref = True
    
    return True

assigned_names = set()

def cleanup_old_name(name):
    addr = ida_name.get_name_ea(idaapi.BADADDR, name)
    if addr != idaapi.BADADDR:
        ida_name.del_global_name(addr)

def process_ctor_call(call_ea):
    func = ida_funcs.get_func(call)
    if not func:
        return False
    
    class_rtti_typename = ""

    for block in idaapi.FlowChart(func):
        if block.start_ea <= call and block.end_ea >= call:
            first_inst_addr = next(idautils.Heads(block.start_ea, block.end_ea))
            if not first_inst_addr:
                return False
            # Should always be sth like lea rdx, addr_of_classname
            first_inst = idautils.DecodeInstruction(first_inst_addr)

            if not first_inst:
                return False
            
            first_op = first_inst.ops[0]
            second_op = first_inst.ops[1]

            if first_inst.itype == ida_allins.NN_lea and first_op == idautils.procregs.rdx and second_op.type == ida_ua.o_mem and second_op.addr in string_map:
                class_rtti_typename = string_map[second_op.addr]
            else:
                return False

            # We don't care about call instruction too much, it does not matter
            call_inst = idautils.DecodeInstruction(call_ea)

            if not call_inst:
                return False

            load_vtable_inst = idautils.DecodeInstruction(call_ea + call_inst.size)

            # lea rax, vtable_addr

            if not load_vtable_inst:
                return False
            
            # Is our VFT assignment good?
            if load_vtable_inst.itype == ida_allins.NN_lea and load_vtable_inst.ops[0] == idautils.procregs.rax and load_vtable_inst.ops[1].type == ida_ua.o_mem:
                vtable_addr = load_vtable_inst.ops[1].addr

                xref_count = list(idautils.DataRefsTo(vtable_addr))

                if len(xref_count) > 1:
                    break
                
                assigned_vtable_name = class_rtti_typename + "::RTTI::vtbl"

                has_name = not (assigned_vtable_name in assigned_names)
                
                if not has_name:
                    # Bring name to more or less spec, no point making more namespaces here I think
                    cleanup_old_name(assigned_vtable_name)
                    ida_name.set_name(vtable_addr, assigned_vtable_name)
                    assigned_names.add(assigned_vtable_name)

                construct_class = ida_bytes.get_qword(vtable_addr + RTTI_CONSTRUCT_CLS_VTABLE_OFFSET)
                destruct_class = ida_bytes.get_qword(vtable_addr + RTTI_DESTRUCT_CLS_VTABLE_OFFSET)
                assign_class = ida_bytes.get_qword(vtable_addr + RTTI_ASSIGN_CLS_VTABLE_OFFSET)

                # Most important things

                assigned_ctor_name = class_rtti_typename + "::ConstructCls"
                assigned_dtor_name = class_rtti_typename + "::DestructCls"
                assigned_copy_name = class_rtti_typename + "::Assign"

                if ida_funcs.get_func(construct_class) and not (assigned_ctor_name in assigned_names) and rtti_func_xrefs_are_ok(construct_class):
                    cleanup_old_name(assigned_ctor_name)
                    ida_name.set_name(construct_class, assigned_ctor_name)
                    assigned_names.add(assigned_ctor_name)

                if ida_funcs.get_func(destruct_class) and not (assigned_dtor_name in assigned_names) and rtti_func_xrefs_are_ok(destruct_class):
                    cleanup_old_name(assigned_dtor_name)
                    ida_name.set_name(destruct_class, assigned_dtor_name)
                    assigned_names.add(assigned_dtor_name)

                if ida_funcs.get_func(assign_class) and not (assigned_copy_name in assigned_names) and rtti_func_xrefs_are_ok(assign_class):
                    cleanup_old_name(assigned_copy_name)
                    ida_name.set_name(assign_class, assigned_copy_name)
                    assigned_names.add(assigned_copy_name)
            break

    # mov qword_something, reg...
    # Then said sth in data gets xrefd to
    # mov rax, qword_something...
    # retn
    # Which in turn should have (maybe multiple!) xrefs in a VFT

    # ida_allins.NN_mov
    # .ops[0].dtype == ida_allins.dt_qword
    # .ops[0].type == ida_ua.o_mem
    # .ops[1].type == ida_ua.o_reg
    
    for insn_addr in idautils.Heads(func.start_ea, func.end_ea):
        insn = idautils.DecodeInstruction(insn_addr)
        if insn and insn.itype == ida_allins.NN_mov and insn.ops[0].type == ida_ua.o_mem and insn.ops[0].dtype == ida_ua.dt_qword and insn.ops[1].type == ida_ua.o_reg:
            # (preliminary) found something matching (not really, it triggers on more stuff), but check xrefs!!!!1111
            for xref in idautils.DataRefsTo(insn.ops[0].addr):
                first_insn = idautils.DecodeInstruction(xref)
                if not first_insn or first_insn.itype != ida_allins.NN_mov or first_insn.ops[0].type != ida_ua.o_reg or first_insn.ops[0] != idautils.procregs.rax or first_insn.ops[1].addr != insn.ops[0].addr:
                    continue

                second_insn = idautils.DecodeInstruction(xref + first_insn.size)
                if not second_insn or second_insn.itype != ida_allins.NN_retn:
                    continue
                
                get_type_func_name = class_rtti_typename + "::GetType"

                if not (get_type_func_name in assigned_names):
                    cleanup_old_name(get_type_func_name)
                    ida_name.set_name(xref, get_type_func_name)
                    assigned_names.add(get_type_func_name)    

                for func_xref in idautils.DataRefsTo(xref):
                    if ida_name.get_name(func_xref).startswith("off_"):
                        cleanup_old_name(class_rtti_typename + "::vtbl")
                        # More hacky vtable getters!
                        ida_name.set_name(func_xref, class_rtti_typename + "::vtbl")
                
                # Rename type object as well, forgot to add that in first ver lol
                if ida_name.get_name(insn.ops[0].addr).startswith("qword_"):
                    cleanup_old_name(class_rtti_typename + "::RTTI")
                    ida_name.set_name(insn.ops[0].addr, class_rtti_typename + "::RTTI")

                return True    
    return True

call_count = 0
successful_resolves = 0

fail_sites = []

for call in class_ctor_calls:
    call_count += 1
    if process_ctor_call(call):
        successful_resolves += 1
    else:
        fail_sites.append(f"RTTI vtable finder failed on: {call:x}")

print(f"Call count: {call_count}, resolves: {successful_resolves}")
for fail_site in fail_sites:
    # Currently 2 known fail points, one on some scene-related type and one on something that looks script-y and not constructor-y
    print(fail_site)


            

            