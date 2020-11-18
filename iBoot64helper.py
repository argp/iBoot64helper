__author__ = "argp@CENSUS-labs.com"

import idautils
import idaapi
import ida_idaapi
import ida_search
import ida_funcs
import ida_segment
import ida_bytes
import ida_idp
import ida_pro
import ida_auto
import idc
import struct

true = True
false = False
none = None

kp_flag = false
br_flag = false

try:
    import keypatch
    kp_flag = true
except:
    pass

prologues = ["7F 23 03 D5", "BD A9", "BF A9"]

def find_panic(base_ea):
    pk_ea = ida_search.find_text(base_ea, 1, 1, "double panic in ", ida_search.SEARCH_DOWN)

    if pk_ea != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(pk_ea):
            func = idaapi.get_func(xref.frm)
            print("\t[+] _panic = 0x%x" % (func.start_ea))
            idc.set_name(func.start_ea, "_panic", idc.SN_CHECK)
            return func.start_ea

    print("\t[-] _panic = not found")
    return ida_idaapi.BADADDR

def find_chipid_get_chip_revision(base_ea, base_end_ea):
    seq_ea = ida_search.find_binary(base_ea, base_end_ea, "00 21 06 33", 16, ida_search.SEARCH_DOWN)

    if seq_ea != ida_idaapi.BADADDR:
        func = idaapi.get_func(seq_ea)
        print("\t[+] _chipid_get_chip_revision = 0x%x" % (func.start_ea))
        idc.set_name(func.start_ea, "_chipid_get_chip_revision", idc.SN_CHECK)
        return func.start_ea

    print("\t[-] _chipid_get_chip_revision = not found")
    return ida_idaapi.BADADDR

def find_platform_early_init(base_ea, base_end_ea):
    seq_ea = ida_search.find_binary(base_ea, base_end_ea, "60 02 40 39", 16, ida_search.SEARCH_DOWN)

    if seq_ea != ida_idaapi.BADADDR:
        func = idaapi.get_func(seq_ea)
        print("\t[+] _platform_early_init = 0x%x" % (func.start_ea))
        idc.set_name(func.start_ea, "_platform_early_init", idc.SN_CHECK)
        return func.start_ea

    print("\t[-] _platform_early_init = not found")
    return ida_idaapi.BADADDR

def find_image4_validate_property_callback(base_ea, base_end_ea, ptr_ea):
    seq_ea = ida_search.find_binary(base_ea, base_end_ea, "?? 77 00 51", 16, ida_search.SEARCH_DOWN)
    func = none

    if seq_ea != ida_idaapi.BADADDR:
        func = idaapi.get_func(seq_ea)
    else:
        for xref in idautils.XrefsTo(ptr_ea):
            func = idaapi.get_func(xref.frm)
            break

    if func:
        print("\t[+] _image4_validate_property_callback = 0x%x" % (func.start_ea))
        idc.set_name(func.start_ea, "_image4_validate_property_callback", idc.SN_CHECK)
        return func.start_ea
        
    print("\t[-] _image4_validate_property_callback = not found")
    return ida_idaapi.BADADDR

def find_image4_load(ea):
    ea_list = list(idautils.XrefsTo(ea))

    if ea_list[0].frm != ida_idaapi.BADADDR:
        func_ea = ida_funcs.get_func(ea_list[0].frm).start_ea
        print("\t[+] _image4_load = 0x%x" % (func_ea))
        idc.set_name(func_ea, "_image4_load", idc.SN_CHECK)
        return func_ea

    print("\t[-] _image4_load = not found")
    return ida_idaapi.BADADDR

def find_image4_validate_property_callback_interposer(base_ea):
    ea_list = ida_search.find_imm(base_ea, ida_search.SEARCH_DOWN, 0x424E)

    if ea_list[0] == ida_idaapi.BADADDR:
        ea_list = ida_search.find_imm(base_ea, ida_search.SEARCH_DOWN, 0x424E0000)

    if ea_list[0] != ida_idaapi.BADADDR:
        func_ea = ida_funcs.get_func(ea_list[0]).start_ea
        print("\t[+] _image4_validate_property_callback_interposer = 0x%x" % (func_ea))
        idc.set_name(func_ea, "_image4_validate_property_callback_interposer", idc.SN_CHECK)
        return func_ea

    print("\t[-] _image4_validate_property_callback_interposer = not found")
    return ida_idaapi.BADADDR

def find_image4_validate_property_callback_interposer_ptr(ea):
    ea_list = list(idautils.XrefsTo(ea))
    ptr_ea = ida_idaapi.BADADDR

    if len(ea_list) > 0:
        ptr_ea = ea_list[0].frm
        insn = idc.print_insn_mnem(ptr_ea)

        if not insn:
            print("\t[+] _image4_validate_property_callback_interposer_ptr = 0x%x" % (ptr_ea))
            idc.set_name(ptr_ea, "_image4_validate_property_callback_interposer_ptr", idc.SN_CHECK)
        else:
            ptr_ea = ida_idaapi.BADADDR
        
        if ptr_ea != ida_idaapi.BADADDR:
            ptr_ea_list = list(idautils.XrefsTo(ptr_ea))

            if len(ptr_ea_list) > 0:
                i4_hash_ptr_ea = ptr_ea_list[0].frm + 8

                src = idc.print_operand(i4_hash_ptr_ea, 1)
                i4_hash_ptr_ea = idc.get_name_ea_simple(src)
                print("\t[+] _image4_hash_init_ptr = 0x%x" % (i4_hash_ptr_ea))
                idc.set_name(i4_hash_ptr_ea, "_image4_hash_init_ptr", idc.SN_CHECK)

                bl_ea = ptr_ea_list[0].frm + 8 + 16
                dst = idc.print_operand(bl_ea, 0)
                i4d_ea = idc.get_name_ea_simple(dst)
                print("\t[+] _Img4DecodePerformTrustEvaluation = 0x%x" % (i4d_ea))
                idc.set_name(i4d_ea, "_Img4DecodePerformTrustEvaluation", idc.SN_CHECK)

                return ptr_ea

    if ptr_ea == ida_idaapi.BADADDR:
        print("\t[-] _image4_validate_property_callback_interposer_ptr = not found")

    print("\t[-] _image4_hash_init_ptr = not found")
    print("\t[-] _Img4DecodePerformTrustEvaluation = not found")
    return ida_idaapi.BADADDR

def find_img4decodeinit(base_ea):
    cur_ea = base_ea

    while true:
        ea_list = ida_search.find_imm(cur_ea, ida_search.SEARCH_DOWN, 0x494D)

        if ea_list[0] == ida_idaapi.BADADDR:
            ea_list = ida_search.find_imm(cur_ea, ida_search.SEARCH_DOWN, 0x494D0000)

        if ea_list[0] != ida_idaapi.BADADDR:
            ea = ea_list[0]
            func = ida_funcs.get_func(ea)
            func_ea = 0

            if not func:
                func_ea = ida_search.find_binary(ea, base_ea, "?? ?? BD A9", 16, ida_search.SEARCH_UP)

                if func_ea != ida_idaapi.BADADDR:
                    ida_funcs.add_func(func_ea)
                else:
                    print("\t[-] _Img4DecodeInit = not found")
                    return ida_idaapi.BADADDR
            else:
                func_ea = func.start_ea

            ea_func_list = list(idautils.XrefsTo(func_ea))
            
            if not ea_func_list:
                cur_ea = ea + 4
                continue

            if ea_func_list[0].frm != ida_idaapi.BADADDR:
                try:
                    i4d_ea = ida_funcs.get_func(ea_func_list[0].frm).start_ea
                    print("\t[+] _Img4DecodeInit = 0x%x" % (i4d_ea))
                    idc.set_name(i4d_ea, "_Img4DecodeInit", idc.SN_CHECK)
                    return i4d_ea
                except:
                    break

        cur_ea = ea + 4

    print("\t[-] _Img4DecodeInit = not found")
    return ida_idaapi.BADADDR

def find_target_early_init(base_ea):
    ea_list = ida_search.find_imm(base_ea, ida_search.SEARCH_DOWN, 0x4A41)

    if ea_list[0] != ida_idaapi.BADADDR:
        try:
            func_ea = ida_funcs.get_func(ea_list[0]).start_ea
        except:
            print("\t[-] _target_early_init = not found")
            return ida_idaapi.BADADDR

        print("\t[+] _target_early_init = 0x%x" % (func_ea))
        idc.set_name(func_ea, "_target_early_init", idc.SN_CHECK)
        tei_ea = func_ea

        str_ea = ida_search.find_text(tei_ea, 1, 1, "All pre", ida_search.SEARCH_DOWN)

        if str_ea != ida_idaapi.BADADDR:
            f_ea = idaapi.get_func(str_ea).start_ea

            if tei_ea != f_ea:
                print("\t[-] _platform_not_supported = not found")
                return tei_ea

            bl_ea = str_ea + 8
            dst = idc.print_operand(bl_ea, 0)
            pns_ea = idc.get_name_ea_simple(dst)
            print("\t[+] _platform_not_supported = 0x%x" % (pns_ea))
            idc.set_name(pns_ea, "_platform_not_supported", idc.SN_CHECK)
            return tei_ea

    print("\t[-] _target_early_init = not found")
    return ida_idaapi.BADADDR

def find_aes_crypto_cmd(base_ea, base_end_ea):
    aes_ea = ida_search.find_binary(base_ea, base_end_ea, "89 2C 00 72", 16, ida_search.SEARCH_DOWN)

    if aes_ea != ida_idaapi.BADADDR:
        func = idaapi.get_func(aes_ea)
        print("\t[+] _aes_crypto_cmd = 0x%x" % (func.start_ea))
        idc.set_name(func.start_ea, "_aes_crypto_cmd", idc.SN_CHECK)
        return func.start_ea

    print("\t[-] _aes_crypto_cmd = not found")
    return ida_idaapi.BADADDR

def find_main_task(base_ea):
    du_ea = ida_search.find_text(base_ea, 1, 1, "debug-uarts", ida_search.SEARCH_DOWN)

    if du_ea != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(du_ea):
            func = idaapi.get_func(xref.frm)
            mt_ea = 0

            if not func:
                mt_ea = ida_search.find_binary(xref.frm, base_ea, prologues[0], 16, ida_search.SEARCH_UP)

                if mt_ea == ida_idaapi.BADADDR:
                    mt_ea = ida_search.find_binary(xref.frm, base_ea, "FF ?? ?? D1", 16, ida_search.SEARCH_UP)
            else:
                mt_ea = func.start_ea

            print("\t[+] _main_task = 0x%x" % (mt_ea))
            idc.set_name(mt_ea, "_main_task", idc.SN_CHECK)
            return mt_ea

    print("\t[-] _main_task = not found")
    return ida_idaapi.BADADDR

def find_boot_check_panic(base_ea, base_end_ea):
    seq_ea = ida_search.find_binary(base_ea, base_end_ea, "1F ?? 03 71", 16, ida_search.SEARCH_DOWN)

    if seq_ea != ida_idaapi.BADADDR:
        func = idaapi.get_func(seq_ea)
        print("\t[+] _boot_check_panic = 0x%x" % (func.start_ea))
        idc.set_name(func.start_ea, "_boot_check_panic", idc.SN_CHECK)
        return func.start_ea

    print("\t[-] _boot_check_panic = not found")
    return ida_idaapi.BADADDR

def find_update_device_tree(base_ea):
    udt_ea = ida_search.find_text(base_ea, 1, 1, "development-cert", ida_search.SEARCH_DOWN)

    if udt_ea != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(udt_ea):
            func = idaapi.get_func(xref.frm)
            print("\t[+] _UpdateDeviceTree = 0x%x" % (func.start_ea))
            idc.set_name(func.start_ea, "_UpdateDeviceTree", idc.SN_CHECK)
            return func.start_ea

    print("\t[-] _UpdateDeviceTree = not found")
    return ida_idaapi.BADADDR

def find_record_memory_range(base_ea):
    rmr_ea = ida_search.find_text(base_ea, 1, 1, "chosen/memory-map", ida_search.SEARCH_DOWN)

    if rmr_ea != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(rmr_ea):
            func = idaapi.get_func(xref.frm)
            print("\t[+] _record_memory_range = 0x%x" % (func.start_ea))
            idc.set_name(func.start_ea, "_record_memory_range", idc.SN_CHECK)
            return func.start_ea

    print("\t[-] _record_memory_range = not found")
    return ida_idaapi.BADADDR

def find_macho_valid(base_ea, base_end_ea):
    seq_ea = ida_search.find_binary(base_ea, base_end_ea, "0B 70 00 91", 16, ida_search.SEARCH_DOWN)

    if seq_ea != ida_idaapi.BADADDR:
        func = idaapi.get_func(seq_ea)
        print("\t[+] _macho_valid = 0x%x" % (func.start_ea))
        idc.set_name(func.start_ea, "_macho_valid", idc.SN_CHECK)
        return func.start_ea

    print("\t[-] _macho_valid = not found")
    return ida_idaapi.BADADDR

def find_stack_chk_fail(base_ea):
    ea_list = ida_search.find_imm(base_ea, ida_search.SEARCH_DOWN, 0x7CC8)
    func = ida_funcs.get_func(ea_list[0])

    if (ea_list[0] != ida_idaapi.BADADDR) and func:
        func_ea = func.start_ea
        print("\t[+] _stack_chk_fail = 0x%x" % (func_ea))
        idc.set_name(func_ea, "_stack_chk_fail", idc.SN_CHECK)
        return func_ea
    else:
        str_ea = ida_search.find_text(base_ea, 1, 1, "__stack_chk_fail", ida_search.SEARCH_DOWN)

        if str_ea != ida_idaapi.BADADDR:
            for xref in idautils.XrefsTo(str_ea):
                func = idaapi.get_func(xref.frm)
                print("\t[+] _stack_chk_fail = 0x%x" % (func.start_ea))
                idc.set_name(func.start_ea, "_stack_chk_fail", idc.SN_CHECK)
                return func.start_ea

    print("\t[-] _stack_chk_fail = not found")
    return ida_idaapi.BADADDR

def find_platform_init_display(base_ea):
    str_ea = idc.get_name_ea_simple("aBacklightLevel")

    if str_ea != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(str_ea):
            func = idaapi.get_func(xref.frm)
            print("\t[+] _platform_init_display = 0x%x" % (func.start_ea))
            idc.set_name(func.start_ea, "_platform_init_display", idc.SN_CHECK)

            egu_ea = find_env_get_uint(xref.frm)

            if egu_ea != ida_idaapi.BADADDR:
                ege_ea = find_env_get_etc(egu_ea)

            return func.start_ea

    print("\t[-] _platform_init_display = not found")
    return ida_idaapi.BADADDR

def find_env_get_uint(ea):
    bl_ea = ea + 12
    dst = idc.print_operand(bl_ea, 0)
    egu_ea = idc.get_name_ea_simple(dst)

    if egu_ea != ida_idaapi.BADADDR:
        print("\t[+] _env_get_uint = 0x%x" % (egu_ea))
        idc.set_name(egu_ea, "_env_get_uint", idc.SN_CHECK)
        return egu_ea

    print("\t[-] _env_get_uint = not found")
    return ida_idaapi.BADADDR

def find_env_get_etc(ea):
    cur_ea = ea + 4

    while true:
        insn = idc.print_insn_mnem(cur_ea)
        
        if insn == "BL":
            dst = idc.print_operand(cur_ea, 0)
            ege_ea = idc.get_name_ea_simple(dst)
            print("\t[+] _env_get_etc = 0x%x" % (ege_ea))
            idc.set_name(ege_ea, "_env_get_etc", idc.SN_CHECK)
            return ege_ea

        if cur_ea > ea + (4 * 20):
            break

        cur_ea = cur_ea + 4

    print("\t[-] _env_get_etc = not found")
    return ida_idaapi.BADADDR

def find_loaded_kernelcache(ea):
    ea_list = list(idautils.XrefsTo(ea))

    if ea_list[0].frm != ida_idaapi.BADADDR:
        func_ea = ida_funcs.get_func(ea_list[0].frm).start_ea
        print("\t[+] _loaded_kernelcache = 0x%x" % (func_ea))
        idc.set_name(func_ea, "_loaded_kernelcache", idc.SN_CHECK)
        return func_ea

    print("\t[-] _loaded_kernelcache = not found")
    return ida_idaapi.BADADDR

def find_load_kernelcache(ea):
    ea_list = list(idautils.XrefsTo(ea))
    func_ea = 0
    
    if len(ea_list) >= 1:
        if ea_list[0].frm != ida_idaapi.BADADDR:
            func = ida_funcs.get_func(ea_list[0].frm)

            if func != none:
                func_ea = func.start_ea
                print("\t[+] _load_kernelcache = 0x%x" % (func_ea))
                idc.set_name(func_ea, "_load_kernelcache", idc.SN_CHECK)
                return func_ea

    print("\t[-] _load_kernelcache = not found")
    return ida_idaapi.BADADDR

def find_load_kernelcache_object(base, ea):
    if ea != ida_idaapi.BADADDR:
        ea_list = list(idautils.XrefsTo(ea))

        if ea_list[0].frm != ida_idaapi.BADADDR:
            func_ea = ida_funcs.get_func(ea_list[0].frm).start_ea
            print("\t[+] _load_kernelcache_object = 0x%x" % (func_ea))
            idc.set_name(func_ea, "_load_kernelcache_object", idc.SN_CHECK)
            return func_ea

        print("\t[-] _load_kernelcache_object = not found")
        return ida_idaapi.BADADDR
    else:
        str_ea = ida_search.find_text(base, 1, 1, "Kernelcache too large", ida_search.SEARCH_DOWN)

        if str_ea != ida_idaapi.BADADDR:
            for xref in idautils.XrefsTo(str_ea):
                func = idaapi.get_func(xref.frm)
                print("\t[+] _load_kernelcache_object = 0x%x" % (func.start_ea))
                idc.set_name(func.start_ea, "_load_kernelcache_object", idc.SN_CHECK)
                return func.start_ea

    print("\t[-] _load_kernelcache_object = not found")
    return ida_idaapi.BADADDR

def find_do_go(base_ea):
    str_ea = idc.get_name_ea_simple("aCebilefciladrm")

    if str_ea != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(str_ea):
            # IDA messes up this function, so I find it this way:
            func = idaapi.get_func(xref.frm)
            dg_ea = 0

            if func != none:
                dg_ea = ida_search.find_binary(xref.frm, func.start_ea, prologues[0], 16, ida_search.SEARCH_UP)

                if dg_ea == ida_idaapi.BADADDR:
                    dg_ea = ida_search.find_binary(xref.frm, func.start_ea, "FF ?? ?? D1", 16, ida_search.SEARCH_UP)

            else:
                dg_ea = ida_search.find_binary(xref.frm, base_ea, "FF ?? ?? D1", 16, ida_search.SEARCH_UP)

            ida_funcs.add_func(dg_ea)
            print("\t[+] _do_go = 0x%x" % (dg_ea))
            idc.set_name(dg_ea, "_do_go", idc.SN_CHECK)
            return dg_ea

    print("\t[-] _do_go = not found")
    return ida_idaapi.BADADDR

def find_pmgr_binning_mode_get_value(base_ea):
    str_ea = ida_search.find_text(base_ea, 1, 1, "Invalid low", ida_search.SEARCH_DOWN)

    if str_ea != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(str_ea):
            func = idaapi.get_func(xref.frm)
            print("\t[+] _pmgr_binning_mode_get_value = 0x%x" % (func.start_ea))
            idc.set_name(func.start_ea, "_pmgr_binning_mode_get_value", idc.SN_CHECK)
            return func.start_ea

    print("\t[-] _pmgr_binning_mode_get_value = not found")
    return ida_idaapi.BADADDR

def find_do_printf(base_ea, base_end_ea):
    str_ea = ida_search.find_text(base_ea, 1, 1, "<ptr>", ida_search.SEARCH_DOWN)

    if str_ea != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(str_ea):
            func = idaapi.get_func(xref.frm)

            if not func:
                break

            print("\t[+] _do_printf = 0x%x" % (func.start_ea))
            idc.set_name(func.start_ea, "_do_printf", idc.SN_CHECK)
            return func.start_ea

    cmp_ea = ida_search.find_binary(base_ea, base_end_ea, "3F 94 00 71", 16, ida_search.SEARCH_DOWN)

    if cmp_ea != ida_idaapi.BADADDR:
        func = idaapi.get_func(cmp_ea)

        if not func:
            print("\t[-] _do_printf = not found")
            return ida_idaapi.BADADDR

        print("\t[+] _do_printf = 0x%x" % (func.start_ea))
        idc.set_name(func.start_ea, "_do_printf", idc.SN_CHECK)
        return func.start_ea

    print("\t[-] _do_printf = not found")
    return ida_idaapi.BADADDR

def find_image4_get_partial(base_ea):
    str_ea = idc.get_name_ea_simple("aImg4")

    if str_ea != ida_idaapi.BADADDR:
        aimg4_ea = list(idautils.XrefsTo(str_ea))[0].frm

        if aimg4_ea == ida_idaapi.BADADDR:
            return ida_idaapi.BADADDR

        func = idaapi.get_func(aimg4_ea)
        print("\t[+] _image4_get_partial = 0x%x" % (func.start_ea))
        idc.set_name(func.start_ea, "_image4_get_partial", idc.SN_CHECK)
        return func.start_ea

    print("\t[-] _image4_get_partial = not found")
    return ida_idaapi.BADADDR

def find_putchar(base_ea, base_end_ea):
    seq_ea = ida_search.find_binary(base_ea, base_end_ea, "A0 01 80 52 ?? ?? FF 97 E0", 16, ida_search.SEARCH_DOWN)

    if seq_ea != ida_idaapi.BADADDR:
        func = idaapi.get_func(seq_ea)
        print("\t[+] _putchar = 0x%x" % (func.start_ea))
        idc.set_name(func.start_ea, "_putchar", idc.SN_CHECK)
        return func.start_ea

    print("\t[-] _putchar = not found")
    return ida_idaapi.BADADDR

def find_macho_load(base_ea):
    pz_ea = idc.get_name_ea_simple("aPagezero")

    if pz_ea != ida_idaapi.BADADDR:
        if len(list(idautils.XrefsTo(pz_ea))) != 3:
            print("\t[-] _macho_load = not found")
            return ida_idaapi.BADADDR

        # in iBoot versions newer than 6603.x _macho_load seems inlined,
        # so the following heuristic isn't applicable
        func1_ea = idaapi.get_func(list(idautils.XrefsTo(pz_ea))[0].frm).start_ea
        func2_ea = idaapi.get_func(list(idautils.XrefsTo(pz_ea))[1].frm).start_ea
        func3_ea = idaapi.get_func(list(idautils.XrefsTo(pz_ea))[2].frm).start_ea

        if func2_ea != func3_ea:
            print("\t[-] _macho_load = not found")
            return ida_idaapi.BADADDR

        if func1_ea != func2_ea:
            print("\t[+] _macho_load = 0x%x" % (func2_ea))
            idc.set_name(func2_ea, "_macho_load", idc.SN_CHECK)
            return func2_ea

    print("\t[-] _macho_load = not found")
    return ida_idaapi.BADADDR

def find_interesting(base_ea, base_end):
    mv_ea = find_macho_valid(base_ea, base_end)

    if mv_ea != ida_idaapi.BADADDR:
        ldk_ea = find_loaded_kernelcache(mv_ea)

        if ldk_ea != ida_idaapi.BADADDR:
            lk_ea = find_load_kernelcache(ldk_ea)
        else:
            print("\t[-] _load_kernelcache = not found")
    else:
        print("\t[-] _loaded_kernelcache = not found")
        print("\t[-] _load_kernelcache = not found")
    
    pk_ea = find_panic(base_ea)
    go_ea = find_do_go(base_ea)
    pr_ea = find_do_printf(base_ea, base_end)

    i4i_ea = find_image4_validate_property_callback_interposer(base_ea)

    if i4i_ea != ida_idaapi.BADADDR:
        i4ip_ea = find_image4_validate_property_callback_interposer_ptr(i4i_ea)
        i4vc_ea = find_image4_validate_property_callback(base_ea, base_end, i4ip_ea)

        if i4vc_ea != ida_idaapi.BADADDR:
            i4l_ea = find_image4_load(i4vc_ea)
        else:
            print("\t[-] _image4_load = not found")

    else:
        print("\t[-] _image4_load = not found")
        print("\t[-] _image4_validate_property_callback = not found")
        print("\t[-] _image4_validate_property_callback_interposer_ptr = not found")

    rmr_ea = find_record_memory_range(base_ea)
    i4d_ea = find_img4decodeinit(base_ea)
    scf_ea = find_stack_chk_fail(base_ea)
    aes_ea = find_aes_crypto_cmd(base_ea, base_end)
    udt_ea = find_update_device_tree(base_ea)
    ml_ea = find_macho_load(base_ea)
    lko_ea = find_load_kernelcache_object(base_ea, ml_ea)
    pgv_ea = find_pmgr_binning_mode_get_value(base_ea)
    i4p_ea = find_image4_get_partial(base_ea)
    mt_ea = find_main_task(base_ea)
    tei_ea = find_target_early_init(base_ea)
    bc_ea = find_boot_check_panic(base_ea, base_end)
    pei_ea = find_platform_early_init(base_ea, base_end)
    crv_ea = find_chipid_get_chip_revision(base_ea, base_end)
    pid_ea = find_platform_init_display(base_ea)

    pc_ea = find_putchar(base_ea, base_end)
    
    # just to be sure
    if br_flag == false:
        if pc_ea != ida_idaapi.BADADDR and mv_ea == ida_idaapi.BADADDR:
            # this is a SecureROM image
            segm = ida_segment.getseg(base_ea)

            if segm:
                idaapi.set_segm_name(segm, "SecureROM", 0)
                print("[+] Identified as a SecureROM image")

def accept_file(fd, fname):
    global br_flag
    version = 0
    ret = 0

    if type(fname) == str:
        fd.seek(0x200)
        ver_bin = fd.read(0x30)

        try:
            ver_str = ver_bin.decode()
            ver_str = "%s" % (ver_str)
        except:
            return ret

        if ver_str[:9] == "SecureROM":
            ret = {"format" : "SecureROM (AArch64)", "processor" : "arm"}
            br_flag = true
            return ret

        fd.seek(0x280)
        ver_bin = fd.read(0x20)

        try:
            ver_str = ver_bin.decode()
            ver_str = "%s" % (ver_str)
        except:
            return ret

        if ver_str[:5] == "iBoot":
            version = ver_str[6:] # for later
            ret = {"format" : "iBoot (AArch64)", "processor" : "arm"}
            
    return ret

def load_file(fd, neflags, format):
    global prologues
    global br_flag
    size = 0
    base_addr = 0
    ea = 0
    nfunc = 0

    idaapi.set_processor_type("arm", ida_idp.SETPROC_LOADER_NON_FATAL)
    idaapi.get_inf_structure().lflags |= idaapi.LFLG_64BIT
    
    if (neflags & idaapi.NEF_RELOAD) != 0:
        return 1

    fd.seek(0, idaapi.SEEK_END)
    size = fd.tell()

    segm = idaapi.segment_t()
    segm.bitness = 2 # 64-bit
    segm.start_ea = 0
    segm.end_ea = size

    if br_flag == false:
        idaapi.add_segm_ex(segm, "iBoot", "CODE", idaapi.ADDSEG_OR_DIE)
    else:
        idaapi.add_segm_ex(segm, "SecureROM", "CODE", idaapi.ADDSEG_OR_DIE)

    fd.seek(0)
    fd.file2base(0, 0, size, false)

    idaapi.add_entry(0, 0, "start", 1)
    ida_funcs.add_func(ea)

    print("[+] Marked as code")

    # heuristic
    while(true):
        mnemonic = idc.print_insn_mnem(ea)
        
        if "LDR" in mnemonic:
            base_str = idc.print_operand(ea, 1)
            base_addr = int(base_str.split("=")[1], 16)
            
            break

        ea += 4

    print("[+] Rebasing to address 0x%x" % (base_addr))
    idaapi.rebase_program(base_addr, idc.MSF_NOFIX)

    segment_start = base_addr
    segment_end = idc.get_segm_attr(segment_start, idc.SEGATTR_END)

    ea = segment_start

    print("[+] Searching and defining functions")

    for prologue in prologues:
        while ea != ida_idaapi.BADADDR:
            ea = ida_search.find_binary(ea, segment_end, prologue, 16, ida_search.SEARCH_DOWN)
            
            if ea != ida_idaapi.BADADDR:
                if len(prologue) < 8:
                    ea = ea - 2

                if (ea % 4) == 0 and ida_bytes.get_full_flags(ea) < 0x200:
                    # print("[+] Defining a function at 0x%x" % (ea))
                    ida_funcs.add_func(ea)
                    nfunc = nfunc + 1

                ea = ea + 4
    
    idc.plan_and_wait(segment_start, segment_end)

    print("[+] Identified %d new functions" % (nfunc))

    print("[+] Looking for interesting functions")
    find_interesting(segment_start, segment_end)

    return 1

# for easy testing
if __name__ == "__main__":
    # ida_auto.auto_wait()
    print("[+] find_interesting():")

    for seg in idautils.Segments():
        st = ida_segment.getseg(seg)
        name = idaapi.get_segm_name(st)

        if name == "iBoot" or name == "SecureROM" or name == "iBEC" \
                or name == "BootRom" or name == "LLB":

            segm_start = st.start_ea
            segm_end = idc.get_segm_attr(segm_start, idc.SEGATTR_END)
            find_interesting(segm_start, segm_end)
            break

    # ida_pro.qexit(0)

# EOF
