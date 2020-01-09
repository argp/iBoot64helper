# argp@census-labs.com

import idautils
import idaapi
import ida_idaapi
import ida_search
import ida_funcs
import ida_segment
import ida_bytes
import ida_idp
import idc
import struct

true = True
false = False
none = None

kp_flag = false

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

    return ida_idaapi.BADADDR

def find_image4_load(base_ea):
    ea_list = ida_search.find_imm(base_ea, ida_search.SEARCH_DOWN, 0x4D650000)

    if ea_list[0] != ida_idaapi.BADADDR:
        func_ea = ida_funcs.get_func(ea_list[0]).start_ea
        print("\t[+] _image4_load = 0x%x" % (func_ea))
        idc.set_name(func_ea, "_image4_load", idc.SN_CHECK)
        return func_ea

    return ida_idaapi.BADADDR

def find_img4decodeinit(base_ea):
    ea_list = ida_search.find_imm(base_ea, ida_search.SEARCH_DOWN, 0x494D0000)

    if ea_list[0] != ida_idaapi.BADADDR:
        func_ea = ida_funcs.get_func(ea_list[0]).start_ea
        ea_func_list = list(idautils.XrefsTo(func_ea))

        if ea_func_list[0].frm != ida_idaapi.BADADDR:
            i4d_ea = ida_funcs.get_func(ea_func_list[0].frm).start_ea
            print("\t[+] _Img4DecodeInit = 0x%x" % (i4d_ea))
            idc.set_name(i4d_ea, "_Img4DecodeInit", idc.SN_CHECK)
            return i4d_ea

    return ida_idaapi.BADADDR

def find_aes_crypto_cmd(base_ea):
    aes_ea = ida_search.find_text(base_ea, 1, 1, "aes_crypto_cmd", ida_search.SEARCH_DOWN)

    if aes_ea != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(aes_ea):
            func = idaapi.get_func(xref.frm)
            print("\t[+] _aes_crypto_cmd = 0x%x" % (func.start_ea))
            idc.set_name(func.start_ea, "_aes_crypto_cmd", idc.SN_CHECK)
            return func.start_ea

    return ida_idaapi.BADADDR

def find_main_task(base_ea):
    du_ea = ida_search.find_text(base_ea, 1, 1, "debug-uarts", ida_search.SEARCH_DOWN)

    if du_ea != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(du_ea):
            func = idaapi.get_func(xref.frm)
            print("\t[+] _main_task = 0x%x" % (func.start_ea))
            idc.set_name(func.start_ea, "_main_task", idc.SN_CHECK)
            return func.start_ea

    return ida_idaapi.BADADDR

def find_boot_check_panic(base_ea, base_end_ea):
    seq_ea = ida_search.find_binary(base_ea, base_end_ea, "1F ?? 03 71", 16, ida_search.SEARCH_DOWN)

    if seq_ea != ida_idaapi.BADADDR:
        func = idaapi.get_func(seq_ea)
        print("\t[+] _boot_check_panic = 0x%x" % (func.start_ea))
        idc.set_name(func.start_ea, "_boot_check_panic", idc.SN_CHECK)
        return func.start_ea

    return ida_idaapi.BADADDR

def find_update_device_tree(base_ea):
    udt_ea = ida_search.find_text(base_ea, 1, 1, "development-cert", ida_search.SEARCH_DOWN)

    if udt_ea != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(udt_ea):
            func = idaapi.get_func(xref.frm)
            print("\t[+] _UpdateDeviceTree = 0x%x" % (func.start_ea))
            idc.set_name(func.start_ea, "_UpdateDeviceTree", idc.SN_CHECK)
            return func.start_ea

    return ida_idaapi.BADADDR

def find_macho_valid(base_ea):
    ea_list = ida_search.find_imm(base_ea, ida_search.SEARCH_DOWN, 0xFACF)

    if ea_list[0] == ida_idaapi.BADADDR:
        ea_list = ida_search.find_imm(base_ea, ida_search.SEARCH_DOWN, 0xFEEDFACF)
    
    if ea_list[0] != ida_idaapi.BADADDR:
        func_ea = ida_funcs.get_func(ea_list[0]).start_ea
        print("\t[+] _macho_valid = 0x%x" % (func_ea))
        idc.set_name(func_ea, "_macho_valid", idc.SN_CHECK)
        return func_ea

    return ida_idaapi.BADADDR

def find_loaded_kernelcache(ea):
    ea_list = list(idautils.XrefsTo(ea))

    if ea_list[0].frm != ida_idaapi.BADADDR:
        func_ea = ida_funcs.get_func(ea_list[0].frm).start_ea
        print("\t[+] _loaded_kernelcache = 0x%x" % (func_ea))
        idc.set_name(func_ea, "_loaded_kernelcache", idc.SN_CHECK)
        return func_ea

    return ida_idaapi.BADADDR

def find_load_kernelcache(ea):
    ea_list = list(idautils.XrefsTo(ea))

    if ea_list[0].frm != ida_idaapi.BADADDR:
        func_ea = ida_funcs.get_func(ea_list[0].frm).start_ea
        print("\t[+] _load_kernelcache = 0x%x" % (func_ea))
        idc.set_name(func_ea, "_load_kernelcache", idc.SN_CHECK)
        return func_ea

    return ida_idaapi.BADADDR

def find_do_go(base_ea):
    str_ea = ida_search.find_text(base_ea, 1, 1, "Memory image not valid", ida_search.SEARCH_DOWN)

    if str_ea != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(str_ea):
            func = idaapi.get_func(xref.frm)
            print("\t[+] _do_go = 0x%x" % (func.start_ea))
            idc.set_name(func.start_ea, "_do_go", idc.SN_CHECK)
            return func.start_ea

    return ida_idaapi.BADADDR

def find_pmgr_binning_mode_get_value(base_ea):
    str_ea = ida_search.find_text(base_ea, 1, 1, "Invalid low", ida_search.SEARCH_DOWN)

    if str_ea != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(str_ea):
            func = idaapi.get_func(xref.frm)
            print("\t[+] _pmgr_binning_mode_get_value = 0x%x" % (func.start_ea))
            idc.set_name(func.start_ea, "_pmgr_binning_mode_get_value", idc.SN_CHECK)
            return func.start_ea

    return ida_idaapi.BADADDR

def find_do_printf(base_ea):
    str_ea = ida_search.find_text(base_ea, 1, 1, "<ptr>", ida_search.SEARCH_DOWN)

    if str_ea != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(str_ea):
            func = idaapi.get_func(xref.frm)
            print("\t[+] _do_printf = 0x%x" % (func.start_ea))
            idc.set_name(func.start_ea, "_do_printf", idc.SN_CHECK)
            return func.start_ea

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

    return ida_idaapi.BADADDR

def find_putchar(base_ea):
    str_ea = idc.get_name_ea_simple("aPanic")

    if str_ea != ida_idaapi.BADADDR:
        apanic_ea = list(idautils.XrefsTo(str_ea))[0].frm

        if apanic_ea == ida_idaapi.BADADDR:
            return ida_idaapi.BADADDR

        opnd0 = idc.print_operand(apanic_ea + 8, 0)
        ins_str = idc.print_insn_mnem(apanic_ea + 8)

        if ins_str == "BL":
            func_ea = idc.get_name_ea_simple(opnd0)
            ea = func_ea

            while ea != ida_idaapi.BADADDR:
                ins_str = idc.print_insn_mnem(ea)
                
                if ins_str == "ADD":
                    opnd2 = idc.print_operand(ea, 2)
                    
                    if opnd2 == "#1":
                        ins_ea = ea - 4
                        opnd0 = idc.print_operand(ins_ea, 0)
                        ins_str = idc.print_insn_mnem(ins_ea)

                        if ins_str == "BL":
                            pc_ea = idc.get_name_ea_simple(opnd0)
                            print("\t[+] _putchar = 0x%x" % (pc_ea))
                            idc.set_name(pc_ea, "_putchar", idc.SN_CHECK)
                            return pc_ea

                ea = ea + 4

    return ida_idaapi.BADADDR

def find_macho_load(base_ea):
    pz_ea = idc.get_name_ea_simple("aPagezero")

    if pz_ea != ida_idaapi.BADADDR:
        if len(list(idautils.XrefsTo(pz_ea))) != 3:
            return ida_idaapi.BADADDR

        func1_ea = idaapi.get_func(list(idautils.XrefsTo(pz_ea))[0].frm).start_ea
        func2_ea = idaapi.get_func(list(idautils.XrefsTo(pz_ea))[1].frm).start_ea
        func3_ea = idaapi.get_func(list(idautils.XrefsTo(pz_ea))[2].frm).start_ea

        if func2_ea != func3_ea:
            return ida_idaapi.BADADDR

        if func1_ea != func2_ea:
            print("\t[+] _macho_load = 0x%x" % (func2_ea))
            idc.set_name(func2_ea, "_macho_load", idc.SN_CHECK)
            return func2_ea

    return ida_idaapi.BADADDR

def find_interesting(base_ea, base_end):
    mv_ea = find_macho_valid(base_ea)

    if mv_ea != ida_idaapi.BADADDR:
        ldk_ea = find_loaded_kernelcache(mv_ea)
        lk_ea = find_load_kernelcache(ldk_ea)
    
    pk_ea = find_panic(base_ea)
    go_ea = find_do_go(base_ea)
    pr_ea = find_do_printf(base_ea)
    i4l_ea = find_image4_load(base_ea)
    i4d_ea = find_img4decodeinit(base_ea)
    aes_ea = find_aes_crypto_cmd(base_ea)
    udt_ea = find_update_device_tree(base_ea)
    ml_ea = find_macho_load(base_ea)
    pgv_ea = find_pmgr_binning_mode_get_value(base_ea)
    i4p_ea = find_image4_get_partial(base_ea)
    mt_ea = find_main_task(base_ea)
    bc_ea = find_boot_check_panic(base_ea, base_end)

    pc_ea = find_putchar(base_ea)

    if pc_ea != ida_idaapi.BADADDR and mv_ea == ida_idaapi.BADADDR:
        # this is a SecureROM image
        segm = ida_segment.getseg(base_ea)

        if segm:
            idaapi.set_segm_name(segm, "SecureROM", 0)
            print("[+] Identified as a SecureROM image")

def accept_file(fd, fname):
    version = 0
    ret = 0

    if type(fname) == str:
        fd.seek(0x280)
        ver_str = fd.read(0x20)

        try:
            # Python 3.x.
            label = "".join(map(chr, ver_str[:5]))
        except TypeError:
            # Python 2.x.
            label = ver_str[:5]

        if "iBoot" == label:
            version = ver_str[6:] # for later
            ret = {"format" : "iBoot (AArch64)", "processor" : "arm"}

    return ret

def load_file(fd, neflags, format):
    global prologues
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
    idaapi.add_segm_ex(segm, "iBoot", "CODE", idaapi.ADDSEG_OR_DIE)

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

# EOF
