# argp@census-labs.com

import idautils
import idaapi
import ida_search
import ida_funcs
import idc
import struct

true = True
false = False
none = None

prologues = ["BD A9", "BF A9"]

def find_panic(base_ea):
    pk_ea = ida_search.find_text(base_ea, 1, 1, "double panic in ", ida_search.SEARCH_DOWN)

    if pk_ea != idaapi.BADADDR:
        for xref in idautils.XrefsTo(pk_ea):
            func = idaapi.get_func(xref.frm)
            print("\t[+] _panic = 0x%x" % (func.startEA))
            idc.MakeName(func.startEA, "_panic")
            return func.startEA

    return idaapi.BADADDR

def find_aes_crypto_cmd(base_ea):
    aes_ea = ida_search.find_text(base_ea, 1, 1, "aes_crypto_cmd", ida_search.SEARCH_DOWN)

    if aes_ea != idaapi.BADADDR:
        for xref in idautils.XrefsTo(aes_ea):
            func = idaapi.get_func(xref.frm)
            print("\t[+] _aes_crypto_cmd = 0x%x" % (func.startEA))
            idc.MakeName(func.startEA, "_aes_crypto_cmd")
            return func.startEA

    return idaapi.BADADDR

def find_update_device_tree(base_ea):
    udt_ea = ida_search.find_text(base_ea, 1, 1, "development-cert", ida_search.SEARCH_DOWN)

    if udt_ea != idaapi.BADADDR:
        for xref in idautils.XrefsTo(udt_ea):
            func = idaapi.get_func(xref.frm)
            print("\t[+] _UpdateDeviceTree = 0x%x" % (func.startEA))
            idc.MakeName(func.startEA, "_UpdateDeviceTree")
            return func.startEA

    return idaapi.BADADDR

def find_macho_valid(base_ea):
    ea_list = ida_search.find_imm(base_ea, ida_search.SEARCH_DOWN, 0xFACF)

    if ea_list[0] == idaapi.BADADDR:
        ea_list = ida_search.find_imm(base_ea, ida_search.SEARCH_DOWN, 0xFEEDFACF)
    
    if ea_list[0] != idaapi.BADADDR:
        func_ea = ida_funcs.get_func(ea_list[0]).start_ea
        print("\t[+] _macho_valid = 0x%x" % (func_ea))
        idc.MakeName(func_ea, "_macho_valid")
        return func_ea

    return idaapi.BADADDR

def find_loaded_kernelcache(ea):
    ea_list = list(idautils.XrefsTo(ea))

    if ea_list[0].frm != idaapi.BADADDR:
        func_ea = ida_funcs.get_func(ea_list[0].frm).start_ea
        print("\t[+] _loaded_kernelcache = 0x%x" % (func_ea))
        idc.MakeName(func_ea, "_loaded_kernelcache")
        return func_ea

    return idaapi.BADADDR

def find_load_kernelcache(ea):
    ea_list = list(idautils.XrefsTo(ea))

    if ea_list[0].frm != idaapi.BADADDR:
        func_ea = ida_funcs.get_func(ea_list[0].frm).start_ea
        print("\t[+] _load_kernelcache = 0x%x" % (func_ea))
        idc.MakeName(func_ea, "_load_kernelcache")
        return func_ea

    return idaapi.BADADDR

def find_do_go(base_ea):
    str_ea = ida_search.find_text(base_ea, 1, 1, "Memory image not valid", ida_search.SEARCH_DOWN)

    if str_ea != idaapi.BADADDR:
        for xref in idautils.XrefsTo(str_ea):
            func = idaapi.get_func(xref.frm)
            print("\t[+] _do_go = 0x%x" % (func.startEA))
            idc.MakeName(func.startEA, "_do_go")
            return func.startEA

    return idaapi.BADADDR

def find_pmgr_binning_mode_get_value(base_ea):
    str_ea = ida_search.find_text(base_ea, 1, 1, "Invalid low", ida_search.SEARCH_DOWN)

    if str_ea != idaapi.BADADDR:
        for xref in idautils.XrefsTo(str_ea):
            func = idaapi.get_func(xref.frm)
            print("\t[+] _pmgr_binning_mode_get_value = 0x%x" % (func.startEA))
            idc.MakeName(func.startEA, "_pmgr_binning_mode_get_value")
            return func.startEA

    return idaapi.BADADDR

def find_macho_load(base_ea):
    pz_ea = idc.LocByName("aPagezero")

    if pz_ea != idaapi.BADADDR:
        if len(list(idautils.XrefsTo(pz_ea))) != 3:
            return idaapi.BADADDR

        func1_ea = idaapi.get_func(list(idautils.XrefsTo(pz_ea))[0].frm).startEA
        func2_ea = idaapi.get_func(list(idautils.XrefsTo(pz_ea))[1].frm).startEA
        func3_ea = idaapi.get_func(list(idautils.XrefsTo(pz_ea))[2].frm).startEA

        if func2_ea != func3_ea:
            return idaapi.BADADDR

        if func1_ea != func2_ea:
            print("\t[+] _macho_load = 0x%x" % (func2_ea))
            idc.MakeName(func2_ea, "_macho_load")
            return func2_ea

    return idaapi.BADADDR

def find_interesting(base_ea):

    mv_ea = find_macho_valid(base_ea)

    if mv_ea != idaapi.BADADDR:
        ldk_ea = find_loaded_kernelcache(mv_ea)
        lk_ea = find_load_kernelcache(ldk_ea)
    
    pk_ea = find_panic(base_ea)
    go_ea = find_do_go(base_ea)
    aes_ea = find_aes_crypto_cmd(base_ea)
    udt_ea = find_update_device_tree(base_ea)
    ml_ea = find_macho_load(base_ea)
    pgv_ea = find_pmgr_binning_mode_get_value(base_ea)

def accept_file(fd, fname):
    version = 0
    ret = 0

    if type(fname) == str:
        fd.seek(0x280)
        ver_str = fd.read(0x20)

        if ver_str[:5] == "iBoot":
            version = ver_str[6:] # for later
            ret = {"format" : "iBoot (AArch64)", "processor" : "arm"}

    return ret

def load_file(fd, neflags, format):
    global prologues
    size = 0
    base_addr = 0
    ea = 0
    nfunc = 0

    idaapi.set_processor_type("arm", idaapi.SETPROC_ALL)
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
    idc.MakeFunction(ea)

    print("[+] Marked as code")

    # heuristic
    while(true):
        mnemonic = idc.GetMnem(ea)
        
        if "LDR" in mnemonic:
            base_str = idc.GetOpnd(ea, 1)
            base_addr = int(base_str.split("=")[1], 16)
            
            break

        ea += 4

    print("[+] Rebasing to address 0x%x" % (base_addr))
    idaapi.rebase_program(base_addr, idc.MSF_NOFIX)
    idaapi.autoWait()

    segment_start = base_addr
    segment_end = idc.GetSegmentAttr(segment_start, idc.SEGATTR_END)

    ea = segment_start

    print("[+] Searching and defining functions")

    for prologue in prologues:
        while ea != idc.BADADDR:
            ea = idc.FindBinary(ea, idc.SEARCH_DOWN, prologue, 16)
            
            if ea != idc.BADADDR:
                ea = ea - 2

                if (ea % 4) == 0 and idc.GetFlags(ea) < 0x200:
                    # print("[+] Defining a function at 0x%x" % (ea))
                    idc.MakeFunction(ea)
                    nfunc = nfunc + 1

                ea = ea + 4
    
    idc.AnalyzeArea(segment_start, segment_end)
    idaapi.autoWait()

    print("[+] Identified %d new functions" % (nfunc))

    print("[+] Looking for interesting functions")
    find_interesting(segment_start)

    return 1

# EOF
