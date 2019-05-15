# argp@census-labs.com, Wed 15 May 2019 01:05:33 PM EEST

import idautils
import idaapi
import idc
import struct

true = True
false = False
none = None

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
    size = 0
    base_addr = 0
    ea = 0

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

    while ea != idc.BADADDR:
        ea = idc.FindBinary(ea, idc.SEARCH_DOWN, "BF A9", 16)
            
        if ea != idc.BADADDR:
            ea = ea - 2

            if (ea % 4) == 0 and idc.GetFlags(ea) < 0x200:
                # print("[+] Defining a function at 0x%x" % (ea))
                idc.MakeFunction(ea)

            ea = ea + 4
            
    idc.AnalyzeArea(segment_start, segment_end)
    idaapi.autoWait()

    return 1

# EOF