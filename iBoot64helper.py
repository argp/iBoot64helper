# argp@census-labs.com, Fri Sep 30 13:50:29 EEST 2016

import idautils
import idaapi
import idc

true = True
false = False
none = None

def main():
    base_addr = 0
    ea = 0
    idc.MakeFunction(ea)

    # heuristic
    while(true):
        mnemonic = idc.GetMnem(ea)
        
        if "LDR" in mnemonic:
            base_str = idc.GetOpnd(ea, 1)
            base_addr = int(base_str.split("=")[1], 16)
            
            break

        ea += 4

    print("[+] rebasing to address 0x%x" % (base_addr))
    idc.rebase_program(base_addr, idc.MSF_FIXONCE)
    idaapi.autoWait()

    segment_start = base_addr
    segment_end = idc.GetSegmentAttr(segment_start, idc.SEGATTR_END)

    ea = segment_start

    print("[+] searching and defining functions")

    while ea != idc.BADADDR:
        ea = idc.FindBinary(ea, idc.SEARCH_DOWN, "BF A9", 16)
            
        if ea != idc.BADADDR:
            ea = ea - 2

            if (ea % 4) == 0 and idc.GetFlags(ea) < 0x200:
                # print("[+] defining a function at 0x%x" % (ea))
                idc.MakeFunction(ea)

            ea = ea + 4
            
    idc.AnalyzeArea(segment_start, segment_end)
    idaapi.autoWait()

if __name__ == "__main__":
    main()
    print("[+] iboot64helper finished")

# EOF
