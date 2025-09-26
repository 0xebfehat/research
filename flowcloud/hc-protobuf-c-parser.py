# FlowCloud hcClient x86 protobuf-c parser
#
# Confirmed versoin
#   IDA Pro 9.1
#
# Run this script inside .rdata segment
#

import idaapi
import idautils
import idc
import struct
import ida_bytes
import ida_nalt
import ida_ida

protobuf_c_type = {
    0: "int32",
    1: "sint32",
    2: "sfixed32",
    3: "int64",
    4: "sint64",
    5: "sfixed64",
    6: "uint32",
    7: "fixed32",
    8: "uint64",
    9: "fixed64",
    10: "float",
    11: "double",
    12: "bool",
    13: "enum",
    14: "string",
    15: "bytes",
    16: "message",
}

protobuf_c_label = {
    0: "required",
    1: "optional",
    2: "repeated",
}

IDA_NALT_ENCODING = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)  # use one byte-per-character encoding

def parse_ProtobufCFieldDescriptor(addr, index):
    entry_addr = addr+48*index
    
    name_addr = get_wide_dword(entry_addr)
    name = get_strlit_contents(name_addr, -1, STRTYPE_C)
    
    id = get_wide_dword(entry_addr+0x4)
    label = get_wide_dword(entry_addr+0x8)
    type_f = get_wide_dword(entry_addr+0xC)

    offset = get_wide_dword(entry_addr+0x14)
    
    descriptor = get_wide_dword(entry_addr+0x18)
    
    label_name = protobuf_c_label.get(label, f"unknown({label})")
    type_name = protobuf_c_type.get(type_f, f"unknown({type_f})")
    
    # descriptor is address to ProtobufCEnumDescriptor
    if descriptor:
        short_name =  ida_bytes.get_strlit_contents(get_wide_dword(descriptor + 0x8), -1, STRTYPE_C)
        print("  %s %s %s = %d" % (label_name, short_name.decode('utf-8'), name.decode(), id))
    else:
        print("  %s %s %s = %d" % (label_name, type_name, name.decode(), id))
    
    
def parse_ProtobufCMessageDescriptor(addr):
    print("Message target found at 0x%08x" % addr)
    magic = ida_bytes.get_wide_dword(addr)
    if magic != 0x28aaeef9:
        print("bad magic")
        return
        
    #c_name_addr = ida_bytes.get_wide_dword(addr+0x8)
    c_name_addr = ida_bytes.get_wide_dword(addr+0xC)
    c_name = ida_bytes.get_strlit_contents(c_name_addr, -1, STRTYPE_C)


    print("message %s {" % c_name.decode())
    idc.set_name(addr, c_name.decode(), ida_name.SN_CHECK | ida_name.SN_FORCE)
    
    sizeof_message = ida_bytes.get_wide_dword(addr+0x14)
    n_fields = ida_bytes.get_wide_dword(addr+0x18)
    fields_addr = ida_bytes.get_wide_dword(addr+0x1c)

    for i in range(n_fields):
        parse_ProtobufCFieldDescriptor(fields_addr, i)
        
    print("}\n")

def search_protobufc_message(searchPattern, startAddress, endAddress):

    byte_data = bytes(int(byte, 16) for byte in searchPattern.split())
    byte_count = len(byte_data)
    message_cnt = 0
    
    patterns = ida_bytes.compiled_binpat_vec_t()
    err = ida_bytes.parse_binpat_str(patterns, 0, searchPattern, 16, IDA_NALT_ENCODING)
    if err:
        return

    pos = startAddress
    while pos < endAddress:
        found_pos = ida_bytes.bin_search(pos, endAddress, patterns, ida_bytes.BIN_SEARCH_FORWARD)
        pos = found_pos[0]
        if pos == idaapi.BADADDR:
            break
        message_cnt += 1
        parse_ProtobufCMessageDescriptor(pos)
        pos += byte_count
        
    return message_cnt

def read_ptr(addr):
    if ida_ida.inf_is_32bit_exactly() :
        return struct.unpack("<I", idc.get_bytes(addr, 4))[0]
    else:
        return struct.unpack("<Q", idc.get_bytes(addr, 8))[0]

def read_cstr(ptr):
    return idc.get_strlit_contents(ptr, -1, idc.STRTYPE_C).decode("utf-8") if ptr else ""

def parse_enum_descriptor(ea):
    ptr_size = 4 if ida_ida.inf_is_32bit_exactly() else 8
    off = 0

    # magic number
    magic = struct.unpack("<I", idc.get_bytes(ea + off, 4))[0]
    off += 4

    if magic != 0x114315af:
        print(f"[!] Magic number mismatch: 0x{magic:X}")
        return

    name_ptr         = read_ptr(ea + off); off += ptr_size
    short_name_ptr   = read_ptr(ea + off); off += ptr_size
    c_name_ptr       = read_ptr(ea + off); off += ptr_size
    package_name_ptr = read_ptr(ea + off); off += ptr_size

    n_values = struct.unpack("<I", idc.get_bytes(ea + off, 4))[0]
    off += 4
    values_ptr = read_ptr(ea + off)
    off += ptr_size

    print(f"  Name       : {read_cstr(name_ptr)}")
    print(f"  Short Name : {read_cstr(short_name_ptr)}")
    print(f"  C Name     : {read_cstr(c_name_ptr)}")
    print(f"  Package    : {read_cstr(package_name_ptr)}")
    print(f"  n_values   : {n_values}")
    #print(f"  values_ptr : 0x{values_ptr:X}")

    # === values (ProtobufCEnumValue[])
    if not values_ptr or n_values == 0:
        print("  [!] No enum values found.")
        return

    print("  Values:")
    base = values_ptr
    for i in range(n_values):
        name_str = read_cstr(read_ptr(base))
        base += ptr_size
        c_name = read_cstr(read_ptr(base))
        print(f"    - {name_str} = {c_name}")
        base += 2 * ptr_size

def search_protobufc_enum(searchPattern, startAddress, endAddress):

    byte_data = bytes(int(byte, 16) for byte in searchPattern.split())
    byte_count = len(byte_data)
    enum_cnt = 0

    patterns = ida_bytes.compiled_binpat_vec_t()
    err = ida_bytes.parse_binpat_str(patterns, 0, searchPattern, 16, IDA_NALT_ENCODING)
    if err:
        return

    pos = startAddress
    while pos < endAddress:
        found_pos = ida_bytes.bin_search(pos, endAddress, patterns, ida_bytes.BIN_SEARCH_FORWARD)
        pos = found_pos[0]
        if pos == idaapi.BADADDR:
            break
        enum_cnt += 1
        parse_enum_descriptor(pos)
        pos += byte_count
        
    return enum_cnt

def main():

    msg_cnt = 0
    enum_cnt = 0

    start_ea = idc.get_segm_start(ida_kernwin.get_screen_ea())
    end_ea = idc.get_segm_end(start_ea)
    SEARCH_PATTERN = "F9 EE AA 28"
    msg_cnt = search_protobufc_message(SEARCH_PATTERN, start_ea, end_ea)
    SEARCH_PATTERN = "AF 15 43 11"
    enum_cnt = search_protobufc_enum(SEARCH_PATTERN, start_ea, end_ea)

    print("%d messages found and %d enum found" % (msg_cnt, enum_cnt))

if __name__ == '__main__':
    main()
