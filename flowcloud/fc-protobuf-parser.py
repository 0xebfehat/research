# FlowCloud fcClient x86 Protocol Buffers Parser
# Need protobuf package
# pip install protobuf 
# Confirmed versoin
#   IDA Pro 8.4sp2, 9.1
#   protbuf: 3.20.1, 5.28.3

# Usage: set cursor at the Protocol Buffer File Descriptor in rdata segment
# Run at 2 bytes before fc_net.proto or fc_file_transfer.proto string
# .rdata:102CE610 unk_102CE610    db  0Ah           <-- Here
# .rdata:102CE611                 db  0Ch
# .rdata:102CE612 aFcNetProto_0   db 'fc_net.proto'

from google.protobuf import descriptor_pb2
import ida_bytes
import ida_kernwin

def read_bytes(addr, size):
    return bytes([ida_bytes.get_byte(addr + i) for i in range(size)])

def parse_descriptor(addr):
    try:
        for size in [0x1000, 0x2000, 0x4000, 0x8000]:
            try:
                data = read_bytes(addr, size)
                proto = descriptor_pb2.FileDescriptorProto()
                proto.ParseFromString(data)
                print(f"[+] Success with size: {size}")
                return proto
            except Exception as e:
                continue
        return proto
    except Exception:
        print("exception")
        return None
    
def count_messages(msg):
    count = 1
    for nested in msg.nested_type:
        count += count_messages(nested)
    return count

def format_enum(enum, indent=0):
    indent_str = '  ' * indent
    lines = [f'{indent_str}enum {enum.name} {{']
    for value in enum.value:
        lines.append(f'{indent_str}  {value.name} = {value.number},')
    lines.append(f'{indent_str}}}')
    return "\n".join(lines)

def format_message(msg, indent=0):
    indent_str = '  ' * indent
    lines = [f'{indent_str}message {msg.name} {{']

    # Nested enums
    for enum in msg.enum_type:
        lines.append(format_enum(enum, indent + 1))
        lines.append("")

    for nested in msg.nested_type:
        lines.append(format_message(nested, indent + 1))
        lines.append("")

    # Fields
    for field in msg.field:
        label = {
            1: "optional",
            2: "required",
            3: "repeated"
        }.get(field.label, "optional")
        if field.type == 11 or field.type == 14:
            ftype = field.type_name.split(".")[-1] if field.type_name else "unknown_message_or_enum"
        else:
            ftype = {
                1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32",
                6: "fixed64", 7: "fixed32", 8: "bool", 9: "string",
                12: "bytes", 13: "uint32", 15: "sfixed32", 16: "sfixed64", 17: "sint32", 18: "sint64"
            }.get(field.type, "unknown")
        lines.append(f'{indent_str}  {label} {ftype} {field.name} = {field.number};')
    lines.append(f'{indent_str}}}')
    return "\n".join(lines)

def format_proto(fd_proto):
    lines = [f'// File: {fd_proto.name}']
    msg_cnt = 0

    for enum in fd_proto.enum_type:
        lines.append(format_enum(enum))
        lines.append("")

    for msg in fd_proto.message_type:
        lines.append(format_message(msg))
        lines.append("")
        msg_cnt += count_messages(msg)

    return '\n'.join(lines), msg_cnt



def main():
    addr = ida_kernwin.get_screen_ea()
    print(f"[+] Scanning for valid descriptor at 0x{addr:X}...")
    descriptor = parse_descriptor(addr)
    if descriptor:
        print(f"[+] Successfully parsed descriptor at 0x{addr:X}")
        result, msg_cnt = format_proto(descriptor)
        print("\n=== Extracted Proto ===\n")
        print("syntax = \"proto2\";\n")
        print(result)
        print("\n=== [%d] messages found\n" % msg_cnt)
    else:
        print("[!] Failed to parse descriptor within allowed size range.")

if __name__ == "__main__":
    main()
