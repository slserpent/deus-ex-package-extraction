#!/usr/bin/env python3
"""
Deus Ex Codes and Logins List Tool
Gets a list of all objects of type ATM, Computer, or Keypad plus their associated login or code
in the given Deus Ex map files
"""

import os
import sys
import glob
import struct

def read_uint32_le(data, offset):
    """Read a 32-bit little-endian unsigned integer"""
    if offset + 4 > len(data):
        return None, offset
    return struct.unpack('<I', data[offset:offset+4])[0], offset + 4

def read_compact_index(data, offset):
    """Read a CompactIndex from the data"""
    if offset >= len(data):
        return None, offset
    
    # Read first byte
    first_byte = data[offset]
    offset += 1
    
    # Extract sign bit (most significant bit)
    is_negative = (first_byte & 0x80) != 0
    
    # Extract continuation flag (second most significant bit)
    has_continuation = (first_byte & 0x40) != 0
    
    # Extract value bits (remaining 6 bits)
    value = first_byte & 0x3F
    
    # If no continuation, we're done
    if not has_continuation:
        return -value if is_negative else value, offset
    
    # Read subsequent bytes (up to 4 more)
    shift = 6
    for byte_num in range(1, 5):
        if offset >= len(data):
            return None, offset
        
        next_byte = data[offset]
        offset += 1
        
        # Check continuation flag (most significant bit for bytes 2-4)
        has_continuation = (next_byte & 0x80) != 0
        
        # Extract value bits
        if byte_num < 4:
            # Bytes 2-4: 7 bits of value
            byte_value = next_byte & 0x7F
        else:
            # Byte 5: all 8 bits are value
            byte_value = next_byte
        
        # Add to value
        value |= (byte_value << shift)
        shift += 7 if byte_num < 4 else 8
        
        # Stop if no continuation
        if not has_continuation or byte_num == 4:
            break
    
    return -value if is_negative else value, offset

def read_pascal_string_with_flags(data, offset):
    """Read a pascal-style string followed by 4 bytes of flags"""
    if offset >= len(data):
        return None, offset
    
    # Read string length
    string_length = data[offset]
    offset += 1
    
    if offset + string_length + 4 > len(data):
        return None, offset
    
    # Read string (including null terminator)
    string_data = data[offset:offset + string_length]
    offset += string_length
    
    # Remove null terminator if present
    if string_data and string_data[-1] == 0:
        string_data = string_data[:-1]
    
    # Skip 4 bytes of flags
    offset += 4
    
    try:
        string_text = string_data.decode('ascii', errors='ignore')
        return string_text, offset
    except:
        return None, offset

def parse_name_table(data, name_count, name_table_offset):
    """Parse the name table and return a list of names"""
    names = []
    offset = name_table_offset
    
    for i in range(name_count):
        name, new_offset = read_pascal_string_with_flags(data, offset)
        
        if name is None:
            break
        
        names.append(name)
        offset = new_offset
        
        if offset >= len(data):
            break
    
    return names

def parse_import_table(data, import_count, import_table_offset, names):
    """Parse the import table and return a list of import entries"""
    imports = []
    offset = import_table_offset
    
    for i in range(import_count):
        # Read Class Package index
        class_package_index, offset = read_compact_index(data, offset)
        if class_package_index is None:
            break
        
        # Read Class Name index
        class_name_index, offset = read_compact_index(data, offset)
        if class_name_index is None:
            break
        
        # Read Package DWORD (ObjectReference)
        package, offset = read_uint32_le(data, offset)
        if package is None:
            break
        
        # Read Object Name index
        object_name_index, offset = read_compact_index(data, offset)
        if object_name_index is None:
            break
        
        # Resolve names
        class_package_name = names[class_package_index] if 0 <= class_package_index < len(names) else f"<invalid:{class_package_index}>"
        class_name = names[class_name_index] if 0 <= class_name_index < len(names) else f"<invalid:{class_name_index}>"
        object_name = names[object_name_index] if 0 <= object_name_index < len(names) else f"<invalid:{object_name_index}>"
        
        imports.append({
            'class_package_index': class_package_index,
            'class_package_name': class_package_name,
            'class_name_index': class_name_index,
            'class_name': class_name,
            'package': package,
            'object_name_index': object_name_index,
            'object_name': object_name
        })
    
    return imports

def parse_export_table(data, export_count, export_table_offset, names):
    """Parse the export table and return a list of export entries"""
    exports = []
    offset = export_table_offset
    
    for i in range(export_count):
        # Read Class index
        class_index, offset = read_compact_index(data, offset)
        if class_index is None:
            break
        
        # Read Super index
        super_index, offset = read_compact_index(data, offset)
        if super_index is None:
            break
        
        # Read Group DWORD
        group, offset = read_uint32_le(data, offset)
        if group is None:
            break
        
        # Read Object Name index
        name_index, offset = read_compact_index(data, offset)
        if name_index is None:
            break
        
        # Read Object Flags DWORD
        object_flags, offset = read_uint32_le(data, offset)
        if object_flags is None:
            break
        
        # Read Serial Size
        serial_size, offset = read_compact_index(data, offset)
        if serial_size is None:
            break
        
        # Read Serial Offset (only if serial size > 0)
        serial_offset = None
        if serial_size > 0:
            serial_offset, offset = read_compact_index(data, offset)
            if serial_offset is None:
                break
        
        # Get the instance name string
        instance_name = names[name_index] if 0 <= name_index < len(names) else f"<invalid:{name_index}>"
        
        exports.append({
            'class_index': class_index,
            'super_index': super_index,
            'group': group,
            'name_index': name_index,
            'instance_name': instance_name,
            'object_flags': object_flags,
            'serial_size': serial_size,
            'serial_offset': serial_offset
        })
    
    return exports

def resolve_class_name(class_index, imports, exports):
    """Resolve a class_index to its class name"""
    if class_index < 0:
        # Negative: references import table (1-indexed, so -1 = import[0])
        import_idx = (-class_index) - 1
        if 0 <= import_idx < len(imports):
            return imports[import_idx]['object_name'], False
        return f"<invalid_import:{class_index}>", False
    elif class_index > 0:
        # Positive: references export table (1-indexed, so 1 = export[0])
        export_idx = class_index - 1
        if 0 <= export_idx < len(exports):
            return exports[export_idx]['instance_name'], True
        return f"<invalid_export:{class_index}>", True
    else:
        # Zero: null reference
        return "<None>", False

def parse_property_block(data, serial_offset, serial_size, names, class_name, extract_balance=False, debug=False):
    """Parse property block to extract userList or validCode data"""
    results = []
    
    if serial_offset is None or serial_offset >= len(data):
        return results
    
    # Read the property block
    block_end = min(serial_offset + serial_size, len(data))
    block_data = data[serial_offset:block_end]
    
    if len(block_data) < 15:
        return results
    
    offset = 0
    
    # Find the name indices we're looking for
    userlist_index = None
    suserinfo_index = None
    validcode_index = None
    
    for i, name in enumerate(names):
        if name == 'userList':
            userlist_index = i
        elif name == 'sUserInfo':
            suserinfo_index = i
        elif name == 'validCode':
            validcode_index = i
    
    if debug:
        print(f"  Looking for: userList={userlist_index}, sUserInfo={suserinfo_index}, validCode={validcode_index}", file=sys.stderr)
    
    # Search for userList properties (only for Computers and ATMs)
    if userlist_index is not None and suserinfo_index is not None and class_name in ['ComputerPersonal', 'ComputerSecurity', 'ATM']:
        offset = 0
        
        while offset < len(block_data) - 20:
            try:
                prop_index, new_offset = read_compact_index(block_data, offset)
                if prop_index == userlist_index:
                    if debug:
                        print(f"    Found userList at offset {offset}", file=sys.stderr)
                    
                    # Read flags byte
                    if new_offset >= len(block_data):
                        break
                    flags_byte = block_data[new_offset]
                    check_offset = new_offset + 1
                    
                    # Extract flags
                    has_struct_size = (flags_byte & 0x10) != 0
                    has_array_index = (flags_byte & 0x80) != 0
                    
                    if debug:
                        print(f"      Flags byte: 0x{flags_byte:02x}", file=sys.stderr)
                    
                    if check_offset >= len(block_data):
                        break
                    
                    # Read sUserInfo index
                    info_index, check_offset = read_compact_index(block_data, check_offset)
                    if info_index == suserinfo_index:
                        if debug:
                            print(f"      Confirmed sUserInfo", file=sys.stderr)
                        
                        # Read struct size if flag is set
                        if has_struct_size:
                            if check_offset >= len(block_data):
                                break
                            struct_size = block_data[check_offset]
                            check_offset += 1
                            if debug:
                                print(f"      Struct size: {struct_size}", file=sys.stderr)
                        
                        # Read array index if flag is set
                        if has_array_index:
                            if check_offset >= len(block_data):
                                break
                            array_index = block_data[check_offset]
                            check_offset += 1
                            if debug:
                                print(f"      Array index: {array_index}", file=sys.stderr)
                        
                        # Read username
                        if check_offset >= len(block_data):
                            break
                        username_len = block_data[check_offset]
                        check_offset += 1
                        
                        if check_offset + username_len > len(block_data):
                            break
                        username_bytes = block_data[check_offset:check_offset + username_len]
                        if username_bytes and username_bytes[-1] == 0:
                            username_bytes = username_bytes[:-1]
                        username = username_bytes.decode('ascii', errors='ignore')
                        check_offset += username_len
                        
                        # Read password
                        if check_offset >= len(block_data):
                            break
                        password_len = block_data[check_offset]
                        check_offset += 1
                        
                        if check_offset + password_len > len(block_data):
                            break
                        password_bytes = block_data[check_offset:check_offset + password_len]
                        if password_bytes and password_bytes[-1] == 0:
                            password_bytes = password_bytes[:-1]
                        password = password_bytes.decode('ascii', errors='ignore')
                        check_offset += password_len
                        
                        # Read balance if extracting and enough bytes remain
                        balance = None
                        if extract_balance and check_offset + 4 <= len(block_data):
                            balance = struct.unpack('<I', block_data[check_offset:check_offset+4])[0]
                            if debug:
                                print(f"      Balance: {balance}", file=sys.stderr)
                        
                        result = {'type': 'user', 'username': username, 'password': password}
                        if balance is not None:
                            result['balance'] = balance
                        results.append(result)
                        
                        if debug:
                            print(f"      Found: '{username}' / '{password}'", file=sys.stderr)
                
                offset = new_offset
            except:
                offset += 1
    
    # Search for validCode property (only for Keypads)
    if validcode_index is not None and class_name in ['Keypad1', 'Keypad2', 'Keypad3']:
        offset = 0
        while offset < len(block_data) - 10:
            try:
                prop_index, new_offset = read_compact_index(block_data, offset)
                if prop_index == validcode_index:
                    if debug:
                        print(f"    Found validCode at offset {offset}", file=sys.stderr)
                    
                    # Read flags byte
                    if new_offset >= len(block_data):
                        break
                    flags_byte = block_data[new_offset]
                    check_offset = new_offset + 1
                    
                    # Extract flags
                    has_struct_size = (flags_byte & 0x10) != 0
                    has_array_index = (flags_byte & 0x80) != 0
                    
                    if debug:
                        print(f"      Flags byte: 0x{flags_byte:02x}", file=sys.stderr)
                    
                    # Read property length if struct size flag is set
                    if has_struct_size:
                        if check_offset >= len(block_data):
                            break
                        prop_length = block_data[check_offset]
                        check_offset += 1
                        if debug:
                            print(f"      Property length: {prop_length}", file=sys.stderr)
                    
                    # Read array index if flag is set
                    if has_array_index:
                        if check_offset >= len(block_data):
                            break
                        array_index = block_data[check_offset]
                        check_offset += 1
                        if debug:
                            print(f"      Array index: {array_index}", file=sys.stderr)
                    
                    # Read string length
                    if check_offset >= len(block_data):
                        break
                    code_len = block_data[check_offset]
                    check_offset += 1
                    
                    # Read the code
                    if check_offset + code_len > len(block_data):
                        break
                    code_bytes = block_data[check_offset:check_offset + code_len]
                    if code_bytes and code_bytes[-1] == 0:
                        code_bytes = code_bytes[:-1]
                    code = code_bytes.decode('ascii', errors='ignore')
                    
                    results.append({'type': 'keypad', 'code': code})
                    
                    if debug:
                        print(f"      Found keypad code: '{code}'", file=sys.stderr)
                    break
                
                offset = new_offset
            except:
                offset += 1
    
    return results

def process_file(filepath, extract_balance=False, debug=False):
    """Process a single .dx file and extract credentials"""
    filename = os.path.basename(filepath)
    results = []
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading {filepath}: {e}", file=sys.stderr)
        return results
    
    if len(data) < 36:
        return results
    
    signature = data[0:4]
    expected_signature = bytes([0xC1, 0x83, 0x2A, 0x9E])
    
    if signature != expected_signature:
        print(f"Warning: {filename} doesn't have expected signature", file=sys.stderr)
        return results
    
    # Read header values
    name_count, _ = read_uint32_le(data, 12)
    name_table_offset, _ = read_uint32_le(data, 16)
    export_count, _ = read_uint32_le(data, 20)
    export_table_offset, _ = read_uint32_le(data, 24)
    import_count, _ = read_uint32_le(data, 28)
    import_table_offset, _ = read_uint32_le(data, 32)
    
    if any(x is None for x in [name_count, name_table_offset, export_count, export_table_offset, import_count, import_table_offset]):
        print(f"Error: Could not read header from {filename}", file=sys.stderr)
        return results
    
    # Parse all three tables
    names = parse_name_table(data, name_count, name_table_offset)
    imports = parse_import_table(data, import_count, import_table_offset, names)
    exports = parse_export_table(data, export_count, export_table_offset, names)
    
    if debug:
        print(f"\n=== DEBUG: {filename} ===", file=sys.stderr)
        print(f"Names: {len(names)}, Imports: {len(imports)}, Exports: {len(exports)}", file=sys.stderr)
    
    # Target names we're interested in
    target_names = {
        'ATM',
        'ComputerPersonal',
        'ComputerSecurity',
        'Keypad1',
        'Keypad2',
        'Keypad3'
    }
    
    # Filter exports by matching resolved class names
    for export in exports:
        class_name, is_export_ref = resolve_class_name(export['class_index'], imports, exports)
        
        if is_export_ref and class_name in target_names:
            print(f"Warning: {filename} - Found target class '{class_name}' via export reference", file=sys.stderr)
        
        if class_name in target_names:
            if debug:
                print(f"\n  Processing: {class_name} instance={export['instance_name']}", file=sys.stderr)
            
            # Parse the property block to extract credentials
            credentials = parse_property_block(
                data, 
                export['serial_offset'], 
                export['serial_size'], 
                names, 
                class_name,
                extract_balance,
                debug
            )
            
            # Check if we found any credentials
            if not credentials:
                # No credentials found - add default/missing values
                if class_name in ['Keypad1', 'Keypad2', 'Keypad3']:
                    results.append(
                        f"{filename}\t{class_name}\t{export['instance_name']}\t"
                        f"\t1234"
                    )
                else:
                    # Computer or ATM
                    results.append(
                        f"{filename}\t{class_name}\t{export['instance_name']}\t"
                        f"MISSING\tMISSING"
                    )
            else:
                # Output results
                for cred in credentials:
                    if cred['type'] == 'user':
                        output = f"{filename}\t{class_name}\t{export['instance_name']}\t{cred['username']}\t{cred['password']}"
                        # Only add balance for ATMs, not computers
                        if extract_balance and class_name == 'ATM' and 'balance' in cred:
                            output += f"\t{cred['balance']}"
                        results.append(output)
                    elif cred['type'] == 'keypad':
                        results.append(
                            f"{filename}\t{class_name}\t{export['instance_name']}\t"
                            f"\t{cred['code']}"
                        )
    
    return results

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <path_or_file> [--balance] [--debug]", file=sys.stderr)
        print("  path_or_file: Directory containing .dx files, or a specific .dx file", file=sys.stderr)
        print("  --balance: Extract ATM account balances (default: off)", file=sys.stderr)
        print("  --debug: Show detailed parsing information", file=sys.stderr)
        sys.exit(1)
    
    input_path = sys.argv[1]
    extract_balance = '--balance' in sys.argv
    debug = '--debug' in sys.argv
    
    if not os.path.exists(input_path):
        print(f"Error: Path '{input_path}' does not exist", file=sys.stderr)
        sys.exit(1)
    
    # Determine if input is a file or directory
    dx_files = []
    if os.path.isfile(input_path):
        if not input_path.lower().endswith('.dx'):
            print(f"Error: File must have .dx extension", file=sys.stderr)
            sys.exit(1)
        dx_files = [input_path]
    elif os.path.isdir(input_path):
        pattern_path = os.path.join(input_path, "*.dx")
        dx_files = glob.glob(pattern_path)
        
        if not dx_files:
            print(f"No .dx files found in '{input_path}'", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"Error: '{input_path}' is neither a file nor directory", file=sys.stderr)
        sys.exit(1)
    
    # Print header with optional balance column
    if extract_balance:
        print("FILENAME\tCLASS_NAME\tINSTANCE_NAME\tUSERNAME\tPASSWORD/CODE\tBALANCE")
    else:
        print("FILENAME\tCLASS_NAME\tINSTANCE_NAME\tUSERNAME\tPASSWORD/CODE")
    
    for filepath in sorted(dx_files):
        results = process_file(filepath, extract_balance, debug)
        for result in results:
            print(result)

if __name__ == "__main__":
    main()