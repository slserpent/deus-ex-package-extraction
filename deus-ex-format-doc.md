# Deus Ex Package File Format Documentation

## Overview

Deus Ex uses the Unreal Engine 1 package format to store game assets including maps (.dx files), textures, sounds, and code. This document details the binary structure of these package files based on reverse engineering efforts.

## File Signature

All Deus Ex package files begin with a 4-byte signature:
```
0xC1 0x83 0x2A 0x9E
```

This signature identifies the file as an Unreal Engine package and should be verified before attempting to parse the file.

## Package Header

The package header is located at offset 0 and contains pointers to the three main data tables.

| Offset | Type  | Field              | Description                                      |
|--------|-------|--------------------|--------------------------------------------------|
| 0x00   | DWORD | Signature          | Always 0x9E2A83C1 (little-endian)               |
| 0x04   | WORD  | Package Version    | File format version (61-69 for UE1)             |
| 0x06   | WORD  | License Mode       | Game-specific license identifier                |
| 0x08   | DWORD | Package Flags      | Global package flags                            |
| 0x0C   | DWORD | Name Count         | Number of entries in name table                 |
| 0x10   | DWORD | Name Table Offset  | Absolute offset to name table                   |
| 0x14   | DWORD | Export Count       | Number of entries in export table               |
| 0x18   | DWORD | Export Table Offset| Absolute offset to export table                 |
| 0x1C   | DWORD | Import Count       | Number of entries in import table               |
| 0x20   | DWORD | Import Table Offset| Absolute offset to import table                 |

*Note: All multi-byte values use little-endian byte order.*

## CompactIndex Format

CompactIndex is a variable-length integer encoding used throughout the package format to save space. It can represent both positive and negative values and uses 1-5 bytes depending on the magnitude.

### Encoding Structure

**First Byte:**
- Bit 7 (0x80): Sign flag (1 = negative)
- Bit 6 (0x40): Continuation flag (1 = more bytes follow)
- Bits 5-0 (0x3F): Lower 6 bits of value

**Bytes 2-4 (if continuation flag set):**
- Bit 7 (0x80): Continuation flag (1 = more bytes follow)
- Bits 6-0 (0x7F): Next 7 bits of value

**Byte 5 (if reached):**
- All 8 bits: Final 8 bits of value (no continuation flag)

### Decoding Algorithm

```python
def read_compact_index(data, offset):
    first_byte = data[offset]
    offset += 1
    
    is_negative = (first_byte & 0x80) != 0
    has_continuation = (first_byte & 0x40) != 0
    value = first_byte & 0x3F
    
    if not has_continuation:
        return -value if is_negative else value, offset
    
    shift = 6
    for byte_num in range(1, 5):
        next_byte = data[offset]
        offset += 1
        
        has_continuation = (next_byte & 0x80) != 0
        byte_value = next_byte & 0x7F if byte_num < 4 else next_byte
        
        value |= (byte_value << shift)
        shift += 7 if byte_num < 4 else 8
        
        if not has_continuation or byte_num == 4:
            break
    
    return -value if is_negative else value, offset
```

### ObjectReference Format

CompactIndex values are also used as ObjectReferences that point to objects in different tables:

- **Negative values**: Reference to import table (e.g., -1 points to imports[0])
- **Positive values**: Reference to export table (e.g., 1 points to exports[0])
- **Zero**: Null reference (no object)

## Name Table

The name table stores all unique string identifiers used throughout the package. Each entry consists of a Pascal-style string followed by flag data.

### Name Entry Format

| Field         | Type  | Description                                    |
|---------------|-------|------------------------------------------------|
| String Length | BYTE  | Length of string including null terminator    |
| String Data   | CHAR[]| Null-terminated ASCII string                   |
| Flags         | DWORD | Name flags (purpose varies)                    |

### Usage

Names are referenced by their zero-based index in the table. The name table is referenced by both the import and export tables for identifying classes, objects, and properties.

## Import Table

The import table defines external objects (classes, packages) that are referenced by objects in this package but defined elsewhere.

### Import Entry Format

| Field             | Type  | Description                                           |
|-------------------|-------|-------------------------------------------------------|
| Class Package     | INDEX | Name table index for the package containing the class |
| Class Name        | INDEX | Name table index for the class type                   |
| Package           | DWORD | ObjectReference to the package (often 0)              |
| Object Name       | INDEX | Name table index for the actual object name           |

*INDEX = CompactIndex*

### Class Resolution

For objects in the export table with negative class references, the import table provides the actual class type. The **Object Name** field typically contains the class name (e.g., "ComputerPersonal", "Texture", "Sound").

## Export Table

The export table defines all objects contained within this package. Each entry describes an object's type, location, and properties.

### Export Entry Format

| Field         | Type  | Description                                              |
|---------------|-------|----------------------------------------------------------|
| Class         | INDEX | ObjectReference to class (negative = import, positive = export) |
| Super         | INDEX | ObjectReference to parent class                          |
| Group         | DWORD | Package group identifier                                 |
| Object Name   | INDEX | Name table index for instance name                       |
| Object Flags  | DWORD | Object-specific flags                                    |
| Serial Size   | INDEX | Size of serialized object data in bytes                  |
| Serial Offset | INDEX | Absolute offset to object data (only if Serial Size > 0) |

*INDEX = CompactIndex*

### Relationship Between Tables

1. Export entry's **Class** field (if negative) → Import table entry
2. Import table's **Object Name** → Name table (provides class type string)
3. Export entry's **Object Name** → Name table (provides instance name string)

**Example:**
```
Export[5].Class = -12  →  Import[11].ObjectName = 153  →  Names[153] = "ComputerPersonal"
Export[5].ObjectName = 847  →  Names[847] = "ComputerPersonal3"
```

This tells us Export[5] is an instance named "ComputerPersonal3" of class type "ComputerPersonal".

## Object Instance Data

Object instance data is located at the **Serial Offset** specified in the export table entry and extends for **Serial Size** bytes.

### Object Header Format

The object data begins with a header structure (approximately 15-17 bytes):

| Field              | Type  | Description                                    |
|--------------------|-------|------------------------------------------------|
| Class Reference 1  | INDEX | Class reference (same as export table)         |
| Class Reference 2  | INDEX | Class reference repeated                       |
| Unknown Flags      | 13 bytes | Purpose unclear, likely object state flags  |

After this header, the property list begins.

## Property Format

Object properties are serialized as a sequence of tagged values. Each property consists of:

### Property Entry Structure

| Field          | Type  | Description                                          |
|----------------|-------|------------------------------------------------------|
| Property Name  | INDEX | Name table index identifying the property            |
| Property Flags | BYTE  | Flags controlling property structure                 |
| Property Data  | varies| Property-specific data                               |

### Property Flags (1 byte)

The property flags byte encodes both type information and structural flags:

| Bits  | Purpose          | Description                                    |
|-------|------------------|------------------------------------------------|
| 0-3   | Type Enum        | Property type (e.g., 0x0A = struct, 0x05 = string) |
| 4     | Struct Size Flag | If set (0x10), struct size byte follows        |
| 5-6   | Unknown          | Purpose unclear                                |
| 7     | Array Index Flag | If set (0x80), array index byte follows        |

### Common Property Patterns

#### Simple String Property
```
[Property Name INDEX]
[Flags: 0x05]  // String type, no struct size, no array index
[String Length BYTE]
[String Data with null terminator]
```

#### Struct Property
```
[Property Name INDEX]
[Flags: 0x1A]  // Struct type (0x0A) + struct size flag (0x10)
[Struct Type INDEX]  // References name table for struct type
[Struct Size BYTE]
[Struct Data...]
```

#### Array Element (not first)
```
[Property Name INDEX]
[Flags: 0x9A]  // Struct type (0x0A) + struct size (0x10) + array index (0x80)
[Struct Type INDEX]
[Struct Size BYTE]
[Array Index BYTE]  // Position in array (0 = first, 1 = second, etc.)
[Struct Data...]
```

**Important Note:** The array index byte is **only present for elements after the first** (index >= 1). The first array element (index 0) does not include an array index byte even if it's part of an array.

### Property List Termination

The property list ends when a property name resolves to "None" (case-insensitive) in the name table, or when the serial size boundary is reached.

## Example: Decoding a Computer Object

Given an export entry for a ComputerPersonal object:

1. **Find the class**: Export.Class = -5 → Import[4].ObjectName = 89 → Names[89] = "ComputerPersonal"
2. **Find instance name**: Export.ObjectName = 234 → Names[234] = "Computer0"
3. **Locate object data**: Jump to Export.SerialOffset
4. **Parse header**: Skip CompactIndex + CompactIndex + 13 bytes
5. **Parse properties**:
   - Read property name INDEX → look up in Names table
   - Read flags byte → determine structure
   - Read property data based on flags
   - Repeat until "None" property or end of Serial Size

### Example Property: userList Array of sUserInfo Structs

```
Offset  Data                Description
------  ------------------  -----------
0x00    [INDEX: 203]        Property name = "userList"
0x01    0x1A               Flags: struct type (0x0A) + struct size (0x10)
0x02    [INDEX: 205]        Struct type = "sUserInfo"
0x03    0x18               Struct size = 24 bytes
0x04    0x07               Username string length
0x05    "admin\0"          Username (7 bytes)
0x0C    0x09               Password string length
0x0D    "password\0"       Password (9 bytes)
0x16    [4 bytes]          Integer (e.g., balance for ATM)
---     Second element (if exists)
0x1A    [INDEX: 203]        Property name = "userList" (same)
0x1B    0x9A               Flags: struct (0x0A) + size (0x10) + array (0x80)
0x1C    [INDEX: 205]        Struct type = "sUserInfo"
0x1D    0x18               Struct size = 24 bytes
0x1E    0x01               Array index = 1 (second element)
0x1F    ...                Second struct data
```

## Tips for Implementation

1. **Always validate the signature** before parsing
2. **Use CompactIndex decoding** for all INDEX fields
3. **Handle negative ObjectReferences** by looking up imports
4. **Check property flags carefully** - struct size and array index are conditional
5. **The first array element has no array index byte**, but subsequent elements do
6. **Property parsing is challenging** - consider brute-force searching for known property names if full parsing proves difficult
7. **Different object classes have different property structures** - properties are class-specific

## References

- Original documentation by Antonio Cordero Balcázar (acordero.org)
- UnrealWiki Package File Format documentation
- Reverse engineering of Deus Ex .dx map files
