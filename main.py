#!/usr/bin/env python3
"""
eBPF Instruction Set Simulator for Hardware Verification

This simulator parses LLVM-compiled eBPF relocatable object files (.o) and generates
execution traces similar to RISC-V ISS output format.

Only handles relocatable ELF files (ET_REL), not executables.

Based on eBPF ISA v1.0 specification:
https://www.ietf.org/archive/id/draft-thaler-bpf-isa-00.html
"""

import struct
import sys
import argparse
from typing import Dict, List, Tuple, Optional


class eBPFSimulator:
    """eBPF Instruction Set Simulator"""
    
    def __init__(self):
        # eBPF has 11 registers: R0-R10 (all 64-bit)
        # R0: return value
        # R1-R5: function arguments (caller-saved)
        # R6-R9: callee-saved
        # R10: read-only frame pointer (stack)
        self.regs = [0] * 11
        self.stack = bytearray(512)  # 512 bytes of stack space
        self.memory: Dict[int, int] = {}  # Memory for load/store operations
        self.pc = 0
        self.instructions: List[Tuple[int, bytes]] = []
        
    def reset(self):
        """Reset simulator state"""
        self.regs = [0] * 11
        self.stack = bytearray(512)
        self.memory = {}
        self.pc = 0
        
    def parse_elf(self, filename: str) -> List[Tuple[int, bytes]]:
        """Parse relocatable ELF file and extract eBPF instructions from .text section
        
        Only handles relocatable object files (ET_REL). Section addresses are
        typically 0 or relative, so instructions start at address 0 within the section.
        """
        with open(filename, 'rb') as f:
            data = f.read()
            
        if data[:4] != b'\x7fELF':
            raise ValueError("Not a valid ELF file")
            
        ei_data = data[5]
        little_endian = ei_data == 1
        
        if data[4] == 1:  # 32-bit
            raise ValueError("32-bit ELF not supported")
        elif data[4] != 2:  # 64-bit
            raise ValueError("Invalid ELF class")
        
        # ELF64 header is 64 bytes
        if len(data) < 64:
            raise ValueError(f"File too small to contain ELF64 header (need 64 bytes, got {len(data)})")
        
        # Check file type - must be ET_REL (relocatable) = 1
        # e_type is at offset 16 (2 bytes)
        e_type_slice = data[16:18]
        if len(e_type_slice) != 2:
            raise ValueError("Failed to read e_type from ELF header")
        
        if little_endian:
            e_type = struct.unpack('<H', e_type_slice)[0]
        else:
            e_type = struct.unpack('>H', e_type_slice)[0]
        
        # ET_REL = 1 (Relocatable file)
        if e_type != 1:
            raise ValueError(f"Expected relocatable file (ET_REL=1), got file type {e_type}")
            
        # Verify we have enough data for all reads
        if len(data) < 64:
            raise ValueError(f"File too small: need at least 64 bytes for ELF header, got {len(data)}")
        
        # Read e_shoff (8 bytes at offset 40)
        e_shoff_slice = data[40:48]
        if len(e_shoff_slice) != 8:
            raise ValueError(f"Failed to read e_shoff: need 8 bytes, got {len(e_shoff_slice)}")
        
        # Read e_shentsize (2 bytes at offset 58)
        e_shentsize_slice = data[58:60]
        if len(e_shentsize_slice) != 2:
            raise ValueError(f"Failed to read e_shentsize: need 2 bytes, got {len(e_shentsize_slice)}")
        
        # Read e_shnum (2 bytes at offset 60)
        e_shnum_slice = data[60:62]
        if len(e_shnum_slice) != 2:
            raise ValueError(f"Failed to read e_shnum: need 2 bytes, got {len(e_shnum_slice)}")
        
        # Read e_shstrndx (2 bytes at offset 62)
        e_shstrndx_slice = data[62:64]
        if len(e_shstrndx_slice) != 2:
            raise ValueError(f"Failed to read e_shstrndx: need 2 bytes, got {len(e_shstrndx_slice)}")
        
        try:
            if little_endian:
                e_shoff = struct.unpack('<Q', e_shoff_slice)[0]
                e_shentsize = struct.unpack('<H', e_shentsize_slice)[0]
                e_shnum = struct.unpack('<H', e_shnum_slice)[0]
                e_shstrndx = struct.unpack('<H', e_shstrndx_slice)[0]
            else:
                e_shoff = struct.unpack('>Q', e_shoff_slice)[0]
                e_shentsize = struct.unpack('>H', e_shentsize_slice)[0]
                e_shnum = struct.unpack('>H', e_shnum_slice)[0]
                e_shstrndx = struct.unpack('>H', e_shstrndx_slice)[0]
        except struct.error as e:
            raise ValueError(f"Error unpacking ELF header fields: {e}")
            
        if e_shoff == 0:
            raise ValueError("No section headers found")
            
        # Read section string table
        if e_shstrndx >= e_shnum:
            raise ValueError(f"Invalid section header string table index: {e_shstrndx}")
        shstrtab_sh = e_shoff + e_shstrndx * e_shentsize
        if shstrtab_sh + 64 > len(data):
            raise ValueError(f"Section header string table header extends beyond file (need {shstrtab_sh + 64}, have {len(data)})")
        # Read sh_offset (offset 24) and sh_size (offset 32) from section header
        # Need 16 bytes (QQ = 8+8) starting at offset 24
        shstrtab_data_start = shstrtab_sh + 24
        shstrtab_data_end = shstrtab_sh + 40
        if shstrtab_data_end > len(data):
            raise ValueError(f"Section header string table header extends beyond file (need {shstrtab_data_end}, have {len(data)})")
        shstrtab_slice = data[shstrtab_data_start:shstrtab_data_end]
        if len(shstrtab_slice) < 16:
            raise ValueError(f"Not enough data to read section header string table (need 16 bytes, got {len(shstrtab_slice)})")
        if little_endian:
            sh_offset, sh_size = struct.unpack('<QQ', shstrtab_slice)
        else:
            sh_offset, sh_size = struct.unpack('>QQ', shstrtab_slice)
        if sh_offset + sh_size > len(data):
            raise ValueError("Section header string table extends beyond file")
        shstrtab = data[sh_offset:sh_offset+sh_size]
        
        # Find .text section
        instructions = []
        found_sections = []
        for i in range(e_shnum):
            sh_offset_pos = e_shoff + i * e_shentsize
            if sh_offset_pos + 40 > len(data):
                found_sections.append((f"<header_{i}_out_of_bounds>", 0, 0))
                continue
            # Read section header fields: sh_name (4), sh_type (4), sh_flags (8), sh_addr (8), sh_offset (8), sh_size (8) = 40 bytes
            sh_slice = data[sh_offset_pos:sh_offset_pos+40]
            if len(sh_slice) < 40:
                found_sections.append((f"<header_{i}_incomplete>", 0, 0))
                continue
            if little_endian:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack('<IIQQQQ', sh_slice)
            else:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack('>IIQQQQ', sh_slice)

                
            # Get section name
            if sh_name >= len(shstrtab):
                section_name = f"<invalid_offset_{sh_name}>"
            else:
                # Find null terminator starting from sh_name
                name_end = sh_name
                while name_end < len(shstrtab) and shstrtab[name_end] != 0:
                    name_end += 1
                section_name = shstrtab[sh_name:name_end].decode('ascii', errors='ignore')
                # Handle empty name (NULL section)
                if not section_name:
                    section_name = "<null>"
            
            found_sections.append((section_name, sh_type, sh_size))
            
            # Look for .text section (SHT_PROGBITS = 1, but be flexible)
            if section_name == '.text' and sh_size > 0:
                # For relocatable files, sh_addr is typically 0, so instructions start at 0
                if sh_offset + sh_size <= len(data):
                    section_data = data[sh_offset:sh_offset+sh_size]
                    # In relocatable files, use sh_addr as base (typically 0)
                    # Instructions are addressed relative to the section start
                    addr = sh_addr if sh_addr != 0 else 0
                    
                    # eBPF instructions are 64-bit (8 bytes) or 128-bit (16 bytes) for wide
                    idx = 0
                    while idx < len(section_data):
                        if idx + 8 > len(section_data):
                            break
                            
                        inst_bytes = section_data[idx:idx+8]
                        
                        # Check if this is a wide instruction (opcode 0x18 for LD64)
                        opcode = inst_bytes[0]
                        is_wide = (opcode == 0x18)  # LD64 uses wide encoding
                        
                        if is_wide and idx + 16 <= len(section_data):
                            inst_bytes = section_data[idx:idx+16]
                            instructions.append((addr, inst_bytes))
                            idx += 16
                            addr += 16
                        else:
                            instructions.append((addr, inst_bytes))
                            idx += 8
                            addr += 8
                            
                    break
                
        if not instructions:
            sections_info = ", ".join([f"{name}(type={sh_type},size={sh_size})" for name, sh_type, sh_size in found_sections])
            raise ValueError(f"No .text section found or no instructions extracted. Found sections: {sections_info}")
            
        return instructions
        
    def _format_offset(self, offset: int) -> str:
        """Format offset as signed value for display (matches objdump format)
        
        The offset is already sign-extended to 32 bits, so we just need to
        convert it to a Python signed int and format it.
        """
        # Convert to Python signed int (handle 32-bit sign extension)
        if offset & 0x80000000:
            offset_signed = offset - 0x100000000
        else:
            offset_signed = offset & 0xFFFFFFFF
        
        if offset_signed < 0:
            return f" - 0x{abs(offset_signed):x}"
        elif offset_signed > 0:
            return f" + 0x{offset_signed:x}"
        else:
            return ""
    
    def decode_instruction(self, inst_bytes: bytes, addr: int) -> str:
        """Decode eBPF instruction to assembly format"""
        if len(inst_bytes) < 8:
            return "invalid"
            
        # eBPF instruction format (little-endian):
        # opcode:8 src_reg:4 dst_reg:4 offset:16 imm:32
        # Read bytes directly instead of using struct.unpack
        opcode = inst_bytes[0]
        regs = inst_bytes[1]
        offset = inst_bytes[2] | (inst_bytes[3] << 8)  # little-endian 16-bit
        imm = inst_bytes[4] | (inst_bytes[5] << 8) | (inst_bytes[6] << 16) | (inst_bytes[7] << 24)  # little-endian 32-bit
        
        src_reg = (regs >> 4) & 0xf
        dst_reg = regs & 0xf
        
        # Check for wide instruction
        is_wide = len(inst_bytes) == 16
        if is_wide:
            # Wide instruction: second 64 bits contain high 32 bits of immediate
            imm_high = inst_bytes[12] | (inst_bytes[13] << 8) | (inst_bytes[14] << 16) | (inst_bytes[15] << 24)
            imm = (imm_high << 32) | (imm & 0xFFFFFFFF)
            
        # Sign extend offset and imm
        if offset & 0x8000:
            offset = offset | 0xFFFF0000
        if imm & 0x80000000:
            imm = imm | 0xFFFFFFFF00000000
            
        # eBPF opcode format: the full byte encodes class and operation
        # Check specific opcodes first (these are the common ones)
        if opcode == 0xb7:  # MOV immediate (r_dst = imm)
            return f"r{dst_reg} = {imm}"
        elif opcode == 0xbf:  # MOV register (r_dst = r_src)
            return f"r{dst_reg} = r{src_reg}"
        elif opcode == 0x95:  # EXIT
            return "exit"
        
        # Instruction classes (bits 0-2)
        inst_class = opcode & 0x07
        op = opcode & 0xf0  # Operation (bits 4-7)
        
        # Decode based on instruction class
        if inst_class == 0x00:  # ALU/ALU64
            return self._decode_alu(op, src_reg, dst_reg, offset, imm)
        elif inst_class == 0x01:  # ALU immediate (32-bit)
            return self._decode_alu_imm(op, src_reg, dst_reg, offset, imm)
        elif inst_class == 0x07:  # ALU64 immediate (64-bit)
            return self._decode_alu_imm(op, src_reg, dst_reg, offset, imm)
        elif inst_class == 0x04:  # JMP
            return self._decode_jmp(op, src_reg, dst_reg, offset, imm)
        elif inst_class == 0x05:  # JMP32
            return self._decode_jmp32(op, src_reg, dst_reg, offset, imm)
        elif inst_class == 0x18:  # LD64 (64-bit immediate)
            if is_wide:
                return f"r{dst_reg} = {imm}"
            return f"ld64(op={opcode:02x})"
        elif inst_class == 0x20:  # LD (indirect)
            size = (opcode >> 3) & 0x3
            size_map = {0: "8", 1: "16", 2: "32", 3: "64"}
            size_str = size_map.get(size, "?")
            offset_str = self._format_offset(offset)
            return f"r{dst_reg} = *(u{size_str}*)(r{src_reg}{offset_str})"
        elif inst_class == 0x40:  # ST (immediate)
            size = (opcode >> 3) & 0x3
            size_map = {0: "8", 1: "16", 2: "32", 3: "64"}
            size_str = size_map.get(size, "?")
            offset_str = self._format_offset(offset)
            return f"*(u{size_str}*)(r{dst_reg}{offset_str}) = {imm}"
        elif opcode == 0x63:  # STX (32-bit)
            offset_str = self._format_offset(offset)
            return f"*(u32 *)(r{dst_reg}{offset_str}) = r{src_reg}"
        elif opcode == 0x73:  # STX (64-bit)
            offset_str = self._format_offset(offset)
            return f"*(u64 *)(r{dst_reg}{offset_str}) = r{src_reg}"
        elif opcode == 0x6b:  # STX (16-bit)
            offset_str = self._format_offset(offset)
            return f"*(u16 *)(r{dst_reg}{offset_str}) = r{src_reg}"
        elif opcode == 0x7b:  # STX (8-bit)
            offset_str = self._format_offset(offset)
            return f"*(u8 *)(r{dst_reg}{offset_str}) = r{src_reg}"
        elif inst_class == 0x50:  # LDX
            size = (opcode >> 3) & 0x3
            size_map = {0: "8", 1: "16", 2: "32", 3: "64"}
            size_str = size_map.get(size, "?")
            offset_str = self._format_offset(offset)
            return f"r{dst_reg} = *(u{size_str}*)(r{src_reg}{offset_str})"
        elif inst_class == 0x60:  # LD (immediate)
            return f"r{dst_reg} = {imm}"
        elif inst_class == 0x61:  # LD (immediate, 32-bit)
            return f"r{dst_reg} = {imm & 0xFFFFFFFF}"
        elif inst_class == 0x62:  # LD (immediate, 16-bit)
            return f"r{dst_reg} = {imm & 0xFFFF}"
        elif inst_class == 0xdc:  # Endianness conversion
            size = (opcode >> 3) & 0x3
            if size == 0:  # 16-bit
                return f"r{dst_reg} = be16 r{dst_reg}"
            elif size == 1:  # 32-bit
                return f"r{dst_reg} = be32 r{dst_reg}"
            elif size == 2:  # 64-bit
                return f"r{dst_reg} = be64 r{dst_reg}"
        elif inst_class == 0xdd:  # JMP signed
            if op == 0x00:  # JSLE
                return f"if r{dst_reg} s<= r{src_reg} goto +{offset}"
        elif inst_class == 0xde:  # JMP32 signed
            if op == 0x00:  # JSLE
                return f"if (s32)r{dst_reg} s<= (s32)r{src_reg} goto +{offset}"
        else:
            return f"unknown(op={opcode:02x})"
            
    def _decode_alu(self, op: int, src_reg: int, dst_reg: int, offset: int, imm: int) -> str:
        """Decode ALU/ALU64 instructions"""
        if op == 0x00:  # ADD
            return f"r{dst_reg} += r{src_reg}"
        elif op == 0x10:  # SUB
            return f"r{dst_reg} -= r{src_reg}"
        elif op == 0x20:  # MUL
            return f"r{dst_reg} *= r{src_reg}"
        elif op == 0x30:  # DIV
            return f"r{dst_reg} /= r{src_reg}"
        elif op == 0x40:  # OR
            return f"r{dst_reg} |= r{src_reg}"
        elif op == 0x50:  # AND
            return f"r{dst_reg} &= r{src_reg}"
        elif op == 0x60:  # LSH
            return f"r{dst_reg} <<= r{src_reg}"
        elif op == 0x70:  # RSH
            return f"r{dst_reg} >>= r{src_reg}"
        elif op == 0x80:  # NEG
            return f"r{dst_reg} = -r{dst_reg}"
        elif op == 0x90:  # MOD
            return f"r{dst_reg} %= r{src_reg}"
        elif op == 0xa0:  # XOR
            return f"r{dst_reg} ^= r{src_reg}"
        elif op == 0xb0:  # MOV
            return f"r{dst_reg} = r{src_reg}"
        elif op == 0xc0:  # ARSH
            return f"r{dst_reg} s>>= r{src_reg}"
        elif op == 0xd0:  # END (endianness)
            return f"r{dst_reg} = be r{dst_reg}"
        return f"alu(op={op:02x})"
        
    def _decode_alu_imm(self, op: int, src_reg: int, dst_reg: int, offset: int, imm: int) -> str:
        """Decode ALU immediate instructions"""
        if op == 0x00:  # ADD
            return f"r{dst_reg} += {imm}"
        elif op == 0x10:  # SUB
            return f"r{dst_reg} -= {imm}"
        elif op == 0x20:  # MUL
            return f"r{dst_reg} *= {imm}"
        elif op == 0x30:  # DIV
            return f"r{dst_reg} /= {imm}"
        elif op == 0x40:  # OR
            return f"r{dst_reg} |= {imm}"
        elif op == 0x50:  # AND
            return f"r{dst_reg} &= {imm}"
        elif op == 0x60:  # LSH
            return f"r{dst_reg} <<= {imm}"
        elif op == 0x70:  # RSH
            return f"r{dst_reg} >>= {imm}"
        elif op == 0x90:  # MOD
            return f"r{dst_reg} %= {imm}"
        elif op == 0xa0:  # XOR
            return f"r{dst_reg} ^= {imm}"
        elif op == 0xb0:  # MOV
            return f"r{dst_reg} = {imm}"
        elif op == 0xc0:  # ARSH
            return f"r{dst_reg} s>>= {imm}"
        return f"alu_imm(op={op:02x})"
        
    def _decode_jmp(self, op: int, src_reg: int, dst_reg: int, offset: int, imm: int) -> str:
        """Decode JMP instructions"""
        if op == 0x00:  # JEQ
            return f"if r{dst_reg} == r{src_reg} goto +{offset}"
        elif op == 0x10:  # JGT
            return f"if r{dst_reg} > r{src_reg} goto +{offset}"
        elif op == 0x20:  # JGE
            return f"if r{dst_reg} >= r{src_reg} goto +{offset}"
        elif op == 0x30:  # JSET
            return f"if r{dst_reg} & r{src_reg} goto +{offset}"
        elif op == 0x40:  # JNE
            return f"if r{dst_reg} != r{src_reg} goto +{offset}"
        elif op == 0x50:  # JSGT
            return f"if r{dst_reg} s> r{src_reg} goto +{offset}"
        elif op == 0x60:  # JSGE
            return f"if r{dst_reg} s>= r{src_reg} goto +{offset}"
        elif op == 0x70:  # CALL
            return f"call {imm}"
        elif op == 0x80:  # EXIT
            return "exit"
        elif op == 0x90:  # JLT
            return f"if r{dst_reg} < r{src_reg} goto +{offset}"
        elif op == 0xa0:  # JLE
            return f"if r{dst_reg} <= r{src_reg} goto +{offset}"
        elif op == 0xb0:  # JSLT
            return f"if r{dst_reg} s< r{src_reg} goto +{offset}"
        elif op == 0xc0:  # JSLE
            return f"if r{dst_reg} s<= r{src_reg} goto +{offset}"
        return f"jmp(op={op:02x})"
        
    def _decode_jmp32(self, op: int, src_reg: int, dst_reg: int, offset: int, imm: int) -> str:
        """Decode JMP32 instructions (32-bit comparisons)"""
        if op == 0x00:  # JEQ
            return f"if (u32)r{dst_reg} == (u32)r{src_reg} goto +{offset}"
        elif op == 0x10:  # JGT
            return f"if (u32)r{dst_reg} > (u32)r{src_reg} goto +{offset}"
        elif op == 0x20:  # JGE
            return f"if (u32)r{dst_reg} >= (u32)r{src_reg} goto +{offset}"
        elif op == 0x30:  # JSET
            return f"if (u32)r{dst_reg} & (u32)r{src_reg} goto +{offset}"
        elif op == 0x40:  # JNE
            return f"if (u32)r{dst_reg} != (u32)r{src_reg} goto +{offset}"
        elif op == 0x50:  # JSGT
            return f"if (s32)r{dst_reg} s> (s32)r{src_reg} goto +{offset}"
        elif op == 0x60:  # JSGE
            return f"if (s32)r{dst_reg} s>= (s32)r{src_reg} goto +{offset}"
        elif op == 0x90:  # JLT
            return f"if (u32)r{dst_reg} < (u32)r{src_reg} goto +{offset}"
        elif op == 0xa0:  # JLE
            return f"if (u32)r{dst_reg} <= (u32)r{src_reg} goto +{offset}"
        elif op == 0xb0:  # JSLT
            return f"if (s32)r{dst_reg} s< (s32)r{src_reg} goto +{offset}"
        elif op == 0xc0:  # JSLE
            return f"if (s32)r{dst_reg} s<= (s32)r{src_reg} goto +{offset}"
        return f"jmp32(op={op:02x})"
        
    def execute_instruction(self, inst_bytes: bytes, addr: int) -> Optional[str]:
        """Execute a single eBPF instruction and return trace update string"""
        if len(inst_bytes) < 8:
            return None
            
        # Read bytes directly instead of using struct.unpack
        opcode = inst_bytes[0]
        regs = inst_bytes[1]
        offset = inst_bytes[2] | (inst_bytes[3] << 8)  # little-endian 16-bit
        imm = inst_bytes[4] | (inst_bytes[5] << 8) | (inst_bytes[6] << 16) | (inst_bytes[7] << 24)  # little-endian 32-bit
        
        src_reg = (regs >> 4) & 0xf
        dst_reg = regs & 0xf
        
        is_wide = len(inst_bytes) == 16
        if is_wide:
            imm_high = inst_bytes[12] | (inst_bytes[13] << 8) | (inst_bytes[14] << 16) | (inst_bytes[15] << 24)
            imm = (imm_high << 32) | (imm & 0xFFFFFFFF)
            
        # Sign extend
        if offset & 0x8000:
            offset = offset | 0xFFFF0000
        if imm & 0x80000000:
            imm = imm | 0xFFFFFFFF00000000
            
        updates = []
        
        # Handle specific opcodes first
        if opcode == 0xb7:  # MOV immediate (r_dst = imm)
            self.regs[dst_reg] = imm & 0xFFFFFFFFFFFFFFFF
            updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
        elif opcode == 0xbf:  # MOV register (r_dst = r_src)
            self.regs[dst_reg] = self.regs[src_reg]
            updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
        elif opcode == 0x95:  # EXIT
            return "exit"
        elif opcode == 0x63:  # STX (32-bit): *(u32 *)(r_dst + offset) = r_src
            addr_val = (self.regs[dst_reg] + offset) & 0xFFFFFFFFFFFFFFFF
            val = self.regs[src_reg]
            if addr_val < len(self.stack):
                struct.pack_into('<I', self.stack, addr_val, val & 0xFFFFFFFF)
            else:
                self.memory[addr_val] = val & 0xFFFFFFFFFFFFFFFF
            updates.append(f"mem[0x{addr_val:016X}]=0x{val:016X}")
        else:
            inst_class = opcode & 0x07
            op = opcode & 0xf0
            
            if inst_class == 0x00:  # ALU/ALU64
                if op == 0x00:  # ADD
                    self.regs[dst_reg] = (self.regs[dst_reg] + self.regs[src_reg]) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x10:  # SUB
                    self.regs[dst_reg] = (self.regs[dst_reg] - self.regs[src_reg]) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x20:  # MUL
                    self.regs[dst_reg] = (self.regs[dst_reg] * self.regs[src_reg]) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x30:  # DIV
                    if self.regs[src_reg] != 0:
                        self.regs[dst_reg] = (self.regs[dst_reg] // self.regs[src_reg]) & 0xFFFFFFFFFFFFFFFF
                        updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x40:  # OR
                    self.regs[dst_reg] = (self.regs[dst_reg] | self.regs[src_reg]) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x50:  # AND
                    self.regs[dst_reg] = (self.regs[dst_reg] & self.regs[src_reg]) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x60:  # LSH
                    self.regs[dst_reg] = (self.regs[dst_reg] << (self.regs[src_reg] & 0x3F)) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x70:  # RSH
                    self.regs[dst_reg] = (self.regs[dst_reg] >> (self.regs[src_reg] & 0x3F)) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x80:  # NEG
                    self.regs[dst_reg] = (-self.regs[dst_reg]) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x90:  # MOD
                    if self.regs[src_reg] != 0:
                        self.regs[dst_reg] = (self.regs[dst_reg] % self.regs[src_reg]) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0xa0:  # XOR
                    self.regs[dst_reg] = (self.regs[dst_reg] ^ self.regs[src_reg]) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0xb0:  # MOV
                    self.regs[dst_reg] = self.regs[src_reg]
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0xc0:  # ARSH
                    val = self.regs[dst_reg]
                    shift = self.regs[src_reg] & 0x3F
                    if val & 0x8000000000000000:
                        self.regs[dst_reg] = ((val >> shift) | ((0xFFFFFFFFFFFFFFFF << (64 - shift)) if shift > 0 else 0)) & 0xFFFFFFFFFFFFFFFF
                    else:
                        self.regs[dst_reg] = (val >> shift) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0xd0:  # END (endianness)
                    size = (opcode >> 3) & 0x3
                    val = self.regs[dst_reg]
                    if size == 0:  # 16-bit
                        self.regs[dst_reg] = ((val & 0xFF) << 8) | ((val >> 8) & 0xFF)
                    elif size == 1:  # 32-bit
                        self.regs[dst_reg] = ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) | ((val >> 8) & 0xFF00) | ((val >> 24) & 0xFF)
                    elif size == 2:  # 64-bit
                        self.regs[dst_reg] = struct.unpack('<Q', struct.pack('>Q', val))[0]
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                    
            elif inst_class == 0x01:  # ALU/ALU64 immediate
                if op == 0x00:  # ADD
                    self.regs[dst_reg] = (self.regs[dst_reg] + imm) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x10:  # SUB
                    self.regs[dst_reg] = (self.regs[dst_reg] - imm) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x20:  # MUL
                    self.regs[dst_reg] = (self.regs[dst_reg] * imm) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x30:  # DIV
                    if imm != 0:
                        self.regs[dst_reg] = (self.regs[dst_reg] // imm) & 0xFFFFFFFFFFFFFFFF
                        updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x40:  # OR
                    self.regs[dst_reg] = (self.regs[dst_reg] | imm) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x50:  # AND
                    self.regs[dst_reg] = (self.regs[dst_reg] & imm) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x60:  # LSH
                    self.regs[dst_reg] = (self.regs[dst_reg] << (imm & 0x3F)) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x70:  # RSH
                    self.regs[dst_reg] = (self.regs[dst_reg] >> (imm & 0x3F)) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x90:  # MOD
                    if imm != 0:
                        self.regs[dst_reg] = (self.regs[dst_reg] % imm) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0xa0:  # XOR
                    self.regs[dst_reg] = (self.regs[dst_reg] ^ imm) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0xb0:  # MOV
                    self.regs[dst_reg] = imm & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0xc0:  # ARSH
                    val = self.regs[dst_reg]
                    shift = imm & 0x3F
                    if val & 0x8000000000000000:
                        self.regs[dst_reg] = ((val >> shift) | ((0xFFFFFFFFFFFFFFFF << (64 - shift)) if shift > 0 else 0)) & 0xFFFFFFFFFFFFFFFF
                    else:
                        self.regs[dst_reg] = (val >> shift) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                    
            elif inst_class == 0x07:  # ALU64 immediate (64-bit)
                if op == 0x00:  # ADD
                    self.regs[dst_reg] = (self.regs[dst_reg] + imm) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x10:  # SUB
                    self.regs[dst_reg] = (self.regs[dst_reg] - imm) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x20:  # MUL
                    self.regs[dst_reg] = (self.regs[dst_reg] * imm) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x30:  # DIV
                    if imm != 0:
                        self.regs[dst_reg] = (self.regs[dst_reg] // imm) & 0xFFFFFFFFFFFFFFFF
                        updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x40:  # OR
                    self.regs[dst_reg] = (self.regs[dst_reg] | imm) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x50:  # AND
                    self.regs[dst_reg] = (self.regs[dst_reg] & imm) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x60:  # LSH
                    self.regs[dst_reg] = (self.regs[dst_reg] << (imm & 0x3F)) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x70:  # RSH
                    self.regs[dst_reg] = (self.regs[dst_reg] >> (imm & 0x3F)) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0x90:  # MOD
                    if imm != 0:
                        self.regs[dst_reg] = (self.regs[dst_reg] % imm) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0xa0:  # XOR
                    self.regs[dst_reg] = (self.regs[dst_reg] ^ imm) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0xb0:  # MOV
                    self.regs[dst_reg] = imm & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                elif op == 0xc0:  # ARSH
                    val = self.regs[dst_reg]
                    shift = imm & 0x3F
                    if val & 0x8000000000000000:
                        self.regs[dst_reg] = ((val >> shift) | ((0xFFFFFFFFFFFFFFFF << (64 - shift)) if shift > 0 else 0)) & 0xFFFFFFFFFFFFFFFF
                    else:
                        self.regs[dst_reg] = (val >> shift) & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                    
            elif inst_class == 0x18:  # LD64 (64-bit immediate)
                if is_wide:
                    self.regs[dst_reg] = imm & 0xFFFFFFFFFFFFFFFF
                    updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                    
            elif inst_class == 0x20:  # LD indirect
                size = (opcode >> 3) & 0x3
                addr_val = (self.regs[src_reg] + offset) & 0xFFFFFFFFFFFFFFFF
                val = 0
                if addr_val < len(self.stack):
                    if size == 0:  # 8-bit
                        val = self.stack[addr_val]
                    elif size == 1:  # 16-bit
                        val = struct.unpack('<H', self.stack[addr_val:addr_val+2])[0]
                    elif size == 2:  # 32-bit
                        val = struct.unpack('<I', self.stack[addr_val:addr_val+4])[0]
                    else:  # 64-bit
                        val = struct.unpack('<Q', self.stack[addr_val:addr_val+8])[0]
                elif addr_val in self.memory:
                    val = self.memory[addr_val]
                self.regs[dst_reg] = val & 0xFFFFFFFFFFFFFFFF
                updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                    
            elif inst_class == 0x40:  # ST immediate
                size = (opcode >> 3) & 0x3
                addr_val = (self.regs[dst_reg] + offset) & 0xFFFFFFFFFFFFFFFF
                if addr_val < len(self.stack):
                    if size == 0:  # 8-bit
                        self.stack[addr_val] = imm & 0xFF
                    elif size == 1:  # 16-bit
                        struct.pack_into('<H', self.stack, addr_val, imm & 0xFFFF)
                    elif size == 2:  # 32-bit
                        struct.pack_into('<I', self.stack, addr_val, imm & 0xFFFFFFFF)
                    else:  # 64-bit
                        struct.pack_into('<Q', self.stack, addr_val, imm & 0xFFFFFFFFFFFFFFFF)
                else:
                    self.memory[addr_val] = imm & 0xFFFFFFFFFFFFFFFF
                updates.append(f"mem[0x{addr_val:016X}]=0x{imm:016X}")
                    
            elif inst_class == 0x50:  # LDX
                size = (opcode >> 3) & 0x3
                addr_val = (self.regs[src_reg] + offset) & 0xFFFFFFFFFFFFFFFF
                val = 0
                if addr_val < len(self.stack):
                    if size == 0:  # 8-bit
                        val = self.stack[addr_val]
                    elif size == 1:  # 16-bit
                        val = struct.unpack('<H', self.stack[addr_val:addr_val+2])[0]
                    elif size == 2:  # 32-bit
                        val = struct.unpack('<I', self.stack[addr_val:addr_val+4])[0]
                    else:  # 64-bit
                        val = struct.unpack('<Q', self.stack[addr_val:addr_val+8])[0]
                elif addr_val in self.memory:
                    val = self.memory[addr_val]
                self.regs[dst_reg] = val & 0xFFFFFFFFFFFFFFFF
                updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                    
            elif inst_class == 0x60:  # LD immediate
                self.regs[dst_reg] = imm & 0xFFFFFFFFFFFFFFFF
                updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
            elif inst_class == 0x61:  # LD immediate 32-bit
                self.regs[dst_reg] = imm & 0xFFFFFFFF
                updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
            elif inst_class == 0x62:  # LD immediate 16-bit
                self.regs[dst_reg] = imm & 0xFFFF
                updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
                    
            elif inst_class == 0x04:  # JMP
                jump_taken = False
                if op == 0x00:  # JEQ
                    jump_taken = (self.regs[dst_reg] == self.regs[src_reg])
                elif op == 0x10:  # JGT
                    jump_taken = (self.regs[dst_reg] > self.regs[src_reg])
                elif op == 0x20:  # JGE
                    jump_taken = (self.regs[dst_reg] >= self.regs[src_reg])
                elif op == 0x30:  # JSET
                    jump_taken = ((self.regs[dst_reg] & self.regs[src_reg]) != 0)
                elif op == 0x40:  # JNE
                    jump_taken = (self.regs[dst_reg] != self.regs[src_reg])
                elif op == 0x50:  # JSGT
                    dst_signed = self.regs[dst_reg] if not (self.regs[dst_reg] & 0x8000000000000000) else (self.regs[dst_reg] - 0x10000000000000000)
                    src_signed = self.regs[src_reg] if not (self.regs[src_reg] & 0x8000000000000000) else (self.regs[src_reg] - 0x10000000000000000)
                    jump_taken = (dst_signed > src_signed)
                elif op == 0x60:  # JSGE
                    dst_signed = self.regs[dst_reg] if not (self.regs[dst_reg] & 0x8000000000000000) else (self.regs[dst_reg] - 0x10000000000000000)
                    src_signed = self.regs[src_reg] if not (self.regs[src_reg] & 0x8000000000000000) else (self.regs[src_reg] - 0x10000000000000000)
                    jump_taken = (dst_signed >= src_signed)
                elif op == 0x70:  # CALL
                    # Helper function call - not implemented
                    pass
                elif op == 0x80:  # EXIT
                    return "exit"
                elif op == 0x90:  # JLT
                    jump_taken = (self.regs[dst_reg] < self.regs[src_reg])
                elif op == 0xa0:  # JLE
                    jump_taken = (self.regs[dst_reg] <= self.regs[src_reg])
                elif op == 0xb0:  # JSLT
                    dst_signed = self.regs[dst_reg] if not (self.regs[dst_reg] & 0x8000000000000000) else (self.regs[dst_reg] - 0x10000000000000000)
                    src_signed = self.regs[src_reg] if not (self.regs[src_reg] & 0x8000000000000000) else (self.regs[src_reg] - 0x10000000000000000)
                    jump_taken = (dst_signed < src_signed)
                elif op == 0xc0:  # JSLE
                    dst_signed = self.regs[dst_reg] if not (self.regs[dst_reg] & 0x8000000000000000) else (self.regs[dst_reg] - 0x10000000000000000)
                    src_signed = self.regs[src_reg] if not (self.regs[src_reg] & 0x8000000000000000) else (self.regs[src_reg] - 0x10000000000000000)
                    jump_taken = (dst_signed <= src_signed)
                    
                if jump_taken:
                    self.pc = addr + offset * 8
                else:
                    self.pc = addr + len(inst_bytes)
                    
            elif inst_class == 0x05:  # JMP32
                dst32 = self.regs[dst_reg] & 0xFFFFFFFF
                src32 = self.regs[src_reg] & 0xFFFFFFFF
                jump_taken = False
                if op == 0x00:  # JEQ
                    jump_taken = (dst32 == src32)
                elif op == 0x10:  # JGT
                    jump_taken = (dst32 > src32)
                elif op == 0x20:  # JGE
                    jump_taken = (dst32 >= src32)
                elif op == 0x30:  # JSET
                    jump_taken = ((dst32 & src32) != 0)
                elif op == 0x40:  # JNE
                    jump_taken = (dst32 != src32)
                elif op == 0x50:  # JSGT
                    dst_signed = dst32 if not (dst32 & 0x80000000) else (dst32 - 0x100000000)
                    src_signed = src32 if not (src32 & 0x80000000) else (src32 - 0x100000000)
                    jump_taken = (dst_signed > src_signed)
                elif op == 0x60:  # JSGE
                    dst_signed = dst32 if not (dst32 & 0x80000000) else (dst32 - 0x100000000)
                    src_signed = src32 if not (src32 & 0x80000000) else (src32 - 0x100000000)
                    jump_taken = (dst_signed >= src_signed)
                elif op == 0x90:  # JLT
                    jump_taken = (dst32 < src32)
                elif op == 0xa0:  # JLE
                    jump_taken = (dst32 <= src32)
                elif op == 0xb0:  # JSLT
                    dst_signed = dst32 if not (dst32 & 0x80000000) else (dst32 - 0x100000000)
                    src_signed = src32 if not (src32 & 0x80000000) else (src32 - 0x100000000)
                    jump_taken = (dst_signed < src_signed)
                elif op == 0xc0:  # JSLE
                    dst_signed = dst32 if not (dst32 & 0x80000000) else (dst32 - 0x100000000)
                    src_signed = src32 if not (src32 & 0x80000000) else (src32 - 0x100000000)
                    jump_taken = (dst_signed <= src_signed)
                    
                if jump_taken:
                    self.pc = addr + offset * 8
                else:
                    self.pc = addr + len(inst_bytes)
                    
            elif inst_class == 0xdc:  # Endianness conversion
                size = (opcode >> 3) & 0x3
                val = self.regs[dst_reg]
                if size == 0:  # 16-bit
                    self.regs[dst_reg] = ((val & 0xFF) << 8) | ((val >> 8) & 0xFF)
                elif size == 1:  # 32-bit
                    self.regs[dst_reg] = ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) | ((val >> 8) & 0xFF00) | ((val >> 24) & 0xFF)
                elif size == 2:  # 64-bit
                    self.regs[dst_reg] = struct.unpack('<Q', struct.pack('>Q', val))[0]
                updates.append(f"r{dst_reg}=0x{self.regs[dst_reg]:016X}")
        
        if updates:
            return ";".join(updates)
        return None
        
    def run(self, filename: str, output_file: Optional[str] = None, r10_value: Optional[int] = None):
        """Load and execute eBPF program
        
        Args:
            filename: Path to the eBPF object file
            output_file: Optional output file path (default: stdout)
            r10_value: Optional initial value for r10 (stack pointer)
        """
        self.reset()
        if r10_value is not None:
            self.regs[10] = r10_value & 0xFFFFFFFFFFFFFFFF
        self.instructions = self.parse_elf(filename)
        
        # Create instruction map by address
        inst_map = {addr: inst for addr, inst in self.instructions}
        
        # Execute instructions
        if not self.instructions:
            return
            
        self.pc = self.instructions[0][0]
        max_instructions = 10000  # Safety limit
        instruction_count = 0
        
        # Open output file if specified, otherwise use stdout
        if output_file:
            out = open(output_file, 'w')
        else:
            out = sys.stdout
        
        try:
            while instruction_count < max_instructions:
                if self.pc not in inst_map:
                    break
                    
                inst_bytes = inst_map[self.pc]
                addr = self.pc
                
                # Decode instruction
                asm = self.decode_instruction(inst_bytes, addr)
                
                # Format instruction bytes (MSB:LSB order)
                inst_hex = inst_bytes[::-1].hex().upper()
                
                # Execute instruction
                update_str = self.execute_instruction(inst_bytes, addr)
                
                # Write trace line
                trace_line = f"0x{addr:016X};0x{inst_hex};{asm}"
                if update_str:
                    trace_line += f";{update_str}"
                print(trace_line, file=out)
                
                # Check for exit
                if update_str == "exit":
                    break
                    
                # PC is updated by execute_instruction for jumps
                # If PC wasn't modified by jump, advance to next instruction
                if self.pc == addr:
                    self.pc += len(inst_bytes)
                
                instruction_count += 1
        finally:
            if output_file:
                out.close()


def main():
    parser = argparse.ArgumentParser(description='eBPF Instruction Set Simulator')
    parser.add_argument('input_file', help='LLVM-compiled eBPF relocatable object file (.o)')
    parser.add_argument('-o', '--output', dest='output_file', help='Output trace file (default: stdout)')
    parser.add_argument('--r10', type=str, dest='r10_value', help='Initial value for r10 (stack pointer) in hex (e.g., 0x1000) or decimal')
    args = parser.parse_args()
    
    # Parse r10 value if provided
    r10_value = None
    if args.r10_value:
        try:
            # Try parsing as hex first (if starts with 0x)
            if args.r10_value.startswith('0x') or args.r10_value.startswith('0X'):
                r10_value = int(args.r10_value, 16)
            else:
                r10_value = int(args.r10_value, 10)
        except ValueError as e:
            print(f"Error: Invalid r10 value '{args.r10_value}': {e}", file=sys.stderr)
            sys.exit(1)
    
    sim = eBPFSimulator()
    try:
        sim.run(args.input_file, args.output_file, r10_value)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
