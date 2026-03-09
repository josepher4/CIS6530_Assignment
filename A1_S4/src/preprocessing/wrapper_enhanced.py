# Pure Python PE opcode extractor using pefile + capstone
# Handles .exe/.dll, packed malware, multi-sections
#
# Prerequisites (Remnux):
# sudo remnux install pefile capstone tqdm
# OR: pip install pefile capstone tqdm
#
# Features:
# - Progress bar (tqdm) for 48+ sample batch processing
# - Multiple executable sections extraction
# - Entry point fallback for obfuscated samples
# - JSON log file with stats/failures


import os, pefile, capstone, glob, json
from tqdm import tqdm  # pip install tqdm (Remnux: remnux install tqdm)

malware_dir = "/home/remnux/Desktop/A1_S3_Malware/samples"
output_dir = "./Raw_Extracted_Files"
log_file = "./extraction_log.json"

os.makedirs(output_dir, exist_ok=True)

def extract_opcodes_pe(file_path):
    try:
        pe = pefile.PE(file_path)
        is_64bit = pe.FILE_HEADER.Machine == 0x8664
        md = capstone.Cs(capstone.CS_ARCH_X86, 
                         capstone.CS_MODE_64 if is_64bit else capstone.CS_MODE_32)
        md.skipdata = True  # Skip padding/data bytes [web:38]
        md.detail = True
        
        # Collect ALL executable sections (not just first)
        code_bytes = b''
        for section in pe.sections:
            if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                data = section.get_data()
                code_bytes += data
                print(f"  Added {section.Name.decode().strip()}: {len(data)} bytes")
        
        # Fallback: Entry point from memory-mapped image [web:34]
        if len(code_bytes) < 100:
            entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            mmap_img = pe.get_memory_mapped_image()
            code_bytes = mmap_img[entry_rva:entry_rva + 0x20000]  # 128KB
        
        if len(code_bytes) < 100:
            return []
        
        # Disassemble with better filtering
        opcodes = []
        for i in md.disasm(code_bytes[:0x40000], 0x1000):  # Limit + base addr
            mnemonic = i.mnemonic
            if mnemonic not in ['invalid', 'db', 'dd', 'dw'] and len(mnemonic) > 1:
                opcodes.append(mnemonic)
        
        # Optional: Add n-grams (2-grams for ML) [web:33]
        ngrams = [f"{opcodes[i]};{opcodes[i+1]}" for i in range(len(opcodes)-1)]
        
        return opcodes, ngrams[:len(opcodes)//2]  # Balance size
        
    except Exception as e:
        return [], str(e)

# Process with progress
malwares = glob.glob(f"{malware_dir}/*.exe") + glob.glob(f"{malware_dir}/*.dll")
print(f"Found {len(malwares)} samples")

stats = {'success': 0, 'total_opcodes': 0, 'failures': {}}
log = []

for fname in tqdm(malwares, desc="Extracting"):
    name = os.path.splitext(os.path.basename(fname))[0]
    opcodes, ngrams = extract_opcodes_pe(fname)
    
    if opcodes:
        with open(f"{output_dir}/{name}.opcode", 'w') as f:
            f.write('\n'.join(opcodes))
        print(f"[{name}] ✓ {len(opcodes)} opcodes + {len(ngrams)} n-grams")
        stats['total_opcodes'] += len(opcodes)
        stats['success'] += 1
    else:
        stats['failures'][name] = ngrams[0] if ngrams else "Unknown"
        log.append({'file': name, 'error': ngrams[0] if ngrams else "Parse failed"})

# Save stats/log
with open(log_file, 'w') as f:
    json.dump({'stats': stats, 'log': log}, f, indent=2)

print(f"\n✓ Complete! {stats['success']}/{len(malwares)} files, avg {stats['total_opcodes']/max(stats['success'],1):.0f} opcodes/file")
print(f"Log: {log_file}")
