import os
import json
import math
import hashlib
import pefile
from datetime import datetime

def calculate_entropy(data):
    """Calculates the Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return round(entropy, 4)

def get_file_hashes(file_path):
    """Generates MD5 and SHA-256 hashes for the file."""
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                md5_hash.update(byte_block)
                sha256_hash.update(byte_block)
        return {
            "md5": md5_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest()
        }
    except Exception as e:
        return {"error": f"Failed to hash file: {str(e)}"}

def extract_pe_features(file_path):
    """Extracts structural PE features and telemetry from the executable."""
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    hashes = get_file_hashes(file_path)
    
    feature_set = {
        "file_name": file_name,
        "file_size_bytes": file_size,
        "hashes": hashes,
        "extraction_timestamp": datetime.utcnow().isoformat() + "Z",
        "pe_metadata": {},
        "sections": [],
        "imports": {},
        "exports": [],
        "errors": []
    }

    try:
        # Load the PE file, fast_load=True defers parsing directories until needed
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories()

        # 1. Base PE Metadata
        feature_set["pe_metadata"] = {
            "machine_type": hex(pe.FILE_HEADER.Machine),
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "time_date_stamp": pe.FILE_HEADER.TimeDateStamp,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem
        }

        # 1b. Authenticode presence + version-info vendor claims.
        # A populated IMAGE_DIRECTORY_ENTRY_SECURITY means an Authenticode
        # signature blob is embedded (not that it's valid/trusted - just
        # present). Comparing this against the vendor strings the binary
        # claims for itself (CompanyName/ProductName) surfaces the exact
        # "fake Microsoft Windows 11 Setup Utility" impersonation pattern
        # found in rev_analysis1.md (Quasar RAT sample).
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        ]
        feature_set["has_authenticode_signature"] = sec_dir.VirtualAddress != 0 and sec_dir.Size != 0

        version_info = {}
        if hasattr(pe, 'FileInfo'):
            for file_info_list in pe.FileInfo:
                for entry in file_info_list:
                    if hasattr(entry, 'StringTable'):
                        for st in entry.StringTable:
                            for k, v in st.entries.items():
                                key = k.decode('utf-8', errors='ignore') if isinstance(k, bytes) else k
                                val = v.decode('utf-8', errors='ignore') if isinstance(v, bytes) else v
                                version_info[key] = val
        feature_set["version_info"] = version_info

        # 2. Section Analysis (Crucial for finding packed/polymorphic code)
        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            sec_data = section.get_data()
            entropy = calculate_entropy(sec_data)
            
            # Check for RWX (Read, Write, Execute) permissions
            characteristics = section.Characteristics
            is_read = bool(characteristics & 0x40000000)
            is_write = bool(characteristics & 0x80000000)
            is_exec = bool(characteristics & 0x20000000)
            is_rwx = is_read and is_write and is_exec

            feature_set["sections"].append({
                "name": sec_name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": hex(section.Misc_VirtualSize),
                "raw_size": hex(section.SizeOfRawData),
                "entropy": entropy,
                "is_rwx": is_rwx,
                "characteristics": hex(characteristics)
            })

        # 3. Import Address Table (IAT) Analysis
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                imported_functions = []
                for imp in entry.imports:
                    if imp.name:
                        imported_functions.append(imp.name.decode('utf-8', errors='ignore'))
                    else:
                        # Some functions are imported by ordinal rather than name
                        imported_functions.append(f"Ordinal_{imp.ordinal}")
                feature_set["imports"][dll_name] = imported_functions

        # 4. Export Directory Analysis
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    feature_set["exports"].append(exp.name.decode('utf-8', errors='ignore'))

    except pefile.PEFormatError:
        feature_set["errors"].append("Invalid PE header or not a Windows executable.")
    except Exception as e:
        feature_set["errors"].append(f"Unexpected parsing error: {str(e)}")
        
    return feature_set

def main():
    target_dir = "../samples"
    output_file = "../data/binaries.json"
    target_files = [
        "poly1 (1).exe", 
        "s1 (1).exe", 
        "s2.exe", 
        "security_svc.exe", 
        "hello (1).exe"
    ]
    
    results = []
    
    print(f"[*] Starting static feature extraction for {len(target_files)} target files...")
    
    for filename in target_files:
        file_path = os.path.join(target_dir, filename)
        
        if os.path.exists(file_path):
            print(f"  -> Processing: {filename}")
            features = extract_pe_features(file_path)
            results.append(features)
        else:
            print(f"  [!] Warning: {filename} not found in {target_dir}")
            
    # Write the compiled telemetry to binaries.json
    try:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
        print(f"\n[+] Extraction complete! Structural telemetry saved to '{output_file}'.")
    except IOError as e:
        print(f"\n[-] Failed to write to {output_file}: {str(e)}")

if __name__ == "__main__":
    main()