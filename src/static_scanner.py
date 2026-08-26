import json
import hashlib
import logging


# Well-known publishers frequently spoofed via PE version-info resources.
# If a binary claims one of these but ships no Authenticode signature blob
# at all, that's a strong static tell (see rev_analysis1.md - Quasar RAT
# posing as "Windows 11 Setup Utility" / Microsoft Corporation).
SPOOFABLE_VENDORS = ('microsoft', 'google', 'adobe', 'mozilla', 'apple', 'intel', 'nvidia')


class StaticScanner:
    def __init__(self, engine, binaries_path):
        self.engine = engine
        self.binaries_path = binaries_path

    def scan(self):
        try:
            with open(self.binaries_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logging.error(f"[STATIC] Failed to read {self.binaries_path}: {e}")
            return

        structural_hashes = {}

        for entry in data:
            filename = entry.get('file_name', 'Unknown')
            file_hash = entry.get('hashes', {}).get('sha256', 'Unknown')
            sections = entry.get('sections', [])
            imports = entry.get('imports', {})

            # Structural feature string for metamorphic clustering
            structural_features = []
            
            # Check Sections
            for sec in sections:
                if sec.get('is_rwx'):
                    self.engine.add_static_score(file_hash, 30, f"{filename}: RWX Section found ({sec.get('name')})")
                
                if sec.get('entropy', 0) > 7.5:
                    self.engine.add_static_score(file_hash, 30, f"{filename}: High entropy section ({sec.get('name')} - {sec.get('entropy')})")

                structural_features.append(f"{sec.get('name')}:{sec.get('virtual_size')}")

            # Check Imports
            import_flat = []
            for dll, funcs in imports.items():
                for f in funcs:
                    import_flat.append(f.lower())
            
            if 'virtualallocex' in import_flat and 'writeprocessmemory' in import_flat:
                self.engine.add_static_score(file_hash, 40, f"{filename}: High-risk IAT (Injection pattern)")
            
            if 'setwindowshookexa' in import_flat and 'httpsendrequesta' in import_flat:
                self.engine.add_static_score(file_hash, 40, f"{filename}: High-risk IAT (Keylogger/Exfil pattern)")

            # LSASS credential-dumping IAT pattern, mirrored from Fibratus's
            # credential_access_lsass_memory_dump_via_minidumpwritedump rule:
            # MiniDumpWriteDump (dbghelp.dll) reachable alongside OpenProcess
            # is the classic procdump/Mimikatz-style LSASS dump primitive.
            if 'minidumpwritedump' in import_flat and 'openprocess' in import_flat:
                self.engine.add_static_score(file_hash, 60, f"{filename}: High-risk IAT (LSASS memory dump primitive - MiniDumpWriteDump+OpenProcess)")

            structural_features.append(str(sorted(import_flat)))

            # Brand-impersonation check: version-info vendor claims a
            # well-known publisher but the file carries no Authenticode
            # signature blob at all (System Informer / Sigcheck-style check,
            # applied here as a pure static-metadata comparison).
            version_info = entry.get('version_info', {}) or {}
            has_signature = entry.get('has_authenticode_signature', False)
            claimed_vendor = (version_info.get('CompanyName') or '').strip().lower()
            if claimed_vendor and not has_signature:
                if any(vendor in claimed_vendor for vendor in SPOOFABLE_VENDORS):
                    self.engine.add_static_score(
                        file_hash, 50,
                        f"{filename}: Unsigned binary claims to be published by '{version_info.get('CompanyName')}' "
                        f"(ProductName='{version_info.get('ProductName', '?')}') - brand impersonation"
                    )

            # Calculate Structural Hash
            struct_str = "|".join(structural_features)
            struct_hash = hashlib.sha256(struct_str.encode()).hexdigest()
            
            if struct_hash in structural_hashes:
                other_file = structural_hashes[struct_hash]
                if other_file['sha256'] != file_hash:
                    logging.warning(f"[STATIC] Metamorphic Clone Detected! {filename} and {other_file['filename']} share exact structural hash but different SHA-256.")
                    self.engine.add_static_score(file_hash, 50, "Metamorphic Clone")
            else:
                structural_hashes[struct_hash] = {
                    'filename': filename,
                    'sha256': file_hash
                }
