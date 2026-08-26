import "pe"
import "math"
rule Suspicious_RWX_Section {
    meta:
        description = "Detects files with RWX memory sections (e.g., UPX0/UPX1) indicative of packed or injected code."
        author = "EDR Architect"
        date = "2026-08-18"
    condition:
        pe.is_pe and 
        for any i in (0..pe.number_of_sections - 1) : ( 
            pe.sections[i].characteristics & 0x20000000 and 
            pe.sections[i].characteristics & 0x40000000 and 
            pe.sections[i].characteristics & 0x80000000 
        )
}

rule High_Entropy_Overlay {
    meta:
        description = "Detects files with very high entropy overlays, commonly found in Droppers/Loaders."
        author = "EDR Architect"
        date = "2026-08-18"
    condition:
        pe.is_pe and
        pe.overlay.size > 0 and
        math.entropy(pe.overlay.offset, pe.overlay.size) > 7.5
}

rule LSASS_Memory_Dump_Primitive {
    meta:
        description = "Detects the classic MiniDumpWriteDump+OpenProcess IAT pattern used by Mimikatz/procdump-style LSASS credential dumpers (mirrors Fibratus's credential_access_lsass_memory_dump_via_minidumpwritedump rule)."
        author = "EDR Architect"
        date = "2026-08-25"
    condition:
        pe.is_pe and
        pe.imports("dbghelp.dll", "MiniDumpWriteDump") and
        (pe.imports("kernel32.dll", "OpenProcess") or pe.imports("KERNEL32.DLL", "OpenProcess"))
}

rule Unsigned_Binary_Impersonating_Known_Vendor {
    meta:
        description = "Detects PE files whose version-info resource claims a well-known publisher (Microsoft/Google/Adobe/etc.) while carrying no Authenticode signature blob - the brand-impersonation pattern confirmed in rev_analysis1.md (Quasar RAT posing as 'Windows 11 Setup Utility')."
        author = "EDR Architect"
        date = "2026-08-25"
    condition:
        pe.is_pe and
        pe.number_of_signatures == 0 and
        for any i in (0..pe.version_info_list.size() - 1) : (
            pe.version_info_list[i].key == "CompanyName" and
            (
                pe.version_info_list[i].value icontains "microsoft" or
                pe.version_info_list[i].value icontains "google" or
                pe.version_info_list[i].value icontains "adobe" or
                pe.version_info_list[i].value icontains "mozilla" or
                pe.version_info_list[i].value icontains "apple"
            )
        )
}
