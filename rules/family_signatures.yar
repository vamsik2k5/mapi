rule Quasar_RAT_Win11_Lure {
    meta:
        description = "Detects Quasar RAT disguised as Windows 11 Setup Utility"
        author = "Security Systems Architect"
        date = "2026-08-18"
    strings:
        // Quasar RAT specific strings
        $q1 = "Quasar Client" ascii wide
        $q2 = "Quasar.Client.Properties.Resources" ascii wide
        $q3 = "Quasar.Client.Recovery.Browsers" ascii wide
        $q4 = "GetPasswordResponse" ascii wide
        $q5 = "GetKeyloggerLogsDirectory" ascii wide
        // Brand impersonation
        $s1 = "Windows 11 Setup Utility" ascii wide
        $s2 = "Microsoft Corporation" ascii wide
    condition:
        uint16(0) == 0x5A4D and 3 of ($q*) and $s1 and $s2
}

rule Go_Maze_TaskRunner {
    meta:
        description = "Detects Go binary with Maze Pathfinder Decoy"
        author = "Security Systems Architect"
        date = "2026-08-18"
    strings:
        $m1 = "=== MAZE PATHFINDER SIMULATION ===" ascii wide
        $m2 = "Manhattan distance to goal:" ascii wide
        $m3 = "Executing " ascii wide
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule NSIS_Installer_Dropper {
    meta:
        description = "Detects NSIS Installer with high-entropy overlay"
        author = "Security Systems Architect"
        date = "2026-08-18"
    strings:
        $nsis1 = "Nullsoft.NSIS.exehead" ascii wide
        $nsis2 = "Nullsoft Install System" ascii wide
        $magic = { DE AD BE EF }
    condition:
        uint16(0) == 0x5A4D and all of ($nsis*) and $magic
}
