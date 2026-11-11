// source: AEGIS AI Security Project
// license: Apache-2.0
// version: 2026.11.1

import "pe"

rule AEGIS_PE_Process_Hollowing_Imports {
    meta:
        description = "Executable imports the classic process-hollowing / remote-thread API combination"
        severity = "medium"
        confidence = "60"
        family = "Heuristic.PE.InjectionImports"
    strings:
        $a1 = "VirtualAllocEx" ascii
        $a2 = "WriteProcessMemory" ascii
        $a3 = "CreateRemoteThread" ascii
        $a4 = "NtUnmapViewOfSection" ascii
        $a5 = "QueueUserAPC" ascii
    condition:
        uint16(0) == 0x5A4D and $a1 and $a2 and ($a3 or $a4 or $a5)
}

rule AEGIS_Known_Credential_Dump_Markers {
    meta:
        description = "Contains unambiguous markers from known credential-dumping tools"
        severity = "critical"
        confidence = "95"
        family = "HackTool.CredentialDumper"
    strings:
        $m1 = "gentilkiwi" ascii wide nocase
        $m2 = "sekurlsa::logonpasswords" ascii wide nocase
        $m3 = "lsadump::sam" ascii wide nocase
        $m4 = "privilege::debug" ascii wide nocase
    condition:
        2 of ($m*)
}

rule AEGIS_Ransomware_ShadowCopy_Deletion_Command {
    meta:
        description = "Contains commands that delete Volume Shadow Copies and disable recovery"
        severity = "high"
        confidence = "85"
        family = "Behavior.Ransomware.InhibitRecovery"
    strings:
        $v1 = "vssadmin" ascii wide nocase
        $v2 = "delete shadows" ascii wide nocase
        $w1 = "wmic" ascii wide nocase
        $w2 = "shadowcopy delete" ascii wide nocase
        $b1 = "bcdedit" ascii wide nocase
        $b2 = "recoveryenabled no" ascii wide nocase
        $wb = "wbadmin delete catalog" ascii wide nocase
    condition:
        filesize < 10MB and (
            ($v1 and $v2) or ($w1 and $w2) or ($b1 and $b2) or $wb
        )
}

rule AEGIS_Script_Encoded_Download_Cradle {
    meta:
        description = "Script combining hidden/encoded PowerShell execution with a download cradle"
        severity = "high"
        confidence = "80"
        family = "Suspicious.Script.DownloadCradle"
    strings:
        $ps = "powershell" ascii wide nocase
        $enc = /-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{40,}/i
        $hid = "-w hidden" ascii wide nocase
        $hid2 = "-windowstyle hidden" ascii wide nocase
        $dl1 = "Net.WebClient" ascii wide nocase
        $dl2 = "DownloadString" ascii wide nocase
        $dl3 = "DownloadFile" ascii wide nocase
        $dl4 = "Invoke-WebRequest" ascii wide nocase
        $dl5 = "FromBase64String" ascii wide nocase
        $iex = "IEX" ascii wide
    condition:
        filesize < 2MB and (
            ($ps and $enc) or
            (($hid or $hid2) and 1 of ($dl*) and $iex)
        )
}

rule AEGIS_Stealer_Browser_LoginData_Targeting {
    meta:
        description = "References multiple browser credential / cookie stores alongside DPAPI"
        severity = "high"
        confidence = "80"
        family = "Spyware.Stealer.BrowserCreds"
    strings:
        $b1 = "Google\\Chrome\\User Data" ascii wide nocase
        $b2 = "Microsoft\\Edge\\User Data" ascii wide nocase
        $b3 = "BraveSoftware\\Brave-Browser\\User Data" ascii wide nocase
        $c1 = "Login Data" ascii wide
        $c2 = "Local State" ascii wide
        $c3 = "os_crypt" ascii wide
        $d1 = "CryptUnprotectData" ascii wide
    condition:
        filesize < 20MB and 2 of ($b*) and 2 of ($c*) and $d1
}

