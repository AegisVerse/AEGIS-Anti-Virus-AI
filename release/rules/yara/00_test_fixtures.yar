// source: AEGIS AI Security Project
// license: Apache-2.0
// version: 2026.11.1

rule AEGIS_Test_Signature {
    meta:
        description = "Deterministic harmless test fixture used by AEGIS automated tests"
        severity = "high"
        confidence = "100"
        family = "AEGIS.TestFixture"
        author = "AEGIS AI Security"
    strings:
        $marker = "AEGIS-HARMLESS-TEST-SIGNATURE-2026-DO-NOT-EXECUTE" ascii
    condition:
        $marker
}

rule AEGIS_Test_Suspicious_Marker {
    meta:
        description = "Harmless suspicious-level test marker"
        severity = "medium"
        confidence = "65"
        family = "AEGIS.TestSuspicious"
    strings:
        $s = "AEGIS-TEST-SUSPICIOUS-MARKER-2026" ascii
    condition:
        $s
}

rule AEGIS_EICAR_Standard_Test_File {
    meta:
        description = "EICAR Standard Anti-Virus Test File"
        severity = "high"
        confidence = "100"
        family = "EICAR-Test-File"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        // Split so the rule source file itself is never flagged by host AV.
        $p1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}" ascii
        $p2 = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        filesize <= 128 and $p1 at 0 and $p2
}

