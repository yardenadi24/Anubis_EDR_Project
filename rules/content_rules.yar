rule BlockSuspiciousContent
{
    meta:
        description = "Block files containing suspicious content"
        author = "Anubis EDR"

    strings:
        $s1 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
        $s2 = "malicious_payload" ascii nocase
        $s3 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR" ascii

        // Add your own patterns here:
        // $s4 = "ANUBIS_EDR_TEST" ascii nocase

    condition:
        any of them
}