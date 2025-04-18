// Simple test rule for Anubis EDR
rule Test_EICAR_Detection {
    meta:
        description = "Detects the EICAR test string used to test antivirus systems"
        author = "Anubis EDR Team"
        severity = "info"
        reference = "https://www.eicar.org/?page_id=3950"
    
    strings:
        $eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    
    condition:
        $eicar_string
}

rule Test_Simple_String {
    meta:
        description = "Simple test rule to detect a test string"
        author = "Anubis EDR Team"
        severity = "info"
    
    strings:
        $test_string = "ANUBIS_TEST_STRING_PLEASE_DETECT"
    
    condition:
        $test_string
}

rule Detect_Executable_With_Hello_World {
    meta:
        description = "Detects executables containing 'Hello World'"
        author = "Anubis EDR Team"
        severity = "info"
    
    strings:
        $hello = "Hello World" nocase
    
    condition:
        uint16(0) == 0x5A4D and // PE file header
        $hello
}