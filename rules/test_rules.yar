rule Anubis_Test_Detection {
    strings:
        $test_marker = "ANUBIS-EDR-TEST-DETECTION-MARKER"
    condition:
        $test_marker
}
