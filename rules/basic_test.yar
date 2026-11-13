rule PscanAV_Test_Detection
{
    meta:
        description = "PscanAV test rule"

    strings:
        $marker = "PSCAV_TEST_MARKER_12345"

    condition:
        $marker
}
