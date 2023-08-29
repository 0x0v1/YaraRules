rule APT37_SOLMIR_AutoIT {
    strings:
        $magic_mz = "MZ"
        $magic_pe = "PE\x00\x00"
        $signature = "EP"
        $section_marker = "."
        $alloc_func = "_RUNBINARY_ALLOCATEEXESPACE"
    condition:
        $magic_mz at 0 and
        $magic_pe at 0x3C and
        $signature at (0x3C + 0x18) and
        $section_marker at (0x3C + 0x80) and
        $alloc_func
}
