/*
 * CA4e — SwiftPM C target exposing the libairdrop_ffi headers to Swift.
 * The target needs at least one translation unit; the actual symbols come
 * from the linked archive (see Package.swift linker settings / README).
 */
#include "a4e.h"

/* Anchor so the target never produces a fully empty archive. */
const char *ca4e_module_anchor = "CA4e";
