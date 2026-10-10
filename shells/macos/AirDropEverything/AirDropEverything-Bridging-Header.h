/*
 * Xcode route only — when building as an .app project (not SwiftPM), point
 * SWIFT_OBJC_BRIDGING_HEADER at this file and add libairdrop_ffi.a under
 * "Link Binary With Libraries". SwiftPM users get the same decls through
 * `import CA4e` instead — see README.md.
 */
#import "../CA4e/include/a4e.h"
