// swift-tools-version: 5.9
import PackageDescription

// Dev-buildable SwiftPM package for the macOS shell. Before `swift build`/
// `swift run`, drop libairdrop_ffi.a into shells/macos/lib/:
//
//   cargo build --release -p airdrop-ffi          # from the repo root
//   mkdir -p shells/macos/lib
//   cp target/release/libairdrop_ffi.a shells/macos/lib/
//
// If your SwiftPM version does not resolve the relative -L flag below,
// pass it on the command line instead:
//
//   swift run -Xlinker -L$PWD/lib -Xlinker -lairdrop_ffi
//
// `swift run` gives an unbundled binary — fine for development. For a real
// .app (Info.plist, entitlements such as the multicast entitlement) use the
// Xcode route described in README.md.

let package = Package(
    name: "AirDropEverything",
    platforms: [.macOS(.v13)],
    targets: [
        .target(
            name: "CA4e",
            path: "CA4e",
            publicHeadersPath: "include",
            linkerSettings: [
                .unsafeFlags(["-L", "lib"]),
                .linkedLibrary("airdrop_ffi"),
            ]
        ),
        .executableTarget(
            name: "AirDropEverything",
            dependencies: ["CA4e"],
            path: "AirDropEverything",
            exclude: ["AirDropEverything-Bridging-Header.h"]
        )
    ]
)
