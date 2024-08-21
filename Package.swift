// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "LibSessionUtil",
    defaultLocalization: "en",
    platforms: [
        .iOS(.v12)
    ],
    products: [
        .library(name: "SessionUtil", targets: ["SessionUtil"])
    ],
    targets: [
        .binaryTarget(
            name: "SessionUtil",
            url: "https://github.com/mpretty-cyro/libsession-util/releases/download/0.0.1/libsession-util.xcframework.zip",
            checksum: "d69a0270ab9b5d272c2d73c70ab1b8f291ee19c2de1d54c26c5e3f31991f050e"
        )
    ]
)
