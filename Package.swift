// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "libSession-util",
    defaultLocalization: "en",
    platforms: [
        .iOS(.v12)
    ],
    products: [
        .library(name: "SessionUtil", targets: ["libSession-util-packaged"]),
        .library(name: "SessionUtilSource", targets: ["libSession-util-source"]),
    ],
    targets: [
        .binaryTarget(
            name: "libSession-util-packaged",
            url: "https://github.com/mpretty-cyro/libsession-util/releases/download/0.0.1/libsession-util.xcframework.zip",
            checksum: "839d6a6a46ad7646ffb75914f74a911dfd7c9dedc391db5f15c18126f203b01a"
        ),
        .target(
            name: "libSession-util-source",
            path: ".",
            sources: [
                "src",
                "proto",
                "utils",
            ],
            publicHeadersPath: "include"
        )
    ]
)