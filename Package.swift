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
            checksum: "549facedf450a9b1737fa4af0594e7aad9e99fd432d3b3b9dc90f9925b3a8f47"
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