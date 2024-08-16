// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "libSession-util",
    platforms: [
        .iOS(.v12)
    ],
    products: [
        .library(name: "libSession-util", targets: ["libSession-util"]),
    ],
    targets: [
        .binaryTarget(
            name: "libSession-util",
            url: "https://github.com/mpretty-cyro/libsession-util/releases/download/0.0.1/libsession-util.xcframework",
            checksum: "3c50abe18b6bd5edfe42b9cef531ea6778c8854c0e67bbe3d3d630f8bb1441e5"
        )
    ]
)