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
        .library(name: "SessionUtil", targets: ["SessionUtilTarget"])
    ],
    targets: [
        .binaryTarget(
            name: "libSession-util",
            url: "https://github.com/mpretty-cyro/libsession-util/releases/download/0.0.1/libsession-util.xcframework.zip",
            checksum: "d69a0270ab9b5d272c2d73c70ab1b8f291ee19c2de1d54c26c5e3f31991f050e"
        ),
        .target(
            name: "libSession-util-source",
            dependencies: ["GenerateFramework"],
            path: ".",
            sources: [
                "src",
                "proto",
                "utils",
            ],
            publicHeadersPath: "include"
        ),
        .target(
            name: "GenerateFramework",
            path: "utils",
            sources: ["ios-framework.swift"]
        ),

        .target(
            name: "SessionUtilTarget",
            dependencies: conditionalDependencies(),
            path: ".",
            sources: []
        ),
    ]
)

func conditionalDependencies() -> [Target.Dependency] {
    #if COMPILE_LIB_SESSION
    return [.target(name: "libSession-util-source")]
    #else
    return [.target(name: "libSession-util")]
    #endif
}
