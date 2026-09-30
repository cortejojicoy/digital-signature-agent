{
  "targets": [
    {
      "target_name": "keystore",
      "sources": [
        "src/addon.cc",
        "src/common/encoding.cc"
      ],
      "include_dirs": [
        "include",
        "src"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').targets\"):node_addon_api_except"
      ],
      "conditions": [
        ["OS=='mac'", {
          "dependencies": ["secure_enclave_blob"],
          "sources": [
            "src/mac/SecureEnclaveKeyStore.mm",
            "src/mac/DeviceInfo.mm",
            "src/mac/Hash.cc"
          ],
          "xcode_settings": {
            "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
            "CLANG_ENABLE_OBJC_ARC": "YES",
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
            "MACOSX_DEPLOYMENT_TARGET": "12.0",
            "OTHER_CFLAGS": ["-mmacosx-version-min=12.0", "-Wall", "-Wextra", "-Wno-unused-parameter"],
            "OTHER_LDFLAGS": ["-mmacosx-version-min=12.0"]
          },
          "link_settings": {
            "libraries": [
              "<(module_root_dir)/build/swift/<(target_arch)/SecureEnclaveBlob.o",
              "-L<!(xcrun --show-sdk-path)/usr/lib/swift",
              "-L<!(sh tools/swift-libdir.sh)",
              "-Wl,-rpath,/usr/lib/swift",
              "-framework Foundation",
              "-framework Security",
              "-framework LocalAuthentication",
              "-framework CryptoKit",
              "-framework IOKit",
              "-framework SystemConfiguration"
            ]
          }
        }],
        ["OS=='win'", {
          "sources": [
            "src/win/WinKeyStore.cpp",
            "src/win/HelloKeyStore.cpp",
            "src/win/PcpKeyStore.cpp",
            "src/win/DeviceInfo.cpp",
            "src/win/Hash.cpp"
          ],
          "defines": [
            "UNICODE",
            "_UNICODE",
            "NOMINMAX",
            "WIN32_LEAN_AND_MEAN"
          ],
          "msvs_settings": {
            "VCCLCompilerTool": {
              "ExceptionHandling": 1,
              "AdditionalOptions": ["/std:c++20", "/permissive-", "/bigobj"]
            }
          },
          "libraries": [
            "windowsapp.lib",
            "ncrypt.lib",
            "bcrypt.lib",
            "advapi32.lib",
            "user32.lib"
          ]
        }]
      ]
    }
  ],
  "conditions": [
    ["OS=='mac'", {
      "targets": [
        {
          # CryptoKit Secure Enclave keys outside the keychain (free builds).
          "target_name": "secure_enclave_blob",
          "type": "none",
          "actions": [
            {
              "action_name": "swiftc",
              "inputs": ["src/mac/SecureEnclaveBlob.swift", "tools/swiftc.sh"],
              "outputs": ["<(module_root_dir)/build/swift/<(target_arch)/SecureEnclaveBlob.o"],
              "action": ["sh", "tools/swiftc.sh", "<(target_arch)", "src/mac/SecureEnclaveBlob.swift", "<@(_outputs)"]
            }
          ]
        }
      ]
    }]
  ]
}
