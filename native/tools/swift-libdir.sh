#!/bin/sh
# Prints the toolchain's Swift library directory (back-deployment shims),
# for Xcode and Command Line Tools installs alike.
echo "$(dirname "$(dirname "$(xcrun -f swiftc)")")/lib/swift/macosx"
