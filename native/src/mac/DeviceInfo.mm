// macOS device info (desktop-agent-plan.md §5.4).

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <IOKit/ps/IOPSKeys.h>
#import <IOKit/ps/IOPowerSources.h>
#import <SystemConfiguration/SystemConfiguration.h>
#include <sys/sysctl.h>

#include "../common/encoding.h"
#include "keystore.h"

namespace ks {
namespace {

std::string sysctlString(const char* name) {
    size_t size = 0;
    if (sysctlbyname(name, nullptr, &size, nullptr, 0) != 0 || size == 0) return "";
    std::string value(size, '\0');
    if (sysctlbyname(name, value.data(), &size, nullptr, 0) != 0) return "";
    value.resize(strnlen(value.c_str(), size));
    return value;
}

// Apple silicon exposes a marketing name such as "Mac mini (2024)".
std::string productName() {
    io_registry_entry_t product = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/product");
    if (product == MACH_PORT_NULL) return "";
    std::string name;
    CFTypeRef value = IORegistryEntryCreateCFProperty(product, CFSTR("product-name"), kCFAllocatorDefault, 0);
    if (value && CFGetTypeID(value) == CFDataGetTypeID()) {
        CFDataRef data = (CFDataRef)value;
        const char* p = reinterpret_cast<const char*>(CFDataGetBytePtr(data));
        name.assign(p, strnlen(p, CFDataGetLength(data)));
    }
    if (value) CFRelease(value);
    IOObjectRelease(product);
    return name;
}

// Intel Macs: derive the family from the identifier ("MacBookPro16,1").
std::string familyFromIdentifier(const std::string& id) {
    static const std::pair<const char*, const char*> kFamilies[] = {
        {"MacBookPro", "MacBook Pro"}, {"MacBookAir", "MacBook Air"}, {"MacBook", "MacBook"},
        {"Macmini", "Mac mini"},       {"MacPro", "Mac Pro"},         {"iMacPro", "iMac Pro"},
        {"iMac", "iMac"},
    };
    for (const auto& [prefix, name] : kFamilies) {
        if (id.rfind(prefix, 0) == 0) return name;
    }
    return "";
}

std::string formFactor() {
    CFTypeRef info = IOPSCopyPowerSourcesInfo();
    if (info == nullptr) return "unknown";
    CFArrayRef list = IOPSCopyPowerSourcesList(info);
    std::string result = "desktop";
    if (list) {
        for (CFIndex i = 0; i < CFArrayGetCount(list); i++) {
            CFDictionaryRef desc = IOPSGetPowerSourceDescription(info, CFArrayGetValueAtIndex(list, i));
            if (desc == nullptr) continue;
            CFStringRef type = (CFStringRef)CFDictionaryGetValue(desc, CFSTR(kIOPSTypeKey));
            if (type && CFStringCompare(type, CFSTR(kIOPSInternalBatteryType), 0) == kCFCompareEqualTo) {
                result = "laptop";
                break;
            }
        }
        CFRelease(list);
    }
    CFRelease(info);
    return result;
}

std::string platformUuid() {
    io_service_t expert = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (expert == MACH_PORT_NULL) return "";
    std::string uuid;
    CFTypeRef value = IORegistryEntryCreateCFProperty(expert, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0);
    if (value && CFGetTypeID(value) == CFStringGetTypeID()) {
        uuid = [(__bridge NSString*)value UTF8String];
    }
    if (value) CFRelease(value);
    IOObjectRelease(expert);
    return uuid;
}

std::string computerName() {
    CFStringRef name = SCDynamicStoreCopyComputerName(nullptr, nullptr);
    if (name == nullptr) return [[NSProcessInfo processInfo].hostName UTF8String];
    std::string out = [(__bridge NSString*)name UTF8String];
    CFRelease(name);
    return out;
}

}  // namespace

DeviceInfo readDeviceInfo(const std::string& salt) {
    @autoreleasepool {
        DeviceInfo info;
        info.platform = "macos";
        NSOperatingSystemVersion v = [NSProcessInfo processInfo].operatingSystemVersion;
        info.osVersion = [[NSString stringWithFormat:@"%ld.%ld.%ld", (long)v.majorVersion,
                                                     (long)v.minorVersion, (long)v.patchVersion] UTF8String];
        info.modelIdentifier = sysctlString("hw.model");
        info.model = productName();
        if (info.model.empty()) info.model = familyFromIdentifier(info.modelIdentifier);
        if (info.model.empty()) info.model = info.modelIdentifier;
        info.formFactor = formFactor();
        info.hostname = computerName();
        info.hardwareIdHash = saltedHardwareHash(salt, platformUuid());
        return info;
    }
}

}  // namespace ks
