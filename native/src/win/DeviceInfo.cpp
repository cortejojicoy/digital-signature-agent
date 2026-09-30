// Windows device info (desktop-agent-plan.md §6.3).

#include "WinStores.h"

#include <cstdio>

#include "../common/encoding.h"

namespace ks {
namespace {

using win::narrow;

std::string biosValue(LPCWSTR name) {
    wchar_t buf[256];
    DWORD size = sizeof(buf);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", name, RRF_RT_REG_SZ,
                     nullptr, buf, &size) != ERROR_SUCCESS) {
        return "";
    }
    return narrow(buf);
}

std::string osVersion() {
    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    auto fn = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    RTL_OSVERSIONINFOW v{};
    v.dwOSVersionInfoSize = sizeof(v);
    if (fn == nullptr || fn(&v) != 0) return "";
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%lu.%lu.%lu", v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber);
    return buf;
}

std::string formFactor() {
    SYSTEM_POWER_STATUS power{};
    if (!GetSystemPowerStatus(&power) || power.BatteryFlag == 255) return "unknown";
    return power.BatteryFlag == 128 ? "desktop" : "laptop";  // 128 = no system battery
}

std::string hostname() {
    wchar_t buf[256];
    DWORD size = 256;
    if (!GetComputerNameExW(ComputerNamePhysicalDnsHostname, buf, &size)) return "";
    return narrow(std::wstring(buf, size));
}

// SMBIOS system UUID (type 1, offset 8). From SMBIOS 2.6 on, the first three
// fields are little-endian, matching how Windows itself formats it.
std::string smbiosUuid() {
    struct RawSMBIOSData {
        BYTE Used20CallingMethod;
        BYTE SMBIOSMajorVersion;
        BYTE SMBIOSMinorVersion;
        BYTE DmiRevision;
        DWORD Length;
        BYTE SMBIOSTableData[1];
    };

    const DWORD signature = 'RSMB';
    UINT size = GetSystemFirmwareTable(signature, 0, nullptr, 0);
    if (size == 0) return "";
    Bytes buffer(size);
    if (GetSystemFirmwareTable(signature, 0, buffer.data(), size) != size) return "";
    auto* raw = reinterpret_cast<const RawSMBIOSData*>(buffer.data());
    const uint8_t* p = raw->SMBIOSTableData;
    const uint8_t* end = p + raw->Length;
    const bool littleEndian = raw->SMBIOSMajorVersion > 2 ||
                              (raw->SMBIOSMajorVersion == 2 && raw->SMBIOSMinorVersion >= 6);

    while (p + 4 <= end) {
        const uint8_t type = p[0];
        const uint8_t length = p[1];
        if (length < 4 || p + length > end) break;
        if (type == 1 && length >= 24) {
            const uint8_t* u = p + 8;
            bool allZero = true, allFF = true;
            for (int i = 0; i < 16; i++) {
                allZero &= u[i] == 0x00;
                allFF &= u[i] == 0xff;
            }
            if (allZero || allFF) return "";
            char buf[37];
            if (littleEndian) {
                std::snprintf(buf, sizeof(buf),
                              "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                              u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6], u[8], u[9], u[10], u[11],
                              u[12], u[13], u[14], u[15]);
            } else {
                std::snprintf(buf, sizeof(buf),
                              "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                              u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11],
                              u[12], u[13], u[14], u[15]);
            }
            return buf;
        }
        if (type == 127) break;  // end-of-table
        // Skip the formatted area, then the string set (ends with a double NUL).
        const uint8_t* s = p + length;
        while (s + 1 < end && !(s[0] == 0 && s[1] == 0)) s++;
        p = s + 2;
    }
    return "";
}

}  // namespace

DeviceInfo readDeviceInfo(const std::string& salt) {
    DeviceInfo info;
    info.platform = "windows";
    info.osVersion = osVersion();
    const std::string manufacturer = biosValue(L"SystemManufacturer");
    const std::string product = biosValue(L"SystemProductName");
    const std::string family = biosValue(L"SystemFamily");
    info.modelIdentifier = manufacturer.empty() ? product : manufacturer + " " + product;
    // SystemFamily is the marketing name on most OEMs ("ThinkPad X1 Carbon Gen 10").
    info.model = !family.empty() && family != "To be filled by O.E.M." ? family : info.modelIdentifier;
    info.formFactor = formFactor();
    info.hostname = hostname();
    info.hardwareIdHash = saltedHardwareHash(salt, smbiosUuid());
    return info;
}

}  // namespace ks
