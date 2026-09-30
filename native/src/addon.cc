// N-API binding for the key store (desktop-agent-plan.md §4.2).
//
// Every call runs on a Napi::AsyncWorker and resolves a Promise, because
// sign() blocks while the Touch ID / Hello prompt is up and must not freeze
// the Electron main loop. Calls are serialised with one mutex, so at most one
// OS prompt is shown at a time.

#include <napi.h>

#include <cstdlib>
#include <functional>
#include <memory>
#include <mutex>
#include <regex>
#include <string>

#include "common/encoding.h"
#include "keystore.h"

namespace {

using ks::Bytes;

std::mutex g_mutex;
std::unique_ptr<ks::KeyStore> g_store;

ks::Backend backendFromEnv() {
    const char* value = std::getenv("KUKUX_KEYSTORE_BACKEND");
    if (value && std::string(value) == "software") return ks::Backend::Software;
    return ks::Backend::Auto;
}

ks::KeyStore& store() {
    if (!g_store) g_store = ks::createPlatformKeyStore(backendFromEnv());
    return *g_store;
}

const char* protectionName(ks::Protection p) {
    switch (p) {
        case ks::Protection::SecureEnclave: return "secure_enclave";
        case ks::Protection::Tpm: return "tpm";
        case ks::Protection::Software: return "software";
    }
    return "software";
}

const char* algorithmName(ks::Algorithm a) {
    return a == ks::Algorithm::RS256 ? "RS256" : "ES256";
}

Napi::Buffer<uint8_t> toBuffer(Napi::Env env, const Bytes& bytes) {
    return Napi::Buffer<uint8_t>::Copy(env, bytes.data(), bytes.size());
}

Napi::Object keyInfoToJs(Napi::Env env, const ks::KeyInfo& info) {
    Napi::Object o = Napi::Object::New(env);
    o.Set("keyId", info.keyId);
    o.Set("algorithm", algorithmName(info.algorithm));
    o.Set("spki", toBuffer(env, info.spki));
    o.Set("protection", protectionName(info.protection));
    o.Set("userPresence", info.userPresence);
    return o;
}

// Key ids end up in keychain tags and CNG key names.
std::string requireKeyId(const Napi::Value& value) {
    static const std::regex kPattern("^[A-Za-z0-9._-]{1,128}$");
    if (!value.IsString()) throw Napi::TypeError::New(value.Env(), "keyId must be a string");
    std::string id = value.As<Napi::String>().Utf8Value();
    if (!std::regex_match(id, kPattern)) {
        throw Napi::TypeError::New(value.Env(), "keyId must match [A-Za-z0-9._-]{1,128}");
    }
    return id;
}

// Runs `work` on the libuv thread pool; `done` builds the JS result.
class Worker final : public Napi::AsyncWorker {
public:
    using Work = std::function<void()>;
    using Done = std::function<Napi::Value(Napi::Env)>;

    Worker(Napi::Env env, Work work, Done done)
        : Napi::AsyncWorker(env), deferred_(Napi::Promise::Deferred::New(env)),
          work_(std::move(work)), done_(std::move(done)) {}

    Napi::Promise promise() { return deferred_.Promise(); }

    void Execute() override {
        try {
            std::lock_guard<std::mutex> lock(g_mutex);
            work_();
        } catch (const ks::Error& e) {
            code_ = e.codeName();
            SetError(e.what());
        } catch (const std::exception& e) {
            code_ = "E_INTERNAL";
            SetError(e.what());
        }
    }

    void OnOK() override { deferred_.Resolve(done_(Env())); }

    void OnError(const Napi::Error& error) override {
        Napi::Error err = Napi::Error::New(Env(), error.Message());
        err.Set("code", code_);
        deferred_.Reject(err.Value());
    }

private:
    Napi::Promise::Deferred deferred_;
    Work work_;
    Done done_;
    std::string code_;
};

Napi::Value queue(Napi::Env env, Worker::Work work, Worker::Done done) {
    auto* worker = new Worker(env, std::move(work), std::move(done));
    Napi::Promise promise = worker->promise();
    worker->Queue();
    return promise;
}

Napi::Value Capabilities(const Napi::CallbackInfo& info) {
    auto caps = std::make_shared<ks::Capabilities>();
    return queue(
        info.Env(), [caps] { *caps = store().capabilities(); },
        [caps](Napi::Env env) {
            Napi::Object o = Napi::Object::New(env);
            o.Set("hardware", caps->hardware);
            o.Set("userPresence", caps->userPresence);
            o.Set("attestation", caps->attestation);
            return o;
        });
}

Napi::Value CreateKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!info[0].IsObject()) throw Napi::TypeError::New(env, "createKey expects an options object");
    Napi::Object o = info[0].As<Napi::Object>();
    ks::CreateOptions opts;
    opts.keyId = requireKeyId(o.Get("keyId"));
    opts.requireUserPresence = o.Get("requireUserPresence").ToBoolean();
    opts.biometryOnly = o.Has("biometryOnly") && o.Get("biometryOnly").ToBoolean();

    auto result = std::make_shared<ks::KeyInfo>();
    return queue(
        env, [opts, result] { *result = store().create(opts); },
        [result](Napi::Env env) -> Napi::Value { return keyInfoToJs(env, *result); });
}

Napi::Value FindKey(const Napi::CallbackInfo& info) {
    std::string keyId = requireKeyId(info[0]);
    auto result = std::make_shared<std::optional<ks::KeyInfo>>();
    return queue(
        info.Env(), [keyId, result] { *result = store().find(keyId); },
        [result](Napi::Env env) -> Napi::Value {
            if (!*result) return env.Null();
            return keyInfoToJs(env, **result);
        });
}

Napi::Value Sign(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string keyId = requireKeyId(info[0]);
    if (!info[1].IsBuffer()) throw Napi::TypeError::New(env, "message must be a Buffer");
    auto buf = info[1].As<Napi::Buffer<uint8_t>>();
    Bytes message(buf.Data(), buf.Data() + buf.Length());
    if (!info[2].IsString()) throw Napi::TypeError::New(env, "reason must be a string");
    std::string reason = info[2].As<Napi::String>().Utf8Value();

    // BrowserWindow.getNativeWindowHandle(): a Buffer holding the HWND on Windows.
    void* parent = nullptr;
    if (info.Length() > 3 && info[3].IsBuffer()) {
        auto handle = info[3].As<Napi::Buffer<uint8_t>>();
        if (handle.Length() >= sizeof(void*)) parent = *reinterpret_cast<void**>(handle.Data());
    }

    auto result = std::make_shared<Bytes>();
    return queue(
        env, [keyId, message, reason, parent, result] {
            *result = store().sign(keyId, message, reason, parent);
        },
        [result](Napi::Env env) -> Napi::Value { return toBuffer(env, *result); });
}

Napi::Value Attest(const Napi::CallbackInfo& info) {
    std::string keyId = requireKeyId(info[0]);
    auto result = std::make_shared<std::optional<ks::Attestation>>();
    return queue(
        info.Env(), [keyId, result] { *result = store().attest(keyId); },
        [result](Napi::Env env) -> Napi::Value {
            if (!*result) return env.Null();
            const auto& a = **result;
            Napi::Object o = Napi::Object::New(env);
            o.Set("format", a.format);
            o.Set("statement", toBuffer(env, a.statement));
            Napi::Array chain = Napi::Array::New(env, a.chain.size());
            for (size_t i = 0; i < a.chain.size(); i++) chain.Set(i, toBuffer(env, a.chain[i]));
            o.Set("chain", chain);
            return o;
        });
}

Napi::Value DeleteKey(const Napi::CallbackInfo& info) {
    std::string keyId = requireKeyId(info[0]);
    return queue(
        info.Env(), [keyId] { store().remove(keyId); },
        [](Napi::Env env) -> Napi::Value { return env.Undefined(); });
}

Napi::Value DeviceInfo(const Napi::CallbackInfo& info) {
    std::string salt = info.Length() > 0 && info[0].IsString() ? info[0].As<Napi::String>().Utf8Value() : "";
    auto result = std::make_shared<ks::DeviceInfo>();
    return queue(
        info.Env(), [salt, result] { *result = ks::readDeviceInfo(salt); },
        [result](Napi::Env env) -> Napi::Value {
            Napi::Object o = Napi::Object::New(env);
            o.Set("platform", result->platform);
            o.Set("osVersion", result->osVersion);
            o.Set("model", result->model);
            o.Set("modelIdentifier", result->modelIdentifier);
            o.Set("formFactor", result->formFactor);
            o.Set("hostname", result->hostname);
            o.Set("hardwareIdHash", result->hardwareIdHash);
            return o;
        });
}

// configure({ keyDirectory }): where file-backed keys live (macOS SE blobs).
Napi::Value Configure(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!info[0].IsObject()) throw Napi::TypeError::New(env, "configure expects an options object");
    Napi::Object o = info[0].As<Napi::Object>();
    if (o.Has("keyDirectory")) {
        if (!o.Get("keyDirectory").IsString()) throw Napi::TypeError::New(env, "keyDirectory must be a string");
        std::string dir = o.Get("keyDirectory").As<Napi::String>().Utf8Value();
        const bool absolute = !dir.empty() && (dir[0] == '/' || (dir.size() > 2 && dir[1] == ':'));
        if (!absolute) {
            throw Napi::TypeError::New(env, "keyDirectory must be an absolute path");
        }
        std::lock_guard<std::mutex> lock(g_mutex);
        ks::setKeyDirectory(dir);
    }
    return env.Undefined();
}

// Synchronous on purpose (a few ms, never prompts), so the token store can
// stay synchronous. They don't take g_mutex, which a pending OS prompt holds.
Napi::Value SealingAvailable(const Napi::CallbackInfo& info) {
    return Napi::Boolean::New(info.Env(), ks::sealingAvailable());
}

Napi::Value SealOrOpen(const Napi::CallbackInfo& info, bool seal) {
    Napi::Env env = info.Env();
    if (!info[0].IsBuffer()) throw Napi::TypeError::New(env, "expected a Buffer");
    auto buf = info[0].As<Napi::Buffer<uint8_t>>();
    Bytes input(buf.Data(), buf.Data() + buf.Length());
    try {
        return toBuffer(env, seal ? ks::sealData(input) : ks::openData(input));
    } catch (const ks::Error& e) {
        Napi::Error err = Napi::Error::New(env, e.what());
        err.Set("code", e.codeName());
        throw err;
    }
}

Napi::Value SealData(const Napi::CallbackInfo& info) { return SealOrOpen(info, true); }
Napi::Value OpenData(const Napi::CallbackInfo& info) { return SealOrOpen(info, false); }

// Test hook, see KeyStore::privateKeyExportable.
Napi::Value ProbeExportable(const Napi::CallbackInfo& info) {
    std::string keyId = requireKeyId(info[0]);
    auto result = std::make_shared<bool>(false);
    return queue(
        info.Env(), [keyId, result] { *result = store().privateKeyExportable(keyId); },
        [result](Napi::Env env) -> Napi::Value { return Napi::Boolean::New(env, *result); });
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("capabilities", Napi::Function::New(env, Capabilities));
    exports.Set("createKey", Napi::Function::New(env, CreateKey));
    exports.Set("findKey", Napi::Function::New(env, FindKey));
    exports.Set("sign", Napi::Function::New(env, Sign));
    exports.Set("attest", Napi::Function::New(env, Attest));
    exports.Set("deleteKey", Napi::Function::New(env, DeleteKey));
    exports.Set("deviceInfo", Napi::Function::New(env, DeviceInfo));
    exports.Set("configure", Napi::Function::New(env, Configure));
    exports.Set("sealingAvailable", Napi::Function::New(env, SealingAvailable));
    exports.Set("sealData", Napi::Function::New(env, SealData));
    exports.Set("openData", Napi::Function::New(env, OpenData));
    exports.Set("_probeExportable", Napi::Function::New(env, ProbeExportable));
    return exports;
}

}  // namespace

NODE_API_MODULE(keystore, Init)
