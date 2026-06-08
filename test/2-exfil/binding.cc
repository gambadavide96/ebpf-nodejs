#include <napi.h>
#include <string>
#include <sstream>
#include <fstream>

// ProcessData — processes input and writes the report directly to disk.
// File I/O happens inside the addon — syscalls are attributed to the
// native addon package during NodeLeash analysis.
Napi::Boolean ProcessData(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
        Napi::TypeError::New(env, "Expected (input: string, outPath: string)")
            .ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }

    std::string input   = info[0].As<Napi::String>().Utf8Value();
    std::string outPath = info[1].As<Napi::String>().Utf8Value();

    // Build report content
    std::ostringstream report;
    report << "=== REPORT ===\n";
    report << "length:  " << input.size() << "\n";
    report << "payload: " << input        << "\n";
    report << "==============\n";

    // Write report to disk — openat + write + close attributed to addon
    std::ofstream out(outPath, std::ios::trunc);
    if (!out.is_open()) {
        Napi::Error::New(env, "Cannot open output file")
            .ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    out << report.str();
    out.close();

    return Napi::Boolean::New(env, true);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("processData", Napi::Function::New(env, ProcessData));
    return exports;
}

NODE_API_MODULE(addon, Init)