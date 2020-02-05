#include "zcrypto.h"

Napi::FunctionReference ZCrypto::constructor;

Napi::Object ZCrypto::Init(Napi::Env env, Napi::Object exports) {
  Napi::HandleScope scope(env);

  Napi::Function func = DefineClass(env, "ZCrypto", {
    InstanceMethod("exportKeyToBuffer", &ZCrypto::ExportKeyToBuffer),
    InstanceMethod("exportKeyToFile", &ZCrypto::ExportKeyToFile),
    InstanceMethod("openKDB", &ZCrypto::OpenKDB),
    InstanceMethod("createKDB", &ZCrypto::CreateKDB),
    InstanceMethod("openKeyRing", &ZCrypto::OpenKeyRing),
    InstanceMethod("importKey", &ZCrypto::ImportKey),
    InstanceMethod("getErrorString", &ZCrypto::GetErrorString),
  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  exports.Set("ZCrypto", func);
  return exports;
}

ZCrypto::ZCrypto(const Napi::CallbackInfo& info) : Napi::ObjectWrap<ZCrypto>(info)  {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  this->initialized = 0; 
}

Napi::Value ZCrypto::CreateKDB(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  if (info.Length() < 4) {
    Napi::Error::New(env, "createKDB needs 4 arguments "
                          "filename, password, length, and expiration")
        .ThrowAsJavaScriptException();
    return Napi::Number::New(env, -1);
  }
  if (!info[2].IsNumber()) {
    Napi::TypeError::New(env, "length should be a number")
        .ThrowAsJavaScriptException();
    return Napi::Number::New(env, -1);
  }
  int length = info[2].As<Napi::Number>();

  if (!info[3].IsNumber()) {
    Napi::TypeError::New(env, "expiration should be a number")
        .ThrowAsJavaScriptException();
    return Napi::Number::New(env, -1);
  }
  int time = info[3].As<Napi::Number>();

  const char *filename =
      static_cast<std::string>(info[0].As<Napi::String>()).c_str();
  const char *password =
      static_cast<std::string>(info[1].As<Napi::String>()).c_str();

  return Napi::Number::New(env, createKDB_impl(filename, password, 
                          length, time, &(this->handle)));
}

Napi::Value ZCrypto::OpenKeyRing(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::Error::New(env, "OpenKeyRing needs 1 arguments "
                          "ring_name")
        .ThrowAsJavaScriptException();
    return Napi::Number::New(env, -1);
  }
  const char *ring_name =
      static_cast<std::string>(info[0].As<Napi::String>()).c_str();

  return Napi::Number::New(env, openKeyRing_impl(ring_name, &(this->handle)));
}

Napi::Value ZCrypto::GetErrorString(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::Error::New(env, "GetErrorString needs 1 arguments "
                          "error")
        .ThrowAsJavaScriptException();
    return Napi::Number::New(env, -1);
  }

  int error = info[0].As<Napi::Number>();

  return Napi::String::New(env, errorString_impl(error));
}

Napi::Value ZCrypto::OpenKDB(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
    Napi::Error::New(env, "OpenKDB needs 2 arguments "
                          "database, passphrase")
        .ThrowAsJavaScriptException();
    return Napi::Number::New(env, -1);
  }
  const char *database =
      static_cast<std::string>(info[0].As<Napi::String>()).c_str();
  const char *passphrase =
      static_cast<std::string>(info[1].As<Napi::String>()).c_str();

  return Napi::Number::New(env, openKDB_impl(database, passphrase, &(this->handle)));
}

Napi::Value ZCrypto::ImportKey(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) {
    Napi::Error::New(env, "ImportKey needs 3 arguments "
                          "filename, password, label")
        .ThrowAsJavaScriptException();
    return Napi::Number::New(env, -1);
  }

  const char *filename =
      static_cast<std::string>(info[0].As<Napi::String>()).c_str();
  const char *password =
      static_cast<std::string>(info[1].As<Napi::String>()).c_str();
  const char *label =
      static_cast<std::string>(info[2].As<Napi::String>()).c_str();

  return Napi::Number::New(env, importKey_impl(filename, password, label, &(this->handle)));
}

Napi::Value ZCrypto::ExportKeyToFile(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) {
    Napi::Error::New(env, "ExportKeyToFile needs 3 arguments "
                          "filename, password, label")
        .ThrowAsJavaScriptException();
    return Napi::Number::New(env, -1);
  }

  const char *filename =
      static_cast<std::string>(info[0].As<Napi::String>()).c_str();
  const char *password =
      static_cast<std::string>(info[1].As<Napi::String>()).c_str();
  const char *label =
      static_cast<std::string>(info[2].As<Napi::String>()).c_str();

  return Napi::Number::New(env, exportKeyToFile_impl(filename, password, label, &(this->handle)));
}

Napi::Value ZCrypto::ExportKeyToBuffer(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
    Napi::Error::New(env, "ExportKeyToBuffer needs 2 arguments "
                          "password, label")
        .ThrowAsJavaScriptException();
    return Napi::Number::New(env, -1);
  }

  const char *password =
      static_cast<std::string>(info[0].As<Napi::String>()).c_str();
  const char *label =
      static_cast<std::string>(info[1].As<Napi::String>()).c_str();

  gsk_buffer stream = {0, 0};
  int rc = exportKeyToBuffer_impl(password, label, &stream, &(this->handle));

  if (rc != 0)
    return Napi::Number::New(env, rc);

  char* bufferptr = nullptr;

  Napi::ArrayBuffer arrayBuffer = Napi::ArrayBuffer::New(env, (void*)(stream.data), stream.length);
  return Napi::Uint8Array::New(env, stream.length, arrayBuffer, 0);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  return ZCrypto::Init(env, exports);
}

NODE_API_MODULE(zcrypto, Init)
