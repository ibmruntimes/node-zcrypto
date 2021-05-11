/*
 * Licensed Materials - Property of IBM
 * (C) Copyright IBM Corp. 2020. All Rights Reserved.
 * US Government Users Restricted Rights - Use, duplication or disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
 */

#include "zcrypto.h"

Napi::FunctionReference ZCrypto::constructor;

Napi::Object ZCrypto::Init(Napi::Env env, Napi::Object exports) {
  Napi::HandleScope scope(env);

  Napi::Function func = DefineClass(env, "ZCrypto", {
    InstanceMethod("exportKeyToBuffer", &ZCrypto::ExportKeyToBuffer),
    InstanceMethod("exportCertToBuffer", &ZCrypto::ExportCertToBuffer),
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

  std::string filename = static_cast<std::string>(info[0].As<Napi::String>());
  std::string password = static_cast<std::string>(info[1].As<Napi::String>());

  int rc = createKDB_impl(
    filename.c_str(),
    password.c_str(),
    length,
    time,
    &(this->handle)
  );

  return Napi::Number::New(env, rc);
}

Napi::Value ZCrypto::OpenKeyRing(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::Error::New(env, "OpenKeyRing needs 1 arguments "
                          "ring_name")
        .ThrowAsJavaScriptException();
    return Napi::Number::New(env, -1);
  }
  std::string ring_name = static_cast<std::string>(info[0].As<Napi::String>());

  int rc = openKeyRing_impl(ring_name.c_str(), &(this->handle));

  return Napi::Number::New(env, rc);
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
  std::string database = static_cast<std::string>(info[0].As<Napi::String>());
  std::string passphrase = static_cast<std::string>(info[1].As<Napi::String>());

  int rc = openKDB_impl(database.c_str(), passphrase.c_str(), &(this->handle));

  return Napi::Number::New(env, rc);
}

Napi::Value ZCrypto::ImportKey(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) {
    Napi::Error::New(env, "ImportKey needs 3 arguments "
                          "filename, password, label")
        .ThrowAsJavaScriptException();
    return Napi::Number::New(env, -1);
  }

  std::string filename = static_cast<std::string>(info[0].As<Napi::String>());
  std::string password = static_cast<std::string>(info[1].As<Napi::String>());
  std::string label = static_cast<std::string>(info[2].As<Napi::String>());

  int rc = importKey_impl(
    filename.c_str(),
    password.c_str(),
    label.c_str(),
    &(this->handle)
  );

  return Napi::Number::New(env, rc);
}

Napi::Value ZCrypto::ExportKeyToFile(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) {
    Napi::Error::New(env, "ExportKeyToFile needs 3 arguments "
                          "filename, password, label")
        .ThrowAsJavaScriptException();
    return Napi::Number::New(env, -1);
  }

  std::string filename = static_cast<std::string>(info[0].As<Napi::String>());
  std::string password = static_cast<std::string>(info[1].As<Napi::String>());
  std::string label = static_cast<std::string>(info[2].As<Napi::String>());

  int rc = exportKeyToFile_impl(
    filename.c_str(),
    password.c_str(),
    label.c_str(),
    &(this->handle)
  );

  return Napi::Number::New(env, rc);
}

Napi::Value ZCrypto::ExportKeyToBuffer(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
    Napi::Error::New(env, "ExportKeyToBuffer needs 2 arguments "
                          "password, label")
        .ThrowAsJavaScriptException();
    return Napi::Number::New(env, -1);
  }

  std::string password = static_cast<std::string>(info[0].As<Napi::String>());
  std::string label = static_cast<std::string>(info[1].As<Napi::String>());

  gsk_buffer stream = {0, 0};
  int rc = exportKeyToBuffer_impl(
    password.c_str(),
    label.c_str(),
    &stream,
    &(this->handle)
  );

  if (rc != 0)
    return Napi::Number::New(env, rc);

  char* bufferptr = nullptr;

  Napi::ArrayBuffer arrayBuffer = Napi::ArrayBuffer::New(env, (void*)(stream.data), stream.length);
  return Napi::Uint8Array::New(env, stream.length, arrayBuffer, 0);
}

Napi::Value ZCrypto::ExportCertToBuffer(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::Error::New(env, "ExportCertToBuffer needs 1 arguments "
                          "password, label")
        .ThrowAsJavaScriptException();
    return Napi::Number::New(env, -1);
  }

  std::string label = static_cast<std::string>(info[0].As<Napi::String>());

  gsk_buffer stream = {0, 0};
  int rc = exportCertToBuffer_impl(label.c_str(), &stream, &(this->handle));

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
