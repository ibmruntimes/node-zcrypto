#ifndef __ZCRYPTO_H_
#define __ZCRYPTO_H_ 1

#include <stdio.h>
#include <stdlib.h>
#include <gskcms.h>
#include <gskssl.h>
#include <napi.h>
#include <string>

extern "C" int createKDB_impl( const char* filename, const char* password, int length, int expiration, gsk_handle* handle);
extern "C" int importKey_impl(const char* filename, const char* password, const char* label, gsk_handle* handle);
extern "C" int exportKeyToFile_impl(const char* filename, const char* password, const char* label, gsk_handle* handle);
extern "C" int exportKeyToBuffer_impl(const char* password, const char* label, gsk_buffer* stream, gsk_handle* handle);
extern "C" int exportCertToBuffer_impl(const char* label, gsk_buffer* stream, gsk_handle* handle);
extern "C" int openKDB_impl( const char* filename, const char* password, gsk_handle* handle);
extern "C" int openKeyRing_impl( const char* ring_name, gsk_handle* handle);
extern "C" char* errorString_impl( int error );

class ZCrypto : public Napi::ObjectWrap<ZCrypto> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  ZCrypto(const Napi::CallbackInfo& info);

 private:
  static Napi::FunctionReference constructor;
  
  Napi::Value OpenKeyRing(const Napi::CallbackInfo &info);
  Napi::Value OpenKDB(const Napi::CallbackInfo &info);
  Napi::Value CreateKDB(const Napi::CallbackInfo &info);
  Napi::Value ImportKey(const Napi::CallbackInfo &info);
  Napi::Value GetErrorString(const Napi::CallbackInfo &info);
  Napi::Value ExportKeyToFile(const Napi::CallbackInfo &info);
  Napi::Value ExportKeyToBuffer(const Napi::CallbackInfo &info);
  Napi::Value ExportCertToBuffer(const Napi::CallbackInfo &info);

  bool initialized;
  gsk_handle handle;
};


#if !defined(__MVS__)
#error This addon is for zos only
#endif

#endif
