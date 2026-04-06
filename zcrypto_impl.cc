/*
 * Licensed Materials - Property of IBM
 * (C) Copyright IBM Corp. 2022. All Rights Reserved.
 * US Government Users Restricted Rights - Use, duplication or disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
 */

#include "zcrypto.h"
#include <_Nascii.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef DEBUG
#include <mutex>
#include <libgen.h>
#include <stdarg.h>
#endif


extern "C" int __chgfdccsid(int fd, unsigned short ccsid);

extern "C" int createKDB_impl( const char* filename, const char* password, int length, int expiration, gsk_handle* handle) {
  char * filename_e = (char*)malloc(strlen(filename) + 1);
  memcpy(filename_e, filename, strlen(filename) + 1);
  __a2e_l(filename_e, strlen(filename_e) + 1);
  char * password_e = (char*)malloc(strlen(password) + 1);
  memcpy(password_e, password, strlen(password) + 1);
  __a2e_l(password_e, strlen(password_e) + 1);

  int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
  int rc = gsk_create_database ( filename_e, password_e, gskdb_dbtype_key, length, expiration, handle);
  __ae_thread_swapmode(orig);

  DPRINTF("%sgsk_create_database(filename=%s, gskdb_dbtype_key, len=%d, "
          "exp=%d, handle=%p): rc=%d%s\n",
          (rc == 0) ? "" : "ERROR ", filename, length, expiration, handle, rc,
          getErrStr(rc));

  free(filename_e);
  free(password_e);
  return rc;
}

extern "C" int openKDB_impl( const char* filename, const char* password, gsk_handle* handle) {
  char * filename_e = (char*)malloc(strlen(filename) + 1);
  memcpy(filename_e, filename, strlen(filename) + 1);
  __a2e_l(filename_e, strlen(filename_e) + 1);
  char * password_e = (char*)malloc(strlen(password) + 1);
  memcpy(password_e, password, strlen(password) + 1);
  __a2e_l(password_e, strlen(password_e) + 1);
  int num_records;
  gskdb_database_type type;

  int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
  int rc = gsk_open_database( filename_e, password_e, 1, handle, &type, &num_records);
  __ae_thread_swapmode(orig);

  DPRINTF("%sgsk_open_database(filename=%s, 1, handle=%p) type=%d, "
          "num_records=%d, rc=%d%s\n",
          (rc == 0) ? "" : "ERROR ", filename, handle, type, num_records, rc,
          getErrStr(rc));

  free(filename_e);
  free(password_e);
  return rc;
}

extern "C" int closeKDB_impl( gsk_handle* handle) {
  if (handle == nullptr || *handle == nullptr)
    return 0;
  int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
  int rc = gsk_close_database( handle );
  __ae_thread_swapmode(orig);

  DPRINTF("%sgsk_close_database(handle=%p): rc=%d%s\n",
          (rc == 0) ? "" : "ERROR ", handle, rc, getErrStr(rc));

  return rc;
}

extern "C" char* errorString_impl( int err, char *errstr, int errstrlen ) {
  int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
  const char* errstr_e  = gsk_strerror( err );
  __ae_thread_swapmode(orig);
  strncpy(errstr, errstr_e, errstrlen);
  __e2a_l(errstr, errstrlen);
  return errstr;
}

extern "C" int openKeyRing_impl( const char* ring_name, gsk_handle* handle) {
  char * ring_name_e = (char*)malloc(strlen(ring_name) + 1);
  memcpy(ring_name_e, ring_name, strlen(ring_name) + 1);
  __a2e_l(ring_name_e, strlen(ring_name_e) + 1);
  int num_records;
  int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
  int rc = gsk_open_keyring( ring_name_e, handle, &num_records);
  free(ring_name_e);
  __ae_thread_swapmode(orig);

  DPRINTF(
      "%sgsk_open_keyring(*ringname=%s, handle=%p) num_records=%d: rc=%d%s\n",
      (rc == 0) ? "" : "ERROR ", ring_name, handle, num_records, rc,
      getErrStr(rc));

  return rc;
}

extern "C" int exportKeyToFile_impl(const char* filename, const char* password, const char* label, gsk_handle* handle) {
  char * password_e = (char*)malloc(strlen(password) + 1);
  memcpy(password_e, password, strlen(password) + 1);
  __a2e_l(password_e, strlen(password_e) + 1);

  char * label_e = (char*)malloc(strlen(label) + 1);
  memcpy(label_e, label, strlen(label) + 1);
  __a2e_l(label_e, strlen(label_e) + 1);

  gsk_buffer stream = {0, 0};
  int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
  int rc = gsk_export_key(*handle, label_e, gskdb_export_pkcs12v3_binary,
                          x509_alg_pbeWithSha1And3DesCbc, password_e,
                          &stream);
  __ae_thread_swapmode(orig);

  DPRINTF("%sgsk_export_key(handle=%p, label=%s, gskdb_export_pkcs12v3_binary, "
          "x509_alg_pbeWithSha1And3DesCbc) stream={%u,%p}: rc=%d%s\n",
          (rc == 0) ? "" : "ERROR ", handle, label, stream.length, stream.data,
          rc, getErrStr(rc));

  free(password_e);
  free(label_e);
  if (rc !=0 ) {
    gsk_free_buffer(&stream);
    return rc;
  }
  FILE *fileptr = fopen(filename, "wb");  // Open the file in binary mode

  DPRINTF("%sfopen(%s, wb): errno=%d\n", (fileptr != NULL) ? "" : "ERROR ",
          filename, errno);

  rc = write(fileno(fileptr), stream.data, stream.length);
  DPRINTF("%swrite(%s, data=%p, len=%d): rc=%d, errno=%d\n",
          (rc == static_cast<int>(stream.length)) ? "" : "ERROR ", filename,
          stream.data, stream.length, rc, errno);

  gsk_free_buffer(&stream);
  fclose(fileptr); // Close the file
  fileptr = fopen(filename, "a+");  // Open the file in binary mode

  DPRINTF("%sfopen(%s, a+): errno=%d\n", (fileptr != NULL) ? "" : "ERROR ",
          filename, errno);

  rc = __chgfdccsid(fileno(fileptr), FT_BINARY);

  DPRINTF("%s__chgfdccsid(filename=%s, FT_BINARY): rc=%d, errno=%d\n",
          (rc == 0) ? "" : "ERROR ", filename, rc, errno);

  fclose(fileptr); // Close the file
  return rc;
}

extern "C" int exportCertToFile_impl(const char* filename, const char* label, gsk_handle* handle) {
  char * label_e = (char*)malloc(strlen(label) + 1);
  memcpy(label_e, label, strlen(label) + 1);
  __a2e_l(label_e, strlen(label_e) + 1);

  gsk_buffer stream = {0, 0};
  int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
  int rc = gsk_export_certificate(*handle, label_e, gskdb_export_der_binary, &stream);
  __ae_thread_swapmode(orig);
  free(label_e);

  DPRINTF(
      "%sgsk_export_certificate(handle=%p, label=%s, gskdb_export_der_binary) "
      "stream={%u,%p}: rc=%d%s\n",
      (rc == 0) ? "" : "ERROR ", handle, label, stream.length, stream.data, rc,
      getErrStr(rc));

  if (rc !=0 ) {
    gsk_free_buffer(&stream);
    return rc;
  }

  FILE *fileptr = fopen(filename, "wb");  // Open the file in binary mode

  DPRINTF("%sfopen(%s, wb): errno=%d\n", (fileptr != NULL) ? "" : "ERROR ",
          filename, errno);

  rc = write(fileno(fileptr), stream.data, stream.length);

  DPRINTF("%swrite(%s, data=%p, len=%d): rc=%d, errno=%d\n",
          (rc == static_cast<int>(stream.length)) ? "" : "ERROR ", filename,
          stream.data, stream.length, rc, errno);

  gsk_free_buffer(&stream);
  fclose(fileptr); // Close the file
  fileptr = fopen(filename, "a+");  // Open the file in binary mode

  DPRINTF("%sfopen(%s, a+): errno=%d\n", (fileptr != NULL) ? "" : "ERROR ",
          filename, errno);

  rc = __chgfdccsid(fileno(fileptr), FT_BINARY);

  DPRINTF("%s__chgfdccsid(filename=%s, FT_BINARY): rc=%d, errno=%d\n",
          (rc == 0) ? "" : "ERROR ", filename, rc, errno);

  fclose(fileptr); // Close the file
  return rc;
}

extern "C" int exportCertToBuffer_impl(const char* label, gsk_buffer* stream, gsk_handle* handle) {
  char * label_e = (char*)malloc(strlen(label) + 1);
  memcpy(label_e, label, strlen(label) + 1);
  __a2e_l(label_e, strlen(label_e) + 1);

  int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
  int rc = gsk_export_certificate(*handle, label_e, gskdb_export_der_binary, stream);
  __ae_thread_swapmode(orig);

  DPRINTF(
      "%sgsk_export_certificate(handle=%p, label=%s, gskdb_export_der_binary, "
      "stream={%d, %p}): rc=%d%s\n",
      (rc == 0) ? "" : "ERROR ", handle, label, stream->length, stream->data,
      rc, getErrStr(rc));

  free(label_e);
  return rc;
}

extern "C" int exportKeyToBuffer_impl(const char* password, const char* label, gsk_buffer* stream, gsk_handle* handle) {
  char * password_e = (char*)malloc(strlen(password) + 1);
  memcpy(password_e, password, strlen(password) + 1);
  __a2e_l(password_e, strlen(password_e) + 1);

  char * label_e = (char*)malloc(strlen(label) + 1);
  memcpy(label_e, label, strlen(label) + 1);
  __a2e_l(label_e, strlen(label_e) + 1);

  int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
  int rc = gsk_export_key(*handle, label_e, gskdb_export_pkcs12v3_binary,
                          x509_alg_pbeWithSha1And3DesCbc, password_e, stream);
  __ae_thread_swapmode(orig);

  DPRINTF("%sgsk_export_key(handle=%p, label=%s, gskdb_export_pkcs12v3_binary, "
          "x509_alg_pbeWithSha1And3DesCbc, stream={%u,%p}): rc=%d%s\n",
          (rc == 0) ? "" : "ERROR ", handle, label, stream->length,
          stream->data, rc, getErrStr(rc));

  free(password_e);
  free(label_e);
  return rc;
}

extern "C" int importKey_impl(const char* filename, const char* password, const char* label, gsk_handle* handle) {
  char * buffer;
  long filelen;

  char * filename_e = (char*)malloc(strlen(filename) + 1);
  memcpy(filename_e, filename, strlen(filename) + 1);
  __a2e_l(filename_e, strlen(filename_e) + 1);

  char * password_e = (char*)malloc(strlen(password) + 1);
  memcpy(password_e, password, strlen(password) + 1);
  __a2e_l(password_e, strlen(password_e) + 1);

  char * label_e = (char*)malloc(strlen(label) + 1);
  memcpy(label_e, label, strlen(label) + 1);
  __a2e_l(label_e, strlen(label_e) + 1);

  FILE *fileptr = fopen(filename, "rb");  // Open the file in binary mode

  DPRINTF("%sfopen(%s, rb): errno=%d\n", (fileptr != NULL) ? "" : "ERROR ",
          filename, errno);

  int rc = fseek(fileptr, 0, SEEK_END);      // Jump to the end of the file

  DPRINTF("%sfseek(%s, 0, SEEK_END): rc=%d, errno=%d\n",
          (rc == 0) ? "" : "ERROR ", filename, rc, errno);

  filelen = ftell(fileptr);         // Get the current byte offset in the file
  rewind(fileptr);                  // Jump back to the beginning of the file

  buffer = (char *)malloc((filelen+1)*sizeof(char)); // Enough memory for file + \0
  rc = fread(buffer, filelen, 1, fileptr); // Read in the entire file

  DPRINTF("%sfread(len=%d, 1, filenmae=%s): rc=%d, errno=%d\n",
          (rc == 1) ? "" : "ERROR ", filelen, filename, rc, errno);

  fclose(fileptr); // Close the file

  gsk_buffer stream = {(unsigned int)((filelen+1)*sizeof(char)), (void*)buffer};

  int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
  rc = gsk_import_key(*handle, label_e, password_e, &stream);
  __ae_thread_swapmode(orig);

  DPRINTF("%sgsk_import_key(handle=%p, label=%s) stream={%u,%p}: rc=%d%s\n",
          (rc == 0) ? "" : "ERROR ", handle, label, stream.length, stream.data,
          rc, getErrStr(rc));

  free(filename_e);
  free(password_e);
  free(label_e);
  free(buffer);
  if (stream.data != buffer) {
    gsk_free_buffer(&stream);
    DPRINTF("NOTE: gsk_free_buffer due to %p != %p\n", stream.data, buffer);
  }
  return rc;
}

// The supplied stream can represent either the ASN.1 DER encoding for the certificate or the Cryptographic Message Syntax (PKCS #7)
int importCertificate(char* filename, char* label, gsk_handle* handle) {
  FILE *fileptr = fopen(filename, "rb");  // Open the file in binary mode

  DPRINTF("%sfopen(%s, rb): errno=%d\n", (fileptr != NULL) ? "" : "ERROR ",
          filename, errno);

  int rc = fseek(fileptr, 0, SEEK_END);      // Jump to the end of the file

  DPRINTF("%sfseek(%s, 0, SEEK_END): rc=%d, errno=%d\n",
          (rc == 0) ? "" : "ERROR ", filename, rc, errno);

  int filelen = ftell(fileptr);         // Get the current byte offset in the file
  rewind(fileptr);                  // Jump back to the beginning of the file

  char *buffer = (char *)malloc((filelen+1)*sizeof(char)); // Enough memory for file + \0
  rc = fread(buffer, filelen, 1, fileptr); // Read in the entire file

  DPRINTF("%sfread(len=%d, 1, filenmae=%s: rc=%d, errno=%d\n",
          (rc == 1) ? "" : "ERROR ", filelen, filename, rc, errno);

  fclose(fileptr); // Close the file

  gsk_buffer stream = {(unsigned int)((filelen+1)*sizeof(char)), (void*)buffer};

  char *label_e = (char*)malloc(strlen(label) + 1);
  memcpy(label_e, label, strlen(label) + 1);
  __a2e_l(label_e, strlen(label_e) + 1);

  int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
  rc = gsk_import_certificate(*handle, label_e, &stream);
  __ae_thread_swapmode(orig);
  free(label_e);

  DPRINTF("%sgsk_import_certificate(handle=%p, label=%s) stream={%u,%p}): "
          "rc=%d%s\n",
          (rc == 0) ? "" : "ERROR ", handle, label, stream.length, stream.data,
          rc, getErrStr(rc));

  free(buffer);
  if (stream.data != buffer) {
    gsk_free_buffer(&stream);
    DPRINTF("NOTE: gsk_free_buffer due to %p != %p\n", stream.data, buffer);
  }
  return rc;
}

// The supplied stream can represent either the ASN.1 DER encoding for the certificate or the Cryptographic Message Syntax (PKCS #7)
int exportCertificate(char* filename, char* label, gsk_handle* handle) {
  gsk_buffer stream = {0, 0};

  char *label_e = (char*)malloc(strlen(label) + 1);
  memcpy(label_e, label, strlen(label) + 1);
  __a2e_l(label_e, strlen(label_e) + 1);

  int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
  int rc = gsk_export_certificate (*handle, label_e, gskdb_export_der_binary, &stream);
  __ae_thread_swapmode(orig);
  free(label_e);

  DPRINTF("%sgsk_export_certificate(handle=%p, label=%s, "
          "gskdb_export_der_binary) stream={%d, %p}: rc=%d%s\n",
          (rc == 0) ? "" : "ERROR ", handle, label, stream.length, stream.data,
          rc, getErrStr(rc));

  FILE *fileptr = fopen(filename, "wb");  // Open the file in binary mode

  DPRINTF("%sfopen(%s, wb) errno=%d\n", (fileptr != NULL) ? "" : "ERROR ",
          filename, errno);

  rc = fwrite(stream.data, stream.length, 1, fileptr);

  DPRINTF("%sfwrite(data=%p, len=%d, 1, %s): rc=%d, errno=%d\n",
          (rc == 0) ? "" : "ERROR ", stream.data, stream.length, filename, rc,
          errno);

  gsk_free_buffer(&stream);
  fclose(fileptr); // Close the file
  return rc;
}


#ifdef DEBUG
char* getErrStr(int rc) {
  // This is called for rc from gsk_ APIs only.
  static std::mutex mtx;
  std::lock_guard<std::mutex> lock(mtx);
  static char errstr[256];
  if (rc == 0) {
    *errstr = 0;
  } else {
    int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
    const char* errstr_e  = gsk_strerror(rc);
    __ae_thread_swapmode(orig);
    char rcstr[256];
    strncpy(rcstr, errstr_e, sizeof(rcstr));
    __e2a_l(rcstr, sizeof(rcstr));
    snprintf(errstr, sizeof(errstr), " (%s) ", rcstr);
  }
  return errstr;
}

void dbgPrintf(const char *fname, int linenum, const char *funcname,
               const char *format, ...) {
  static std::mutex mtx;
  std::lock_guard<std::mutex> lock(mtx);
  static const char *logfname = getenv("ZCRYPTO_LOGFILE");
  if (!logfname)
    return;

  va_list args;
  va_start(args, format);
  static bool isstderr = !strcmp(logfname, "stderr");
  static bool isstdout = !strcmp(logfname, "stdout");
  static FILE *fp = NULL;
  static bool binit = false;
  if (binit && fp == NULL)
    return;

  fp = isstderr ? stderr : isstdout ? stdout : fopen(logfname, "a+");

  if (fp == NULL) {
    va_end(args);
    perror(logfname);
    binit = true;
    return;
  }
  fprintf(fp, "In %s:%d:%s ", fname, linenum, funcname);
  vfprintf(fp, format, args);
  va_end(args);
  if (fp != stderr)
    fflush(fp);
}
#endif
