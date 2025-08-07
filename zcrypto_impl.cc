/*
 * Licensed Materials - Property of IBM
 * (C) Copyright IBM Corp. 2022. All Rights Reserved.
 * US Government Users Restricted Rights - Use, duplication or disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
 */

#include "zcrypto.h"
#include <_Nascii.h>
#include <sys/stat.h>
#include <unistd.h>


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
  int rc = gsk_export_key(*handle, label_e, gskdb_export_pkcs12v3_binary,
                          x509_alg_pbeWithSha1And3DesCbc, password_e,
                          &stream);

  free(password_e);
  free(label_e);
  if (rc !=0 ) {
    gsk_free_buffer(&stream);
    return rc;
  }
  FILE *fileptr;
  fileptr = fopen(filename, "wb");  // Open the file in binary mode
  write(fileno(fileptr), stream.data, stream.length);
  gsk_free_buffer(&stream);
  fclose(fileptr); // Close the file
  fileptr = fopen(filename, "a+");  // Open the file in binary mode
  __chgfdccsid(fileno(fileptr), FT_BINARY);
  fclose(fileptr); // Close the file
  return rc;
}

extern "C" int exportCertToFile_impl(const char* filename, const char* label, gsk_handle* handle) {
  char * label_e = (char*)malloc(strlen(label) + 1);
  memcpy(label_e, label, strlen(label) + 1);
  __a2e_l(label_e, strlen(label_e) + 1);

  gsk_buffer stream = {0, 0};
  int rc = gsk_export_certificate(*handle, label_e, gskdb_export_der_binary, &stream);
  free(label_e);
  if (rc !=0 ) {
    gsk_free_buffer(&stream);
    return rc;
  }

  FILE *fileptr;
  fileptr = fopen(filename, "wb");  // Open the file in binary mode
  write(fileno(fileptr), stream.data, stream.length);
  gsk_free_buffer(&stream);
  fclose(fileptr); // Close the file
  fileptr = fopen(filename, "a+");  // Open the file in binary mode
  __chgfdccsid(fileno(fileptr), FT_BINARY);
  fclose(fileptr); // Close the file
  return rc;
}

extern "C" int exportCertToBuffer_impl(const char* label, gsk_buffer* stream, gsk_handle* handle) {
  char * label_e = (char*)malloc(strlen(label) + 1);
  memcpy(label_e, label, strlen(label) + 1);
  __a2e_l(label_e, strlen(label_e) + 1);

  int rc = gsk_export_certificate(*handle, label_e, gskdb_export_der_binary, stream);
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

  int rc = gsk_export_key(*handle, label_e, gskdb_export_pkcs12v3_binary,
                          x509_alg_pbeWithSha1And3DesCbc, password_e, stream);
  free(password_e);
  free(label_e);
  return rc;
}

extern "C" int importKey_impl(const char* filename, const char* password, const char* label, gsk_handle* handle) {
  FILE *fileptr;
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

  fileptr = fopen(filename, "rb");  // Open the file in binary mode
  fseek(fileptr, 0, SEEK_END);      // Jump to the end of the file
  filelen = ftell(fileptr);         // Get the current byte offset in the file
  rewind(fileptr);                  // Jump back to the beginning of the file

  buffer = (char *)malloc((filelen+1)*sizeof(char)); // Enough memory for file + \0
  fread(buffer, filelen, 1, fileptr); // Read in the entire file
  fclose(fileptr); // Close the file

  gsk_buffer stream = {(unsigned int)((filelen+1)*sizeof(char)), (void*)buffer};

  int rc = gsk_import_key(*handle, label_e, password_e, &stream);

  free(filename_e);
  free(password_e);
  free(label_e);
  free(buffer);
  if (stream.data != buffer)
    gsk_free_buffer(&stream);
  return rc;
}

// The supplied stream can represent either the ASN.1 DER encoding for the certificate or the Cryptographic Message Syntax (PKCS #7)
int importCertificate(char* filename, char* label, gsk_handle* handle) {
  FILE *fileptr;
  char *buffer;
  long filelen;

  fileptr = fopen(filename, "rb");  // Open the file in binary mode
  fseek(fileptr, 0, SEEK_END);      // Jump to the end of the file
  filelen = ftell(fileptr);         // Get the current byte offset in the file
  rewind(fileptr);                  // Jump back to the beginning of the file

  buffer = (char *)malloc((filelen+1)*sizeof(char)); // Enough memory for file + \0
  fread(buffer, filelen, 1, fileptr); // Read in the entire file
  fclose(fileptr); // Close the file

  gsk_buffer stream = {(unsigned int)((filelen+1)*sizeof(char)), (void*)buffer};

  int rc = gsk_import_certificate(*handle, label, &stream);
  free(buffer);
  if (stream.data != buffer)
    gsk_free_buffer(&stream);
  return rc;
}

// The supplied stream can represent either the ASN.1 DER encoding for the certificate or the Cryptographic Message Syntax (PKCS #7)
int exportCertificate(char* filename, char* label, gsk_handle* handle) {
  gsk_buffer stream = {0, 0};

  int rc = gsk_export_certificate (*handle, label, gskdb_export_der_binary, &stream);

  FILE *fileptr;
  fileptr = fopen(filename, "wb");  // Open the file in binary mode
  fwrite(stream.data, stream.length, 1, fileptr);
  gsk_free_buffer(&stream);
  fclose(fileptr); // Close the file
  return rc;
}
