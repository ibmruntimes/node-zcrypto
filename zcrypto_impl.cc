#include "zcrypto.h"
#include <unistd.h>
#include <sys/stat.h>


extern "C" int __chgfdccsid(int fd, unsigned short ccsid);


extern "C" int createKDB_impl( const char* filename, const char* password, int length, int expiration, gsk_handle* handle) {
    std::string str; 
	char * filename_e = (char*)malloc(strlen(filename) + 1);
	memcpy(filename_e, filename, strlen(filename) + 1);
	__a2e_l(filename_e, strlen(filename_e) + 1);
	char * password_e = (char*)malloc(strlen(password) + 1);
	memcpy(password_e, password, strlen(password) + 1);
	__a2e_l(password_e, strlen(password_e) + 1);
	int rc = gsk_create_database ( filename_e, password_e, gskdb_dbtype_key, length, expiration, handle);
	if (rc !=0 ) { printf("ERROR: %08x\n", rc); }
	return rc;
}

extern "C" int openKDB_impl( const char* filename, const char* password, gsk_handle* handle) {
    std::string str; 
	char * filename_e = (char*)malloc(strlen(filename) + 1);
	memcpy(filename_e, filename, strlen(filename) + 1);
	__a2e_l(filename_e, strlen(filename_e) + 1);
	char * password_e = (char*)malloc(strlen(password) + 1);
	memcpy(password_e, password, strlen(password) + 1);
	__a2e_l(password_e, strlen(password_e) + 1);
    int num_records;
    gskdb_database_type type;
	int rc = gsk_open_database( filename_e, password_e, 1, handle, &type, &num_records);
	if (rc !=0 ) { printf("ERROR: %08x\n", rc); }
	return rc;
}

extern "C" int openKeyRing_impl( const char* ring_name, gsk_handle* handle) {
    std::string str; 
	char * ring_name_e = (char*)malloc(strlen(ring_name) + 1);
	memcpy(ring_name_e, ring_name, strlen(ring_name) + 1);
	__a2e_l(ring_name_e, strlen(ring_name_e) + 1);
    int num_records;
	int rc = gsk_open_keyring( ring_name_e, handle, &num_records);
	if (rc !=0 ) { printf("ERROR: %08x\n", rc); }
	return rc;
}

extern "C" int exportKeyToFile_impl(const char* filename, const char* password, const char* label, gsk_handle* handle) { 
    gsk_buffer stream = {0, 0};

	char * password_e = (char*)malloc(strlen(password) + 1);
	memcpy(password_e, password, strlen(password) + 1);
	__a2e_l(password_e, strlen(password_e) + 1);

	char * label_e = (char*)malloc(strlen(label) + 1);
	memcpy(label_e, label, strlen(label) + 1);
	__a2e_l(label_e, strlen(label_e) + 1);

int rc = gsk_export_key(*handle, label_e, gskdb_export_pkcs12v3_binary, x509_alg_pbeWithSha1And3DesCbc 
, password_e,  &stream);
    if (rc !=0 ) { printf("ERROR: %08x\n", rc); }

    FILE *fileptr;
    fileptr = fopen(filename, "wb");  // Open the file in binary mode
    //fwrite(stream.data, stream.length, 1, fileptr);
	//__chgfdccsid(fileno(fileptr), FT_BINARY);
    write(fileno(fileptr), stream.data, stream.length);
    fclose(fileptr); // Close the file
    fileptr = fopen(filename, "a+");  // Open the file in binary mode
	__chgfdccsid(fileno(fileptr), FT_BINARY);
    fclose(fileptr); // Close the file
    return rc;
}

extern "C" int exportKeyToBuffer_impl(const char* password, const char* label, gsk_buffer* stream, gsk_handle* handle) { 
	char * password_e = (char*)malloc(strlen(password) + 1);
	memcpy(password_e, password, strlen(password) + 1);
	__a2e_l(password_e, strlen(password_e) + 1);

	char * label_e = (char*)malloc(strlen(label) + 1);
	memcpy(label_e, label, strlen(label) + 1);
	__a2e_l(label_e, strlen(label_e) + 1);

    int rc = gsk_export_key(*handle, label_e, gskdb_export_pkcs12v3_binary, x509_alg_pbeWithSha1And3DesCbc 
, password_e, stream);
    if (rc !=0 ) { printf("ERROR: %08x\n", rc); }
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
	fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
	filelen = ftell(fileptr);             // Get the current byte offset in the file
	rewind(fileptr);                      // Jump back to the beginning of the file

	buffer = (char *)malloc((filelen+1)*sizeof(char)); // Enough memory for file + \0
	fread(buffer, filelen, 1, fileptr); // Read in the entire file
	fclose(fileptr); // Close the file 	

	gsk_buffer stream = {(unsigned int)((filelen+1)*sizeof(char)), (void*)buffer};
	
	int rc = gsk_import_key(*handle, label_e, password_e, &stream);
	if (rc !=0 ) { printf("ERROR: %08x\n", rc); }
	return rc;
}

// The supplied stream can represent either the ASN.1 DER encoding for the certificate or the Cryptographic Message Syntax (PKCS #7) 
int importCertificate(char* filename, char* label, gsk_handle* handle) { 
    FILE *fileptr;
	char *buffer;
	long filelen;

	fileptr = fopen(filename, "rb");  // Open the file in binary mode
	fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
	filelen = ftell(fileptr);             // Get the current byte offset in the file
	rewind(fileptr);                      // Jump back to the beginning of the file

	buffer = (char *)malloc((filelen+1)*sizeof(char)); // Enough memory for file + \0
	fread(buffer, filelen, 1, fileptr); // Read in the entire file
	fclose(fileptr); // Close the file 	

	gsk_buffer stream = {(unsigned int)((filelen+1)*sizeof(char)), (void*)buffer};
	
	int rc = gsk_import_certificate(*handle, label, &stream);
	if (rc !=0 ) { printf("ERROR: %08x\n", rc); }
	return rc;
}

// The supplied stream can represent either the ASN.1 DER encoding for the certificate or the Cryptographic Message Syntax (PKCS #7) 
int exportCertificate(char* filename, char* label, gsk_handle* handle) { 
	gsk_buffer stream = {0, 0};

    int rc = gsk_export_certificate (*handle, label, gskdb_export_der_binary, &stream);
	if (rc !=0 ) { printf("ERROR: %08x\n", rc); }

    FILE *fileptr;
	fileptr = fopen(filename, "wb");  // Open the file in binary mode
	fwrite(stream.data, stream.length, 1, fileptr); 
	fclose(fileptr); // Close the file 	
	return rc;
}
