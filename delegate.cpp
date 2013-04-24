#include <iostream>
#include <sstream>
#include <fstream>
#include <gnutls/gnutls.h>
using namespace std;

class client {
public:
//initialize the cert
int gnutls_x509_crt_init (gnutls_x509_crt_t * cert);

//import the cert
int gnutls_x509_crt_import (gnutls_x509_crt_t cert, const gnutls_datum_t * data, gnutls_x509_crt_fmt_t format);

//de-initialize the cert
void gnutls_x509_crt_deinit (gnutls_x509_crt_t cert);

//get cert key ID
int gnutls_x509_crt_get_key_id (gnutls_x509_crt_t crt, unsigned int flags, unsigned char * output_data, size_t * output_data_size);

//export the cert
int gnutls_x509_crl_export (gnutls_x509_crl_t crl, gnutls_x509_crt_fmt_t format, void * output_data, size_t * output_data_size);

//print the cert
int gnutls_x509_crl_print (gnutls_x509_crl_t crl, gnutls_certificate_print_formats_t format, gnutls_datum_t * out);

void open_session();
void send_intent();
void send_cert();
void receive_cert();
} client1, client2;

class server {
public:
//initialize the cert
int gnutls_x509_crt_init (gnutls_x509_crt_t * cert);

//import the cert
int gnutls_x509_crt_import (gnutls_x509_crt_t cert, const gnutls_datum_t * data, gnutls_x509_crt_fmt_t format);

//de-initialize the cert
void gnutls_x509_crt_deinit (gnutls_x509_crt_t cert);

//get cert key ID
int gnutls_x509_crt_get_key_id (gnutls_x509_crt_t crt, unsigned int flags, unsigned char * output_data, size_t * output_data_size);

//export the cert
int gnutls_x509_crl_export (gnutls_x509_crl_t crl, gnutls_x509_crt_fmt_t format, void * output_data, size_t * output_data_size);

//print the cert
int gnutls_x509_crl_print (gnutls_x509_crl_t crl, gnutls_certificate_print_formats_t format, gnutls_datum_t * out);

//verify the CRL
int gnutls_x509_crl_verify (gnutls_x509_crl_t crl, const gnutls_x509_crt_t * trusted_cas, int tcas_size, unsigned int flags, unsigned int * verify);

//check if cert has been revoked
int gnutls_x509_crt_check_revocation (gnutls_x509_crt_t cert, const gnutls_x509_crl_t * crl_list, int crl_list_length);

//print the cert
int gnutls_x509_crl_print (gnutls_x509_crl_t crl, gnutls_certificate_print_formats_t format, gnutls_datum_t * out);

//verify signed data for public key
int gnutls_pubkey_verify_data (gnutls_pubkey_t pubkey, unsigned int flags, const gnutls_datum_t * data, const gnutls_datum_t * signature);

//verify certificate
int gnutls_x509_crt_verify_data (gnutls_x509_crt_t crt, unsigned int flags, const gnutls_datum_t * data, const gnutls_datum_t * signature)

} server1;

/*class client: public delegate {
public:
void send_cert ();
void negotiate_key ();
void make_request ();*/



int main ()
{
//import the certificates
client1.gnutls_x509_crt_import ();
client2.gnutls_x509_crt_import ();
server1.gnutls_x509_crt_import ();

//socket code for sending authorization request to server and exchanging certs

//client request for file

//server sends file



return 0;
}
