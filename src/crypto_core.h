#ifndef BENCH_CORE_H
#define BENCH_CORE_H
#include <stddef.h>
#include <stdio.h>
#include <openssl/evp.h>

// Carrega os providers 'default' e 'oqsprovider' do OpenSSL.
// Retorna 1 em sucesso, 0 em falha.
int bc_init_providers(void);

// Descarrega os providers previamente carregados.
void bc_shutdown_providers(void);

// Verifica se um algoritmo de assinatura está disponível.
// Retorna 1 se disponível, 0 caso contrário.
int bc_algorithm_available(const char* algorithm_name);

// Par de chaves (ownership do chamador).
typedef struct {
    EVP_PKEY* pkey;
} bc_keypair_t;

// Assinatura alocada com OPENSSL_malloc (ownership do chamador).
typedef struct {
    unsigned char* data;
    size_t len;
} bc_signature_t;

// Gera um par de chaves para o algoritmo especificado.
// Para EC/ECDSA, configura automaticamente a curva prime256v1.
// Retorna 1 em sucesso, 0 em falha.
int bc_keygen(const char* algorithm_name, bc_keypair_t* keypair_out);

// Assina uma mensagem usando a chave privada fornecida.
// Aloca memória para a assinatura (deve ser liberada com bc_signature_free).
// Retorna 1 em sucesso, 0 em falha.
int bc_sign(const bc_keypair_t* keypair,
            const unsigned char* input_msg, size_t input_len,
            bc_signature_t* signature_out);

// Verifica uma assinatura usando a chave pública fornecida.
// Retorna 1 se a assinatura é válida, 0 caso contrário.
int bc_verify(const bc_keypair_t* keypair,
              const unsigned char* input_msg, size_t input_len,
              const bc_signature_t* signature);

// Libera recursos de um par de chaves.
void bc_keypair_free(bc_keypair_t* keypair);

// Libera recursos de uma assinatura.
void bc_signature_free(bc_signature_t* signature);

// Imprime todos os algoritmos de assinatura disponíveis nos providers.
// Retorna o número de algoritmos encontrados.
int bc_print_signature_algs(FILE* out);

// ============================================================================
// Funções de serialização/deserialização (Base64 e PKCS#8 DER)
// ============================================================================

// Converte EVP_PKEY para formato PKCS#8 DER.
// Retorna 1 em sucesso, 0 em falha.
// Em caso de sucesso, *out aponta para buffer alocado (caller deve liberar com OPENSSL_free).
int bc_pkey_to_pkcs8_der(EVP_PKEY* pkey, unsigned char** out, int* out_len);

// Converte PKCS#8 DER para EVP_PKEY.
// Retorna EVP_PKEY* em sucesso, NULL em falha.
// Caller deve liberar com EVP_PKEY_free.
EVP_PKEY* bc_pkcs8_der_to_pkey(const unsigned char* der, size_t der_len);

// Imprime dados binários como Base64 em stdout (uma linha, sem quebras).
void bc_b64_print_line(const unsigned char* data, size_t data_len);

// Decodifica string Base64 (ignora whitespace) para binário.
// Retorna 1 em sucesso, 0 em falha.
// Em caso de sucesso, *out aponta para buffer alocado (caller deve liberar com OPENSSL_free).
int bc_b64_decode(const char* input, unsigned char** out, size_t* out_len);

#endif