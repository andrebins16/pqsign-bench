#define _POSIX_C_SOURCE 200809L
#include "crypto_core.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <stdlib.h>

#define BC_LOG(fmt, ...) fprintf(stderr, "[core] " fmt "\n", ##__VA_ARGS__)

// Providers globais
static OSSL_PROVIDER* provider_default = NULL;
static OSSL_PROVIDER* provider_oqs = NULL;

// Carrega os providers 'default' e 'oqsprovider' do OpenSSL.
// Deve ser chamado uma vez antes de usar qualquer primitiva criptográfica.
// Retorna 1 em sucesso, 0 em falha.
int bc_init_providers(void) {
    provider_default = OSSL_PROVIDER_load(NULL, "default");
    if (!provider_default) {
        BC_LOG("ERRO: falha ao carregar provider 'default'");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    provider_oqs = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!provider_oqs) {
        BC_LOG("ERRO: falha ao carregar provider 'oqsprovider'");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    return 1;
}

// Descarrega os providers previamente carregados.
// Deve ser chamado no final da execução para liberar recursos.
void bc_shutdown_providers(void) {
    if (provider_oqs) {
        OSSL_PROVIDER_unload(provider_oqs);
        provider_oqs = NULL;
    }
    if (provider_default) {
        OSSL_PROVIDER_unload(provider_default);
        provider_default = NULL;
    }
}

// Verifica se o nome do algoritmo é EC ou ECDSA (case-insensitive).
static int is_ec_like_name(const char* name) {
    return name && (!strcasecmp(name, "EC") || !strcasecmp(name, "ECDSA"));
}

// Verifica se um algoritmo de assinatura está disponível nos providers carregados.
// Para EC/ECDSA, testa também se é possível configurar a curva prime256v1.
// Retorna 1 se disponível, 0 caso contrário.
int bc_algorithm_available(const char* algorithm_name) {
    // Tenta criar contexto de keygen para o algoritmo
    EVP_PKEY_CTX* keygen_ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm_name, NULL);
    if (!keygen_ctx) {
        return 0;
    }

    // Tenta inicializar o contexto
    int success = (EVP_PKEY_keygen_init(keygen_ctx) > 0);

    // Para EC, valida se consegue configurar a curva
    if (success && is_ec_like_name(algorithm_name)) {
        OSSL_PARAM ec_params[2];
        ec_params[0] = OSSL_PARAM_construct_utf8_string("group", "prime256v1", 0);
        ec_params[1] = OSSL_PARAM_construct_end();

        success = (EVP_PKEY_CTX_set_params(keygen_ctx, ec_params) > 0);
    }

    EVP_PKEY_CTX_free(keygen_ctx);
    return success;
}

// Gera um par de chaves para o algoritmo especificado.
// Para EC/ECDSA, configura automaticamente a curva prime256v1 (secp256r1).
// Retorna 1 em sucesso, 0 em falha.
// Em caso de sucesso, keypair_out->pkey contém a chave gerada.
int bc_keygen(const char* algorithm_name, bc_keypair_t* keypair_out) {
    if (!algorithm_name || !*algorithm_name || !keypair_out) {
        BC_LOG("ERRO: parâmetros inválidos para bc_keygen");
        return 0;
    }

    memset(keypair_out, 0, sizeof(*keypair_out));

    // Cria contexto de geração de chave
    EVP_PKEY_CTX* keygen_ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm_name, NULL);
    if (!keygen_ctx) {
        BC_LOG("ERRO: falha ao criar contexto de keygen (%s)", algorithm_name);
        return 0;
    }

    // Inicializa o contexto
    if (EVP_PKEY_keygen_init(keygen_ctx) <= 0) {
        BC_LOG("ERRO: keygen_init falhou (%s)", algorithm_name);
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(keygen_ctx);
        return 0;
    }

    // Configura curva para EC/ECDSA
    if (is_ec_like_name(algorithm_name)) {
        OSSL_PARAM ec_params[2];
        ec_params[0] = OSSL_PARAM_construct_utf8_string("group", "prime256v1", 0);
        ec_params[1] = OSSL_PARAM_construct_end();

        if (EVP_PKEY_CTX_set_params(keygen_ctx, ec_params) <= 0) {
            BC_LOG("ERRO: falha em set_params(group=prime256v1) para %s", algorithm_name);
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(keygen_ctx);
            return 0;
        }
    }

    // Gera a chave
    int success = (EVP_PKEY_keygen(keygen_ctx, &keypair_out->pkey) > 0 &&
                   keypair_out->pkey != NULL);

    if (!success) {
        BC_LOG("ERRO: geração de chave falhou (%s)", algorithm_name);
        ERR_print_errors_fp(stderr);
        if (keypair_out->pkey) {
            EVP_PKEY_free(keypair_out->pkey);
            keypair_out->pkey = NULL;
        }
    }

    EVP_PKEY_CTX_free(keygen_ctx);
    return success;
}


// Assina uma mensagem usando a chave privada fornecida.
// Usa DigestSign do OpenSSL (combina hash + assinatura automaticamente).
// Retorna 1 em sucesso, 0 em falha.
// Em caso de sucesso, signature_out contém a assinatura (data e len).
int bc_sign(const bc_keypair_t* keypair,
            const unsigned char* input_msg, size_t input_len,
            bc_signature_t* signature_out) {
    if (!keypair || !keypair->pkey || !input_msg || !signature_out) return 0;

    memset(signature_out, 0, sizeof(*signature_out));

    // Cria contexto de digest para assinatura
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        BC_LOG("ERRO: falha ao criar contexto EVP_MD_CTX_new");
        return 0;
    }

    // Inicializa operação de assinatura (hash automático)
    if (EVP_DigestSignInit_ex(md_ctx, NULL, NULL, NULL, NULL, keypair->pkey, NULL) <= 0) {
        BC_LOG("ERRO: falha ao inicializar DigestSignInit");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    // Descobre tamanho necessário para a assinatura
    size_t sig_len = 0;
    if (EVP_DigestSign(md_ctx, NULL, &sig_len, input_msg, input_len) <= 0) {
        BC_LOG("ERRO: falha ao descobrir tamanho da assinatura");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    // Aloca buffer para assinatura
    unsigned char* sig_buf = (unsigned char*)OPENSSL_malloc(sig_len);
    if (!sig_buf) {
        BC_LOG("ERRO: falha ao alocar buffer para assinatura de %zu bytes", sig_len);
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    // Gera a assinatura
    if (EVP_DigestSign(md_ctx, sig_buf, &sig_len, input_msg, input_len) <= 0) {
        BC_LOG("ERRO: falha ao gerar assinatura");
        ERR_print_errors_fp(stderr);
        OPENSSL_free(sig_buf);
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    EVP_MD_CTX_free(md_ctx);

    // Retorna assinatura gerada
    signature_out->data = sig_buf;
    signature_out->len  = sig_len;
    return 1;
}


// Verifica uma assinatura usando a chave pública fornecida.
// Usa DigestVerify do OpenSSL (combina hash + verificação automaticamente).
// Retorna 1 se a assinatura é válida, 0 caso contrário.
int bc_verify(const bc_keypair_t* keypair,
              const unsigned char* input_msg, size_t input_len,
              const bc_signature_t* signature) {
    if (!keypair || !keypair->pkey || !input_msg || !signature || !signature->data) return 0;

    // Cria contexto de digest para verificação
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        BC_LOG("ERRO: falha ao criar contexto EVP_MD_CTX_new");
        return 0;
    }

    // Inicializa operação de verificação
    if (EVP_DigestVerifyInit_ex(md_ctx, NULL, NULL, NULL, NULL, keypair->pkey, NULL) <= 0) {
        BC_LOG("ERRO: falha ao inicializar DigestVerifyInit");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    // Verifica assinatura (retorna 1 se válida, <=0 caso contrário)
    int verify_rc = EVP_DigestVerify(md_ctx,
                                     signature->data, signature->len,
                                     input_msg, input_len);

    EVP_MD_CTX_free(md_ctx);
    return verify_rc == 1;
}

// Libera recursos de um par de chaves.
void bc_keypair_free(bc_keypair_t* keypair) {
    if (!keypair) return;

    if (keypair->pkey) {
        EVP_PKEY_free(keypair->pkey);
    }
    keypair->pkey = NULL;
}

// Libera recursos de uma assinatura.
void bc_signature_free(bc_signature_t* signature) {
    if (!signature) return;

    if (signature->data) {
        OPENSSL_free(signature->data);
    }
    signature->data = NULL;
    signature->len  = 0;
}


// Conjunto dinâmico para armazenar nomes de algoritmos sem duplicatas
typedef struct {
    char**  names;      // array de strings (nomes de algoritmos)
    size_t  count;      // quantidade de nomes armazenados
    size_t  capacity;   // capacidade alocada do array
} bc_name_set_t;

// Adiciona um nome ao conjunto se ainda não existir.
// Retorna 1 se adicionou, 0 se já existia ou houve erro.
static int bc_names_add_unique(bc_name_set_t* set, const char* name) {
    if (!set || !name || *name == '\0') return 0;

    // Verifica se nome já existe
    for (size_t i = 0; i < set->count; i++) {
        if (strcmp(set->names[i], name) == 0) {
            return 0;  // duplicata
        }
    }

    // Expande capacidade se necessário
    if (set->count == set->capacity) {
        size_t new_capacity = set->capacity ? set->capacity * 2 : 32;
        char** new_names = (char**)realloc(set->names, new_capacity * sizeof(char*));
        if (!new_names) return 0;
        
        set->names = new_names;
        set->capacity = new_capacity;
    }

    // Adiciona cópia do nome
    char* name_copy = strdup(name);
    if (!name_copy) return 0;

    set->names[set->count++] = name_copy;
    return 1;
}

// Callback para cada alias de um algoritmo (chamado pelo OpenSSL)
static void bc_sig_names_cb(const char* name, void* user_data) {
    bc_names_add_unique((bc_name_set_t*)user_data, name);
}

// Callback principal para cada implementação de assinatura (chamado pelo OpenSSL)
static void bc_sig_collect_cb(EVP_SIGNATURE* sig, void* user_data) {
    // Coleta todos os nomes/aliases deste algoritmo
    (void)EVP_SIGNATURE_names_do_all(sig, bc_sig_names_cb, user_data);
}

// Imprime todos os algoritmos de assinatura disponíveis nos providers carregados.
// Cada algoritmo é impresso em uma linha separada.
// Retorna o número de algoritmos encontrados.
int bc_print_signature_algs(FILE* out) {
    if (!out) out = stdout;

    bc_name_set_t set = {0};

    // Percorre todos os algoritmos expostos pelos providers
    EVP_SIGNATURE_do_all_provided(NULL, bc_sig_collect_cb, &set);

    // Imprime lista de algoritmos
    for (size_t i = 0; i < set.count; i++) {
        fprintf(out, "%s\n", set.names[i]);
    }

    BC_LOG("INFO: listados %zu algoritmos de assinatura", set.count);

    // Libera memória alocada
    for (size_t i = 0; i < set.count; i++) {
        free(set.names[i]);
    }
    free(set.names);

    return (int)set.count;
}

// Converte EVP_PKEY para formato PKCS#8 DER.
// Retorna 1 em sucesso, 0 em falha.
// Em caso de sucesso, *out aponta para buffer alocado (caller deve liberar com OPENSSL_free).
int bc_pkey_to_pkcs8_der(EVP_PKEY* pkey, unsigned char** out, int* out_len) {
    *out = NULL;
    *out_len = 0;
    if (!pkey) return 0;

    // Converte para estrutura PKCS#8
    PKCS8_PRIV_KEY_INFO* p8_info = EVP_PKEY2PKCS8(pkey);
    if (!p8_info) return 0;

    // Serializa para DER
    int der_len = i2d_PKCS8_PRIV_KEY_INFO(p8_info, out);
    PKCS8_PRIV_KEY_INFO_free(p8_info);

    if (der_len <= 0) {
        if (*out) {
            OPENSSL_free(*out);
            *out = NULL;
        }
        return 0;
    }

    *out_len = der_len;
    return 1;
}

// Converte PKCS#8 DER para EVP_PKEY.
// Retorna EVP_PKEY* em sucesso, NULL em falha.
// Caller deve liberar com EVP_PKEY_free.
EVP_PKEY* bc_pkcs8_der_to_pkey(const unsigned char* der, size_t der_len) {
    if (!der || der_len == 0) return NULL;

    const unsigned char* der_ptr = der;
    PKCS8_PRIV_KEY_INFO* p8_info = d2i_PKCS8_PRIV_KEY_INFO(NULL, &der_ptr, (long)der_len);
    if (!p8_info) return NULL;

    EVP_PKEY* pkey = EVP_PKCS82PKEY(p8_info);
    PKCS8_PRIV_KEY_INFO_free(p8_info);
    return pkey;
}

// Imprime dados binários como Base64 em stdout (uma linha, sem quebras).
void bc_b64_print_line(const unsigned char* data, size_t data_len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_push(b64, out);
    (void)BIO_write(b64, data, (int)data_len);
    (void)BIO_flush(b64);
    BIO_free_all(b64);
    fputc('\n', stdout);
}

// Decodifica string Base64 (ignora whitespace) para binário.
// Retorna 1 em sucesso, 0 em falha.
// Em caso de sucesso, *out aponta para buffer alocado (caller deve liberar com OPENSSL_free).
int bc_b64_decode(const char* input, unsigned char** out, size_t* out_len) {
    *out = NULL;
    *out_len = 0;
    if (!input) return 0;

    size_t input_len = strlen(input);
    size_t max_output = ((input_len + 3) / 4) * 3;

    unsigned char* buffer = OPENSSL_malloc(max_output);
    if (!buffer) return 0;

    EVP_ENCODE_CTX* ctx = EVP_ENCODE_CTX_new();
    if (!ctx) {
        OPENSSL_free(buffer);
        return 0;
    }

    EVP_DecodeInit(ctx);

    int decoded_chunk = 0, decoded_final = 0, success = 1, total_decoded = 0;

    // Decodifica dados (EVP_DecodeUpdate ignora whitespace automaticamente)
    if (EVP_DecodeUpdate(ctx, buffer, &decoded_chunk, (const unsigned char*)input, (int)input_len) < 0) {
        success = 0;
        goto CLEANUP;
    }
    total_decoded += decoded_chunk;

    // Finaliza decodificação
    if (EVP_DecodeFinal(ctx, buffer + total_decoded, &decoded_final) < 0) {
        success = 0;
        goto CLEANUP;
    }
    total_decoded += decoded_final;

    *out = buffer;
    *out_len = (size_t)total_decoded;
    buffer = NULL;

CLEANUP:
    EVP_ENCODE_CTX_free(ctx);
    if (buffer) OPENSSL_free(buffer);
    return success;
}