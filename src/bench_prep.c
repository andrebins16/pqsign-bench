// bench_prep.c — prepara chaves e assinaturas em Base64 para uso com bench_worker
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "crypto_core.h"

#define PLOG(fmt, ...) fprintf(stderr, "[prep] " fmt "\n", ##__VA_ARGS__)


// CLI
static void usage(const char* prog_name) {
    fprintf(stderr,
      "Uso:\n"
      "  %s genkey --alg ALG\n"
      "     -> stdout: KEY_B64 (linha 1)\n"
      "\n"
      "  %s gensig [--key-b64 B64 | --alg ALG] [--msg-b64 B64 | --msg-len N]\n"
      "     -> se usar --alg (gera nova chave):\n"
      "        stdout: KEY_B64 (linha 1), SIG_B64 (linha 2)\n"
      "     -> se usar --key-b64 (usa chave existente):\n"
      "        stdout: SIG_B64 (linha 1)\n",
      prog_name, prog_name);
}

// Faz parse de string para uint64_t.
// Retorna 1 em sucesso, 0 em falha.
static int parse_u64(const char* str, uint64_t* out) {
    if (!str || !*str) return 0;

    errno = 0;
    char* endptr = NULL;
    unsigned long long value = strtoull(str, &endptr, 10);

    if (errno || endptr == str || *endptr != '\0') return 0;

    *out = (uint64_t)value;
    return 1;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    // Parse de argumentos
    const char* command = argv[1];
    const char* algorithm = NULL;
    const char* key_b64 = NULL;
    const char* msg_b64 = NULL;
    size_t msg_len = 0;

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--alg")) {
            if (++i >= argc) { usage(argv[0]); return 2; }
            algorithm = argv[i];
        }
        else if (!strcmp(argv[i], "--key-b64")) {
            if (++i >= argc) { usage(argv[0]); return 2; }
            key_b64 = argv[i];
        }
        else if (!strcmp(argv[i], "--msg-b64")) {
            if (++i >= argc) { usage(argv[0]); return 2; }
            msg_b64 = argv[i];
        }
        else if (!strcmp(argv[i], "--msg-len")) {
            if (++i >= argc) { usage(argv[0]); return 2; }
            uint64_t value;
            if (!parse_u64(argv[i], &value) || value == 0) {
                usage(argv[0]);
                return 2;
            }
            msg_len = (size_t)value;
        }
        else {
            usage(argv[0]);
            return 2;
        }
    }

    // Inicializa providers
    if (!bc_init_providers()) {
        PLOG("ERRO: falha ao inicializar providers");
        return 1;
    }

    int exit_code = 0;

    // Comando: genkey
    if (!strcmp(command, "genkey")) {
        if (!algorithm) {
            usage(argv[0]);
            exit_code = 2;
            goto CLEANUP;
        }

        // Gera par de chaves
        bc_keypair_t keypair;
        if (!bc_keygen(algorithm, &keypair)) {
            PLOG("ERRO: falha em keygen(%s)", algorithm);
            exit_code = 1;
            goto CLEANUP;
        }

        // Converte para PKCS#8 DER
        unsigned char* der = NULL;
        int der_len = 0;
        if (!bc_pkey_to_pkcs8_der(keypair.pkey, &der, &der_len)) {
            PLOG("ERRO: falha ao converter chave para PKCS#8");
            bc_keypair_free(&keypair);
            exit_code = 1;
            goto CLEANUP;
        }

        // Imprime KEY_B64
        bc_b64_print_line(der, (size_t)der_len);

        OPENSSL_free(der);
        bc_keypair_free(&keypair);
    }
    // Comando: gensig
    else if (!strcmp(command, "gensig")) {
        EVP_PKEY* pkey = NULL;
        unsigned char* message = NULL;
        size_t message_len = 0;

        // Resolve chave (existente ou nova)
        if (key_b64) {
            // Decodifica chave existente
            unsigned char* key_der = NULL;
            size_t key_der_len = 0;
            if (!bc_b64_decode(key_b64, &key_der, &key_der_len) || key_der_len == 0) {
                PLOG("ERRO: falha ao decodificar --key-b64");
                exit_code = 2;
                goto CLEANUP;
            }

            pkey = bc_pkcs8_der_to_pkey(key_der, key_der_len);
            OPENSSL_free(key_der);

            if (!pkey) {
                PLOG("ERRO: falha ao parsear chave");
                exit_code = 2;
                goto CLEANUP;
            }
        }
        else {
            // Gera nova chave
            if (!algorithm) {
                PLOG("ERRO: falta --alg ou --key-b64");
                exit_code = 2;
                goto CLEANUP;
            }

            bc_keypair_t keypair;
            if (!bc_keygen(algorithm, &keypair)) {
                PLOG("ERRO: falha em keygen(%s)", algorithm);
                exit_code = 1;
                goto CLEANUP;
            }

            // Imprime KEY_B64 na linha 1
            unsigned char* der = NULL;
            int der_len = 0;
            if (!bc_pkey_to_pkcs8_der(keypair.pkey, &der, &der_len)) {
                PLOG("ERRO: falha ao converter chave para PKCS#8");
                bc_keypair_free(&keypair);
                exit_code = 1;
                goto CLEANUP;
            }
            bc_b64_print_line(der, (size_t)der_len);

            // Duplica chave para uso posterior
            pkey = EVP_PKEY_dup(keypair.pkey);
            if (!pkey) {
                PLOG("ERRO: falha em EVP_PKEY_dup");
                OPENSSL_free(der);
                bc_keypair_free(&keypair);
                exit_code = 1;
                goto CLEANUP;
            }

            OPENSSL_free(der);
            bc_keypair_free(&keypair);
        }

        // Resolve mensagem (Base64 ou zeros)
        if (msg_b64) {
            // Decodifica mensagem Base64
            if (!bc_b64_decode(msg_b64, &message, &message_len) || message_len == 0) {
                PLOG("ERRO: falha ao decodificar --msg-b64");
                EVP_PKEY_free(pkey);
                exit_code = 2;
                goto CLEANUP;
            }
        }
        else {
            // Aloca mensagem com zeros
            if (msg_len == 0) {
                PLOG("ERRO: falta --msg-b64 ou --msg-len");
                EVP_PKEY_free(pkey);
                exit_code = 2;
                goto CLEANUP;
            }

            message_len = msg_len;
            message = (unsigned char*)OPENSSL_zalloc(message_len);
            if (!message) {
                PLOG("ERRO: falha ao alocar mensagem de %zu bytes", message_len);
                EVP_PKEY_free(pkey);
                exit_code = 1;
                goto CLEANUP;
            }
        }

        // Assina mensagem
        bc_keypair_t keypair_for_sign = { .pkey = pkey };
        bc_signature_t signature = {0};

        if (!bc_sign(&keypair_for_sign, message, message_len, &signature)) {
            PLOG("ERRO: falha ao assinar");
            OPENSSL_free(message);
            EVP_PKEY_free(pkey);
            exit_code = 1;
            goto CLEANUP;
        }

        // Imprime SIG_B64
        bc_b64_print_line(signature.data, signature.len);

        bc_signature_free(&signature);
        OPENSSL_free(message);
        EVP_PKEY_free(pkey);
    }
    else {
        usage(argv[0]);
        exit_code = 2;
    }

CLEANUP:
    bc_shutdown_providers();
    return exit_code;
}