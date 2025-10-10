// bench_worker.c — executa operações criptográficas para benchmark
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

#define WLOG(fmt, ...) fprintf(stderr, "[worker] " fmt "\n", ##__VA_ARGS__)

// Tipos de comando
typedef enum {
    CMD_NONE,
    CMD_KEYGEN,
    CMD_SIGN,
    CMD_VERIFY,
    CMD_ALL,
    CMD_LIST_ALGS
} cmd_t;

// Opções parseadas da linha de comando
typedef struct {
    cmd_t       cmd;
    const char* alg;        // keygen, all
    const char* key_b64;    // sign/verify (PKCS#8 DER em Base64)
    const char* msg_b64;    // sign/verify/all (opcional)
    size_t      msg_len;    // sign/verify/all (se msg_b64 ausente)
    const char* sig_b64;    // verify
    int         baseline;   // 1 => não executar a primitiva (mede overhead)
} opts_t;


// CLI 
static void usage(const char* prog_name) {
    fprintf(stderr,
      "Uso:\n"
      "  %s list-algs\n"
      "  %s keygen --alg ALG [--baseline]\n"
      "  %s sign   --key-b64 B64 [--msg-b64 B64 | --msg-len N] [--baseline]\n"
      "  %s verify --key-b64 B64 --sig-b64 B64 [--msg-b64 B64 | --msg-len N] [--baseline]\n"
      "  %s all    --alg ALG [--msg-b64 B64 | --msg-len N] [--baseline]\n",
      prog_name, prog_name, prog_name, prog_name, prog_name);
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

// Faz parse dos argumentos da linha de comando.
// Retorna 1 em sucesso, 0 em falha.
static int parse_cli(int argc, char** argv, opts_t* opts) {
    memset(opts, 0, sizeof(*opts));
    opts->cmd = CMD_NONE;
    opts->msg_len = 0;
    opts->baseline = 0;

    if (argc < 2) return 0;

    // Identifica comando
    if (!strcmp(argv[1], "list-algs"))      opts->cmd = CMD_LIST_ALGS;
    else if (!strcmp(argv[1], "keygen"))    opts->cmd = CMD_KEYGEN;
    else if (!strcmp(argv[1], "sign"))      opts->cmd = CMD_SIGN;
    else if (!strcmp(argv[1], "verify"))    opts->cmd = CMD_VERIFY;
    else if (!strcmp(argv[1], "all"))       opts->cmd = CMD_ALL;
    else return 0;

    // Parse de opções
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--alg")) {
            if (++i >= argc) return 0;
            opts->alg = argv[i];
        }
        else if (!strcmp(argv[i], "--key-b64")) {
            if (++i >= argc) return 0;
            opts->key_b64 = argv[i];
        }
        else if (!strcmp(argv[i], "--sig-b64")) {
            if (++i >= argc) return 0;
            opts->sig_b64 = argv[i];
        }
        else if (!strcmp(argv[i], "--msg-b64")) {
            if (++i >= argc) return 0;
            opts->msg_b64 = argv[i];
        }
        else if (!strcmp(argv[i], "--msg-len")) {
            if (++i >= argc) return 0;
            uint64_t value;
            if (!parse_u64(argv[i], &value) || value == 0) return 0;
            opts->msg_len = (size_t)value;
        }
        else if (!strcmp(argv[i], "--baseline")) {
            opts->baseline = 1;
        }
        else {
            return 0;
        }
    }

    // Valida requisitos por comando
    if (opts->cmd == CMD_KEYGEN) {
        if (!opts->alg) return 0;
    }
    else if (opts->cmd == CMD_SIGN) {
        if (!opts->key_b64) return 0;
        if (!opts->msg_b64 && opts->msg_len == 0) return 0;
    }
    else if (opts->cmd == CMD_VERIFY) {
        if (!opts->key_b64 || !opts->sig_b64) return 0;
        if (!opts->msg_b64 && opts->msg_len == 0) return 0;
    }
    else if (opts->cmd == CMD_ALL) {
        if (!opts->alg) return 0;
        if (!opts->msg_b64 && opts->msg_len == 0) return 0;
    }

    return 1;
}


int main(int argc, char** argv) {
    // Parse de argumentos
    opts_t opts;
    if (!parse_cli(argc, argv, &opts)) {
        usage(argv[0]);
        return 2;
    }

    // Inicializa providers
    if (!bc_init_providers()) {
        WLOG("ERRO: falha ao inicializar providers");
        return 1;
    }

    int exit_code = 0;

    // Comando: list-algs
    if (opts.cmd == CMD_LIST_ALGS) {
        bc_print_signature_algs(stdout);
    }
    // Comando: keygen
    else if (opts.cmd == CMD_KEYGEN) {
        bc_keypair_t keypair = {0};

        if (!opts.baseline) {
            if (!bc_keygen(opts.alg, &keypair)) {
                WLOG("ERRO: falha em keygen(%s)", opts.alg);
                exit_code = 1;
            }
        }

        bc_keypair_free(&keypair);
    }
    // Comando: sign
    else if (opts.cmd == CMD_SIGN) {
        // Decodifica chave
        unsigned char* key_der = NULL;
        size_t key_der_len = 0;
        if (!bc_b64_decode(opts.key_b64, &key_der, &key_der_len)) {
            WLOG("ERRO: falha ao decodificar --key-b64");
            bc_shutdown_providers();
            return 1;
        }

        EVP_PKEY* pkey = bc_pkcs8_der_to_pkey(key_der, key_der_len);
        OPENSSL_free(key_der);

        if (!pkey) {
            WLOG("ERRO: falha ao parsear chave");
            bc_shutdown_providers();
            return 1;
        }

        // Resolve mensagem (Base64 ou zeros)
        unsigned char* message = NULL;
        size_t message_len = 0;

        if (opts.msg_b64) {
            if (!bc_b64_decode(opts.msg_b64, &message, &message_len) || message_len == 0) {
                WLOG("ERRO: falha ao decodificar --msg-b64");
                EVP_PKEY_free(pkey);
                bc_shutdown_providers();
                return 1;
            }
        }
        else {
            message_len = opts.msg_len;
            message = (unsigned char*)OPENSSL_zalloc(message_len);
            if (!message) {
                WLOG("ERRO: falha ao alocar mensagem de %zu bytes", message_len);
                EVP_PKEY_free(pkey);
                bc_shutdown_providers();
                return 1;
            }
        }

        // Assina mensagem
        bc_keypair_t keypair = { .pkey = pkey };
        bc_signature_t signature = {0};

        if (!opts.baseline) {
            if (!bc_sign(&keypair, message, message_len, &signature)) {
                WLOG("ERRO: falha ao assinar");
                exit_code = 1;
            }
        }

        bc_signature_free(&signature);
        OPENSSL_free(message);
        EVP_PKEY_free(pkey);
    }
    // Comando: verify
    else if (opts.cmd == CMD_VERIFY) {
        // Decodifica chave
        unsigned char* key_der = NULL;
        size_t key_der_len = 0;
        if (!bc_b64_decode(opts.key_b64, &key_der, &key_der_len)) {
            WLOG("ERRO: falha ao decodificar --key-b64");
            bc_shutdown_providers();
            return 1;
        }

        EVP_PKEY* pkey = bc_pkcs8_der_to_pkey(key_der, key_der_len);
        OPENSSL_free(key_der);

        if (!pkey) {
            WLOG("ERRO: falha ao parsear chave");
            bc_shutdown_providers();
            return 1;
        }

        // Decodifica assinatura
        unsigned char* sig_decoded = NULL;
        size_t sig_len = 0;
        if (!bc_b64_decode(opts.sig_b64, &sig_decoded, &sig_len) || sig_len == 0) {
            WLOG("ERRO: falha ao decodificar --sig-b64");
            EVP_PKEY_free(pkey);
            bc_shutdown_providers();
            return 1;
        }

        // Resolve mensagem (Base64 ou zeros)
        unsigned char* message = NULL;
        size_t message_len = 0;

        if (opts.msg_b64) {
            if (!bc_b64_decode(opts.msg_b64, &message, &message_len) || message_len == 0) {
                WLOG("ERRO: falha ao decodificar --msg-b64");
                OPENSSL_free(sig_decoded);
                EVP_PKEY_free(pkey);
                bc_shutdown_providers();
                return 1;
            }
        }
        else {
            message_len = opts.msg_len;
            message = (unsigned char*)OPENSSL_zalloc(message_len);
            if (!message) {
                WLOG("ERRO: falha ao alocar mensagem de %zu bytes", message_len);
                OPENSSL_free(sig_decoded);
                EVP_PKEY_free(pkey);
                bc_shutdown_providers();
                return 1;
            }
        }

        // Verifica assinatura
        bc_keypair_t keypair = { .pkey = pkey };
        bc_signature_t signature = { .data = sig_decoded, .len = sig_len };

        if (!opts.baseline) {
            if (!bc_verify(&keypair, message, message_len, &signature)) {
                WLOG("ERRO: verificação de assinatura falhou");
                exit_code = 1;
            }
        }

        OPENSSL_free(message);
        OPENSSL_free(sig_decoded);
        EVP_PKEY_free(pkey);
    }
    // Comando: all
    else if (opts.cmd == CMD_ALL) {
        // Resolve mensagem (Base64 ou zeros)
        unsigned char* message = NULL;
        size_t message_len = 0;

        if (opts.msg_b64) {
            if (!bc_b64_decode(opts.msg_b64, &message, &message_len) || message_len == 0) {
                WLOG("ERRO: falha ao decodificar --msg-b64");
                bc_shutdown_providers();
                return 1;
            }
        }
        else {
            message_len = opts.msg_len;
            message = (unsigned char*)OPENSSL_zalloc(message_len);
            if (!message) {
                WLOG("ERRO: falha ao alocar mensagem de %zu bytes", message_len);
                bc_shutdown_providers();
                return 1;
            }
        }

        if (!opts.baseline) {
            // Gera chave
            bc_keypair_t keypair = {0};
            if (!bc_keygen(opts.alg, &keypair)) {
                WLOG("ERRO: falha em keygen(%s)", opts.alg);
                OPENSSL_free(message);
                bc_shutdown_providers();
                return 1;
            }

            // Assina mensagem
            bc_signature_t signature = {0};
            if (!bc_sign(&keypair, message, message_len, &signature)) {
                WLOG("ERRO: falha ao assinar");
                bc_keypair_free(&keypair);
                OPENSSL_free(message);
                bc_shutdown_providers();
                return 1;
            }

            // Verifica assinatura
            if (!bc_verify(&keypair, message, message_len, &signature)) {
                WLOG("ERRO: verificação de assinatura falhou");
                bc_signature_free(&signature);
                bc_keypair_free(&keypair);
                OPENSSL_free(message);
                bc_shutdown_providers();
                return 1;
            }

            bc_signature_free(&signature);
            bc_keypair_free(&keypair);
        }

        OPENSSL_free(message);
    }

    bc_shutdown_providers();
    return exit_code;
}