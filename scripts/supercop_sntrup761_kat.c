/* KAT harness for the SUPERCOP sntrup761 reference implementation.
 *
 * The reference source is the one vendored with simplexmq:
 *   simplexmq/cbits/sntrup761.c   (from supercop-20201130, public domain:
 *   D. J. Bernstein, Ch. Chuengsatiansup, T. Lange, C. van Vredendaal)
 *
 * The harness adds nothing to the algorithm: it only replaces the entropy
 * source with a deterministic one, so the vectors are reproducible, and prints
 * them as hex so a Rust test can diff against them byte-for-byte.
 *
 *   ./sntrup761_kat gen <seed> <count>   -> C-side vectors (keypair/enc/dec)
 *   ./sntrup761_kat dec <file>            -> decapsulate "SK CT" hex lines
 *
 * SK layout (both the reference and the Rust port use it):
 *   f(191) | ginv(191) | pk(1158) | rho(191) | cache(32)  = 1763 bytes
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sntrup761.h"  /* simplexmq/cbits/sntrup761.h */

#define SK_BYTES SNTRUP761_SECRETKEY_SIZE
#define PK_BYTES SNTRUP761_PUBLICKEY_SIZE
#define CT_BYTES SNTRUP761_CIPHERTEXT_SIZE
#define SS_BYTES SNTRUP761_SIZE

/* SplitMix64: deterministic, portable, and independent of libc rand(). */
static uint64_t rng_state;

static void rng_reset(uint64_t seed) { rng_state = seed; }

static void rng_bytes(void *ctx, size_t len, uint8_t *dst) {
  (void)ctx;
  while (len--) {
    uint64_t z = (rng_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z ^= z >> 31;
    *dst++ = (uint8_t)(z & 0xff);
  }
}

static void print_hex(const char *tag, const unsigned char *b, size_t len) {
  printf("%s ", tag);
  for (size_t i = 0; i < len; i++) printf("%02x", b[i]);
  printf("\n");
}

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int hex_decode(const char *s, unsigned char *out, size_t len) {
  for (size_t i = 0; i < len; i++) {
    int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return 0;
}

static int cmd_gen(uint64_t seed, int count) {
  unsigned char pk[PK_BYTES], sk[SK_BYTES], ct[CT_BYTES], ss[SS_BYTES], ss2[SS_BYTES];
  for (int i = 0; i < count; i++) {
    rng_reset(seed + (uint64_t)i * 0x100000001b3ULL);
    sntrup761_keypair(pk, sk, NULL, rng_bytes);
    sntrup761_enc(ct, ss, pk, NULL, rng_bytes);
    sntrup761_dec(ss2, ct, sk);
    if (memcmp(ss, ss2, SS_BYTES) != 0) {
      fprintf(stderr, "reference decapsulation mismatch at vector %d\n", i);
      return 1;
    }
    printf("V %d\n", i);
    print_hex("PK", pk, PK_BYTES);
    print_hex("SK", sk, SK_BYTES);
    print_hex("CT", ct, CT_BYTES);
    print_hex("SS", ss, SS_BYTES);
  }
  return 0;
}

/* "SK CT" per line (hex) -> print the decapsulated shared secret (hex). */
static int cmd_dec(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) { perror(path); return 1; }
  static char line[8192];
  while (fgets(line, sizeof line, f)) {
    char *nl = strpbrk(line, "\r\n");
    if (nl) *nl = '\0';
    char *fields[8];
    int nf = 0;
    for (char *tok = strtok(line, " \t"); tok && nf < 8; tok = strtok(NULL, " \t"))
      fields[nf++] = tok;
    if (nf < 2) continue;
    /* pick the fields by length: the secret key and the ciphertext */
    const char *sk_hex = NULL, *ct_hex = NULL;
    for (int i = 0; i < nf; i++) {
      size_t l = strlen(fields[i]);
      if (l == 2 * SK_BYTES) sk_hex = fields[i];
      else if (l == 2 * CT_BYTES) ct_hex = fields[i];
    }
    if (!sk_hex || !ct_hex) {
      fprintf(stderr, "no sk/ct fields in line\n");
      fclose(f);
      return 1;
    }
    static unsigned char sk[SK_BYTES], ct[CT_BYTES], ss[SS_BYTES];
    if (hex_decode(sk_hex, sk, SK_BYTES) != 0 || hex_decode(ct_hex, ct, CT_BYTES) != 0) {
      fprintf(stderr, "bad hex line\n");
      fclose(f);
      return 1;
    }
    sntrup761_dec(ss, ct, sk);
    print_hex("SS", ss, SS_BYTES);
  }
  fclose(f);
  return 0;
}

int main(int argc, char **argv) {
  if (argc >= 4 && strcmp(argv[1], "gen") == 0) {
    return cmd_gen(strtoull(argv[2], NULL, 0), atoi(argv[3]));
  }
  if (argc >= 3 && strcmp(argv[1], "dec") == 0) {
    return cmd_dec(argv[2]);
  }
  fprintf(stderr, "usage: %s gen <seed> <count> | %s dec <file>\n", argv[0], argv[0]);
  return 2;
}
