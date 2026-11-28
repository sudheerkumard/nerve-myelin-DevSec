// Fixture for engine/myelin_engine/rules/sast/c.yaml (opengrep --test). Not compiled.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <curl/curl.h>

void copy(char *in, SSL_CTX *ctx, CURL *c) {
    char buf[64];
    // ruleid: nervve.c.unbounded-copy
    strcpy(buf, in);
    // ruleid: nervve.c.unbounded-copy
    sprintf(buf, "%s", in);
    // ok: nervve.c.unbounded-copy
    snprintf(buf, sizeof buf, "%s", in);
    // ruleid: nervve.c.gets
    gets(buf);
    // ruleid: nervve.c.unbounded-scanf
    scanf("%s", buf);
    // ok: nervve.c.unbounded-scanf
    scanf("%63s", buf);
    // ruleid: nervve.c.format-string
    printf(in);
    // ok: nervve.c.format-string
    printf("%s", in);
    // ruleid: nervve.c.command-injection
    system(in);
    // ok: nervve.c.command-injection
    system("reboot");
    // ruleid: nervve.c.weak-crypto
    MD5_Init(&md);
    // ruleid: nervve.c.tls-verification-disabled
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    // ok: nervve.c.tls-verification-disabled
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // ruleid: nervve.c.tls-verification-disabled
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    // ruleid: nervve.c.insecure-temp-file
    char *t = tmpnam(NULL);
    // ruleid: nervve.c.weak-random
    srand(time(NULL));
    // ruleid: nervve.c.world-writable
    chmod("/etc/app.conf", 0777);
}

struct img { int width; int height; char data[10]; };

void heap_bugs(struct img im, char *src) {
    char *a = malloc(16);
    // ruleid: nervve.c.double-free
    free(a);
    free(a);
}

void heap_ok(void) {
    char *b = malloc(16);
    // ok: nervve.c.double-free
    free(b);
    b = malloc(32);
    free(b);
}

void uaf(char *src) {
    char *c = malloc(16);
    // ruleid: nervve.c.use-after-free
    free(c);
    c[0] = 'a';
}

void uaf_ok(void) {
    char *d = malloc(16);
    // ok: nervve.c.use-after-free
    free(d);
    d = NULL;
    d = malloc(8);
    d[0] = 'a';
}

void sizes(struct img im, size_t n) {
    // ruleid: nervve.c.allocation-size-overflow
    int s = im.width + im.height;
    char *e = malloc(s);
    // ok: nervve.c.allocation-size-overflow
    char *f = malloc(n + 1);
    free(e); free(f);
}
