#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <conio.h>   
typedef unsigned char  uint8_t;   
typedef unsigned int   uint16_t;
typedef unsigned long  uint32_t;  
#define MAX_PATH_LEN      256
#define MAX_PASSWORD_LEN  64
#define MAX_ANSWER_LEN    64
#define LOG_FILE          "encrypt.log"
#define METHOD_CAESAR     1
#define METHOD_XOR        2
#define METHOD_AES        3
#define AES_BLOCK_SIZE    16
#define AES_KEY_SIZE      16
#define AES_NR            10
#define AES_KEYEXP_SIZE   176
#define ENC_MAGIC         "FENC"
#define ENC_MAGIC_LEN     4
#define NUM_QUESTIONS     5
typedef struct {
    unsigned char *data;
    long           size;
} FileBuffer;
typedef struct {
    int          method;          
    unsigned int pwd_hash;        
    long         original_size;   
    int          sec_q_index;     
    unsigned int sec_a_hash;      
    
    unsigned char pwd_stored[64];
} FileHeader;
static const char *questions[NUM_QUESTIONS] = {
    "What is the name of your first pet?",
    "What is your mother's maiden name?",
    "What was the name of your first school?",
    "What is your favourite childhood movie?",
    "What city were you born in?"
};
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const uint8_t inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};
static const uint8_t rcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};
void clear_screen(void) {
    clrscr();
}
void print_banner(void) {
    printf("<---------------------------------------------------------->\n");
    printf("          FILE ENCRYPTION & DECRYPTION TOOL \n");
    printf("         Caesar | XOR | AES-128  Encryption\n");
    printf("<---------------------------------------------------------->\n\n");
}
void print_line(void) {
    printf("------------------------------------------------------\n");
}
void get_password(char *buf, int max_len, const char *prompt) {
    int i;
    int ch;
    printf("%s", prompt);
    i = 0;
    while (i < max_len - 1) {
        ch = getch();           
        if (ch == 13) break;    
        if (ch == 8 && i > 0) {           
            printf("\b \b");
            i--;
            continue;
        }
        if (ch >= 32 && ch <= 126) {
            buf[i++] = (char)ch;
            printf("*");        
        }
    }
    buf[i] = '\0';
    printf("\n");
}
int get_int(const char *prompt, int min, int max) {
    char buf[32];
    int  val;
    int  ok;
    int  i;
    int  len;
    while (1) {
        printf("%s", prompt);
        fgets(buf, sizeof(buf), stdin);
        len = (int)strlen(buf);
        if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
        ok = 1;
        for (i = 0; buf[i]; i++) {
            if (!isdigit((unsigned char)buf[i])) { ok = 0; break; }
        }
        if (ok && strlen(buf) > 0) {
            val = atoi(buf);
            if (val >= min && val <= max) return val;
        }
        printf("[!] Please enter a number between %d and %d.\n", min, max);
    }
}
void get_text(const char *prompt, char *buf, int max_len) {
    int len;
    while (1) {
        printf("%s", prompt);
        fgets(buf, max_len, stdin);
        len = (int)strlen(buf);
        if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
        if (strlen(buf) > 0) return;
        printf("[!] Cannot be empty. Try again.\n");
    }
}
void wait_enter(void) {
    int c;
    printf("\nPress Enter to continue...");
    fflush(stdout);
    while ((c = getchar()) != '\n' && c != EOF);
}
unsigned int djb2_hash(const char *str) {
    unsigned int hash = 5381;
    int c;
    while ((c = (unsigned char)*str++)) {
        hash = ((hash << 5) + hash) ^ (unsigned int)c;
    }
    return hash;
}
unsigned int hash_answer(const char *answer) {
    char lower[MAX_ANSWER_LEN];
    int i;
    strncpy(lower, answer, MAX_ANSWER_LEN - 1);
    lower[MAX_ANSWER_LEN - 1] = '\0';
    for (i = 0; lower[i]; i++) {
        lower[i] = (char)tolower((unsigned char)lower[i]);
    }
    return djb2_hash(lower);
}
void scramble_password(const char *pwd, const char *answer, unsigned char *out) {
    int ans_len;
    int i;
    memset(out, 0, 64);
    ans_len = (int)strlen(answer);
    if (ans_len == 0) {
        strncpy((char *)out, pwd, 63);
        return;
    }
    for (i = 0; pwd[i] != '\0' && i < 63; i++) {
        out[i] = (unsigned char)pwd[i] ^ (unsigned char)answer[i % ans_len];
    }
}
void unscramble_password(const unsigned char *stored,
                         const char *answer, char *out) {
    int           ans_len;
    int           i;
    unsigned char c;
    memset(out, 0, 64);
    ans_len = (int)strlen(answer);
    if (ans_len == 0) {
        strncpy(out, (const char *)stored, 63);
        return;
    }
    for (i = 0; i < 63; i++) {
        c = stored[i] ^ (unsigned char)answer[i % ans_len];
        if (c == '\0') break;
        out[i] = (char)c;
    }
}
int load_file(const char *path, FileBuffer *fb) {
    FILE *f;
    size_t n;
    fb->data = NULL;
    fb->size = 0;
    f = fopen(path, "rb");
    if (!f) {
        printf("[ERROR] Cannot open: %s\n", path);
        return 0;
    }
    fseek(f, 0, SEEK_END);
    fb->size = ftell(f);
    rewind(f);
    if (fb->size <= 0) {
        printf("[ERROR] File is empty.\n");
        fclose(f);
        return 0;
    }
    fb->data = (unsigned char *)malloc((size_t)fb->size);
    if (!fb->data) {
        printf("[ERROR] Not enough memory.\n");
        fclose(f);
        return 0;
    }
    n = fread(fb->data, 1, (size_t)fb->size, f);
    fclose(f);
    if ((long)n != fb->size) {
        printf("[ERROR] Could not read entire file.\n");
        free(fb->data);
        fb->data = NULL;
        return 0;
    }
    return 1;
}
int save_file(const char *path, unsigned char *data, long size) {
    FILE *f;
    size_t n;
    f = fopen(path, "wb");
    if (!f) {
        printf("[ERROR] Cannot write: %s\n", path); perror("       OS reason"); return 0;
    }
    n = fwrite(data, 1, (size_t)size, f);
    fclose(f);
    if ((long)n != size) {
        printf("[ERROR] Write incomplete.\n");
        return 0;
    }
    return 1;
}
int file_exists(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    fclose(f);
    return 1;
}
long get_file_size(const char *path) {
    FILE *f;
    long  sz;
    f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fclose(f);
    return sz;
}
int write_enc_file(const char *path, unsigned char *data, long size,
                   FileHeader *hdr) {
    FILE *f;
    f = fopen(path, "wb");
    if (!f) {
        printf("[ERROR] Cannot create: %s\n", path);
        perror("       OS reason");
        printf("       Check the current directory is writable.\n");
        return 0;
    }
    fwrite(ENC_MAGIC,             1,                    ENC_MAGIC_LEN, f);
    fwrite(&hdr->method,          sizeof(int),          1,             f);
    fwrite(&hdr->pwd_hash,        sizeof(unsigned int), 1,             f);
    fwrite(&hdr->original_size,   sizeof(long),         1,             f);
    fwrite(&hdr->sec_q_index,     sizeof(int),          1,             f);
    fwrite(&hdr->sec_a_hash,      sizeof(unsigned int), 1,             f);
    fwrite(hdr->pwd_stored,       1,                    64,            f);
    fwrite(data,                  1,             (size_t)size,         f);
    fclose(f);
    return 1;
}
int read_enc_file(const char *path, FileBuffer *fb, FileHeader *hdr) {
    FILE *f;
    char  magic[ENC_MAGIC_LEN + 1];
    long  cur;
    long  total;
    fb->data = NULL;
    fb->size = 0;
    f = fopen(path, "rb");
    if (!f) {
        printf("[ERROR] Cannot open file.\n");
        return 0;
    }
    memset(magic, 0, sizeof(magic));
    fread(magic, 1, ENC_MAGIC_LEN, f);
    if (memcmp(magic, ENC_MAGIC, ENC_MAGIC_LEN) != 0) {
        printf("[ERROR] Not a valid .enc file.\n");
        fclose(f);
        return 0;
    }
    fread(&hdr->method,        sizeof(int),          1,  f);
    fread(&hdr->pwd_hash,      sizeof(unsigned int), 1,  f);
    fread(&hdr->original_size, sizeof(long),         1,  f);
    fread(&hdr->sec_q_index,   sizeof(int),          1,  f);
    fread(&hdr->sec_a_hash,    sizeof(unsigned int), 1,  f);
    fread(hdr->pwd_stored,     1,                    64, f);
    cur   = ftell(f);
    fseek(f, 0, SEEK_END);
    total = ftell(f);
    fseek(f, cur, SEEK_SET);
    fb->size = total - cur;
    if (fb->size <= 0) {
        printf("[ERROR] File has no data.\n");
        fclose(f);
        return 0;
    }
    fb->data = (unsigned char *)malloc((size_t)fb->size);
    if (!fb->data) {
        printf("[ERROR] Not enough memory.\n");
        fclose(f);
        return 0;
    }
    fread(fb->data, 1, (size_t)fb->size, f);
    fclose(f);
    return 1;
}
void log_event(const char *action, const char *file, int method) {
    FILE  *log;
    time_t now;
    struct tm *t;
    char   ts[32];
    const char *mname;
    log = fopen(LOG_FILE, "a");
    if (!log) return;
    now = time(NULL);
    t   = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);
    if      (method == METHOD_CAESAR) mname = "Caesar";
    else if (method == METHOD_XOR)    mname = "XOR";
    else if (method == METHOD_AES)    mname = "AES-128";
    else                              mname = "Unknown";
    fprintf(log, "[%s] %s  File: %s  Method: %s\n",
            ts, action, file, mname);
    fclose(log);
}
void caesar_process(unsigned char *buf, long size, int shift) {
    long i;
    unsigned char c;
    shift = ((shift % 26) + 26) % 26;
    for (i = 0; i < size; i++) {
        c = buf[i];
        if (c >= 'A' && c <= 'Z') {
            buf[i] = (unsigned char)(((c - 'A' + shift) % 26) + 'A');
        } else if (c >= 'a' && c <= 'z') {
            buf[i] = (unsigned char)(((c - 'a' + shift) % 26) + 'a');
        }       
    }
}
void caesar_encrypt(unsigned char *buf, long size, int shift) {
    caesar_process(buf, size, shift);
}
void caesar_decrypt(unsigned char *buf, long size, int shift) {
    caesar_process(buf, size, (26 - shift) % 26);
}
void xor_process(unsigned char *buf, long size, const char *password) {
    int  key_len;
    long i;
    key_len = (int)strlen(password);
    if (key_len == 0) return;
    for (i = 0; i < size; i++) {
        buf[i] ^= (unsigned char)password[i % key_len];
    }
}
static uint8_t xtime(uint8_t a) {
    return (uint8_t)((a << 1) ^ (a & 0x80 ? 0x1b : 0x00));
}
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    while (b) {
        if (b & 1) p ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return p;
}
static void aes_expand_key(const uint8_t *key, uint8_t *exp) {
    uint8_t temp[4];
    uint8_t t;
    int     w;
    int     i;
    memcpy(exp, key, 16);
    w = 4;
    while (w < 44) {
        memcpy(temp, exp + (w - 1) * 4, 4);
        if (w % 4 == 0) {
            t       = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            for (i = 0; i < 4; i++) temp[i] = sbox[temp[i]];   
            temp[0] ^= rcon[w / 4];
        }
        for (i = 0; i < 4; i++) {
            exp[w * 4 + i] = exp[(w - 4) * 4 + i] ^ temp[i];
        }
        w++;
    }
}
static void sub_bytes(uint8_t *s) {
    int i;
    for (i = 0; i < 16; i++) s[i] = sbox[s[i]];
}
static void inv_sub_bytes(uint8_t *s) {
    int i;
    for (i = 0; i < 16; i++) s[i] = inv_sbox[s[i]];
}
static void shift_rows(uint8_t *s) {
    uint8_t t;
    t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
    t=s[2]; s[2]=s[10]; s[10]=t;
    t=s[6]; s[6]=s[14]; s[14]=t;   
    t=s[3]; s[3]=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=t;
}
static void inv_shift_rows(uint8_t *s) {
    uint8_t t;
    t=s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t;
    t=s[2]; s[2]=s[10]; s[10]=t;
    t=s[6]; s[6]=s[14]; s[14]=t;   
    t=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t;
}
static void mix_columns(uint8_t *s) {
    int     col;
    uint8_t a[4];
    uint8_t *c;
    for (col = 0; col < 4; col++) {
        c = s + col * 4;
        memcpy(a, c, 4);
        c[0] = gmul(2,a[0]) ^ gmul(3,a[1]) ^ a[2]        ^ a[3];
        c[1] = a[0]         ^ gmul(2,a[1]) ^ gmul(3,a[2]) ^ a[3];
        c[2] = a[0]         ^ a[1]         ^ gmul(2,a[2]) ^ gmul(3,a[3]);
        c[3] = gmul(3,a[0]) ^ a[1]         ^ a[2]         ^ gmul(2,a[3]);
    }
}
static void inv_mix_columns(uint8_t *s) {
    int     col;
    uint8_t a[4];
    uint8_t *c;
    for (col = 0; col < 4; col++) {
        c = s + col * 4;
        memcpy(a, c, 4);
        c[0] = gmul(0x0e,a[0])^gmul(0x0b,a[1])^gmul(0x0d,a[2])^gmul(0x09,a[3]);
        c[1] = gmul(0x09,a[0])^gmul(0x0e,a[1])^gmul(0x0b,a[2])^gmul(0x0d,a[3]);
        c[2] = gmul(0x0d,a[0])^gmul(0x09,a[1])^gmul(0x0e,a[2])^gmul(0x0b,a[3]);
        c[3] = gmul(0x0b,a[0])^gmul(0x0d,a[1])^gmul(0x09,a[2])^gmul(0x0e,a[3]);
    }
}
static void add_round_key(uint8_t *s, const uint8_t *rk) {
    int i;
    for (i = 0; i < 16; i++) s[i] ^= rk[i];
}
static void aes_enc_block(uint8_t *block, const uint8_t *exp) {
    uint8_t state[16];
    int     r;
    memcpy(state, block, 16);
    add_round_key(state, exp);
    for (r = 1; r <= AES_NR - 1; r++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, exp + r * 16);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, exp + AES_NR * 16);
    memcpy(block, state, 16);
}
static void aes_dec_block(uint8_t *block, const uint8_t *exp) {
    uint8_t state[16];
    int     r;
    memcpy(state, block, 16);
    add_round_key(state, exp + AES_NR * 16);
    for (r = AES_NR - 1; r >= 1; r--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, exp + r * 16);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, exp);
    memcpy(block, state, 16);
}
static void aes_make_key(const char *password, uint8_t *key) {
    int i;
    int len;
    memset(key, 0, AES_KEY_SIZE);
    len = (int)strlen(password);
    for (i = 0; i < len; i++) {
        key[i % AES_KEY_SIZE] ^= (uint8_t)password[i];
    }
    for (i = 1; i < AES_KEY_SIZE; i++) {
        key[i] ^= key[i - 1];
    }
}
unsigned char *aes_encrypt_buf(unsigned char *in, long in_size,
                                const char *password, long *out_size) {
    uint8_t        key[AES_KEY_SIZE];
    uint8_t        exp[AES_KEYEXP_SIZE];
    int            pad;
    long           total;
    unsigned char *out;
    long           i;
    long           offset;
    aes_make_key(password, key);
    aes_expand_key(key, exp);
    pad   = AES_BLOCK_SIZE - (int)(in_size % AES_BLOCK_SIZE);
    total = in_size + pad;
    out = (unsigned char *)malloc((size_t)total);
    if (!out) return NULL;
    memcpy(out, in, (size_t)in_size);
    for (i = in_size; i < total; i++) {
        out[i] = (unsigned char)pad;   
    }
    for (offset = 0; offset < total; offset += AES_BLOCK_SIZE) {
        aes_enc_block(out + offset, exp);
    }
    *out_size = total;
    return out;
}
unsigned char *aes_decrypt_buf(unsigned char *in, long in_size,
                                const char *password, long *out_size) {
    uint8_t        key[AES_KEY_SIZE];
    uint8_t        exp[AES_KEYEXP_SIZE];
    unsigned char *out;
    long           offset;
    int            pad;
    if (in_size == 0 || in_size % AES_BLOCK_SIZE != 0) return NULL;
    aes_make_key(password, key);
    aes_expand_key(key, exp);
    out = (unsigned char *)malloc((size_t)in_size);
    if (!out) return NULL;
    memcpy(out, in, (size_t)in_size);
    for (offset = 0; offset < in_size; offset += AES_BLOCK_SIZE) {
        aes_dec_block(out + offset, exp);
    }
    pad = (int)out[in_size - 1];
    if (pad < 1 || pad > AES_BLOCK_SIZE) {
        free(out);
        return NULL;   
    }
    *out_size = in_size - pad;
    return out;
}
int is_strong_password(const char *pwd) {
    int has_upper;
    int has_digit;
    int i;
    if (!pwd || (int)strlen(pwd) < 6) return 0;
    has_upper = 0;
    has_digit = 0;
    for (i = 0; pwd[i]; i++) {
        if (isupper((unsigned char)pwd[i])) has_upper = 1;
        if (isdigit((unsigned char)pwd[i])) has_digit = 1;
    }
    return (has_upper && has_digit);
}
void setup_security_question(int *q_index, unsigned int *a_hash,
                             const char *password, unsigned char *pwd_stored) {
    char answer[MAX_ANSWER_LEN];
    char lower_ans[MAX_ANSWER_LEN];
    int  i;
    printf("\n  --- SET UP PASSWORD RECOVERY ---\n");
    print_line();
    printf("  Choose a security question.\n");
    printf("  If you forget your password, answer this to recover.\n\n");
    for (i = 0; i < NUM_QUESTIONS; i++) {
        printf("    %d. %s\n", i + 1, questions[i]);
    }
    print_line();
    *q_index = get_int("  Your choice (1-5): ", 1, NUM_QUESTIONS);
    printf("\n  Question: %s\n", questions[*q_index - 1]);
    get_text("  Your answer: ", answer, MAX_ANSWER_LEN);
    *a_hash = hash_answer(answer);
    strncpy(lower_ans, answer, MAX_ANSWER_LEN - 1);
    lower_ans[MAX_ANSWER_LEN - 1] = '\0';
    for (i = 0; lower_ans[i]; i++) {
        lower_ans[i] = (char)tolower((unsigned char)lower_ans[i]);
    }
    scramble_password(password, lower_ans, pwd_stored);
    printf("[OK] Security question saved.\n");
    memset(answer,    0, sizeof(answer));
    memset(lower_ans, 0, sizeof(lower_ans));
}
int verify_security_answer(int q_index, unsigned int stored_hash,
                           const unsigned char *pwd_stored,
                           char *recovered_pwd) {
    char         answer[MAX_ANSWER_LEN];
    char         lower_ans[MAX_ANSWER_LEN];
    unsigned int typed_hash;
    int          i;
    printf("\n  --- PASSWORD RECOVERY ---\n");
    print_line();
    printf("  Security Question:\n");
    printf("  %s\n\n", questions[q_index - 1]);
    get_text("  Your answer: ", answer, MAX_ANSWER_LEN);
    typed_hash = hash_answer(answer);   
    if (typed_hash != stored_hash) {
        printf("[ERROR] Wrong answer.\n");
        memset(answer, 0, sizeof(answer));
        return 0;
    }
    strncpy(lower_ans, answer, MAX_ANSWER_LEN - 1);
    lower_ans[MAX_ANSWER_LEN - 1] = '\0';
    for (i = 0; lower_ans[i]; i++) {
        lower_ans[i] = (char)tolower((unsigned char)lower_ans[i]);
    }
    unscramble_password(pwd_stored, lower_ans, recovered_pwd);
    printf("[OK] Answer correct! Password recovered automatically.\n");
    memset(answer,    0, sizeof(answer));
    memset(lower_ans, 0, sizeof(lower_ans));
    return 1;
}
int write_enc_inplace(const char *path, unsigned char *data, long size,
                      FileHeader *hdr) {
    FILE *f;
    f = fopen(path, "wb");
    if (!f) {
        printf("[ERROR] Cannot overwrite: %s\n", path);
        perror("       OS reason");
        return 0;
    }
    fwrite(ENC_MAGIC,             1,                    ENC_MAGIC_LEN, f);
    fwrite(&hdr->method,          sizeof(int),          1,             f);
    fwrite(&hdr->pwd_hash,        sizeof(unsigned int), 1,             f);
    fwrite(&hdr->original_size,   sizeof(long),         1,             f);
    fwrite(&hdr->sec_q_index,     sizeof(int),          1,             f);
    fwrite(&hdr->sec_a_hash,      sizeof(unsigned int), 1,             f);
    fwrite(hdr->pwd_stored,       1,                    64,            f);
    fwrite(data,                  1,             (size_t)size,         f);
    fclose(f);
    return 1;
}
int write_plain_inplace(const char *path, unsigned char *data, long size) {
    FILE   *f;
    size_t  n;
    f = fopen(path, "wb");
    if (!f) {
        printf("[ERROR] Cannot overwrite: %s\n", path);
        perror("       OS reason");
        return 0;
    }
    n = fwrite(data, 1, (size_t)size, f);
    fclose(f);
    if ((long)n != size) {
        printf("[ERROR] Write incomplete.\n");
        return 0;
    }
    return 1;
}
void do_encrypt(void) {
    char          src[MAX_PATH_LEN];
    char          password[MAX_PASSWORD_LEN];
    char          confirm[MAX_PASSWORD_LEN];
    char          choice[8];
    int           method;
    int           shift;
    FileBuffer    fb;
    FileHeader    hdr;
    unsigned char *enc_data;
    long           enc_size;
    clock_t        t1;
    clock_t        t2;
    double         elapsed;
    clear_screen();
    print_banner();
    printf("  --- ENCRYPT A FILE (IN-PLACE) ---\n");
    print_line();
    printf("  WARNING: The original file will be overwritten!\n");
    print_line();
    get_text("  File path to encrypt: ", src, MAX_PATH_LEN);
    if (!file_exists(src)) {
        printf("[ERROR] File not found: %s\n", src);
        wait_enter();
        return;
    }
    printf("\n  Encryption Methods:\n");
    printf("    1. Caesar Cipher  (Educational - very weak)\n");
    printf("    2. XOR Cipher     (Moderate security)\n");
    printf("    3. AES-128        (Strong - recommended)\n\n");
    method = get_int("  Choose method (1-3): ", 1, 3);
    shift = 0;
    if (method == METHOD_CAESAR) {
        shift = get_int("  Shift value (1-25): ", 1, 25);
    }
    printf("\n");
    get_password(password, MAX_PASSWORD_LEN, "  Enter password: ");
    if (!is_strong_password(password)) {
        printf("[WARNING] Weak password! Use 6+ chars with uppercase & digit.\n");
        get_text("  Continue anyway? (y/n): ", choice, sizeof(choice));
        if (choice[0] != 'y' && choice[0] != 'Y') {
            memset(password, 0, sizeof(password));
            wait_enter();
            return;
        }
    }
    get_password(confirm, MAX_PASSWORD_LEN, "  Confirm password: ");
    if (strcmp(password, confirm) != 0) {
        printf("[ERROR] Passwords do not match!\n");
        memset(password, 0, sizeof(password));
        memset(confirm,  0, sizeof(confirm));
        wait_enter();
        return;
    }
    memset(confirm, 0, sizeof(confirm));
    setup_security_question(&hdr.sec_q_index, &hdr.sec_a_hash,
                           password, hdr.pwd_stored);
    printf("\n[INFO] Reading file...\n");
    if (!load_file(src, &fb)) {
        memset(password, 0, sizeof(password));
        wait_enter();
        return;
    }
    printf("[INFO] Encrypting...\n");
    t1 = clock();
    hdr.method        = method;
    hdr.original_size = fb.size;
    hdr.pwd_hash      = djb2_hash(password);
    enc_data = NULL;
    enc_size = 0;
    if (method == METHOD_CAESAR) {
        caesar_encrypt(fb.data, fb.size, shift);
        enc_data = fb.data;
        enc_size = fb.size;
        fb.data  = NULL;   
    } else if (method == METHOD_XOR) {
        xor_process(fb.data, fb.size, password);
        enc_data = fb.data;
        enc_size = fb.size;
        fb.data  = NULL;
    } else {
        enc_data = aes_encrypt_buf(fb.data, fb.size, password, &enc_size);
        if (!enc_data) {
            printf("[ERROR] AES encryption failed.\n");
            free(fb.data);
            memset(password, 0, sizeof(password));
            wait_enter();
            return;
        }
        free(fb.data);
        fb.data = NULL;
    }
    t2      = clock();
    elapsed = (double)(t2 - t1) / CLOCKS_PER_SEC;
    printf("Overwriting original file: %s\n", src);
    if (!write_enc_inplace(src, enc_data, enc_size, &hdr)) {
        free(enc_data);
        memset(password, 0, sizeof(password));
        wait_enter();
        return;
    }
    free(enc_data);
    log_event("ENCRYPT", src, method);
    print_line();
    printf("[OK] Encryption successful! File modified in-place.\n");
    printf("  File   : %s\n", src);
    printf("  Method : %s\n",
           method == METHOD_CAESAR ? "Caesar" :
           method == METHOD_XOR    ? "XOR"    : "AES-128");
    printf("  Time   : %.4f seconds\n", elapsed);
    print_line();
    memset(password, 0, sizeof(password));
    wait_enter();
}
void do_decrypt(void) {
    char          src[MAX_PATH_LEN];
    char          password[MAX_PASSWORD_LEN];
    int           shift;
    FileBuffer    fb;
    FileHeader    hdr;
    unsigned char *dec_data;
    long           dec_size;
    clock_t        t1;
    clock_t        t2;
    double         elapsed;
    char           rec_choice[8];
    clear_screen();
    print_banner();
    printf("  --- DECRYPT A FILE (IN-PLACE) ---\n");
    print_line();
    printf("  WARNING: The encrypted file will be overwritten!\n");
    print_line();
    get_text("  File path to decrypt: ", src, MAX_PATH_LEN);
    if (!file_exists(src)) {
        printf("[ERROR] File not found: %s\n", src);
        wait_enter();
        return;
    }
    printf("[INFO] Reading file...\n");
    if (!read_enc_file(src, &fb, &hdr)) {
        wait_enter();
        return;
    }
    shift = 0;
    if (hdr.method == METHOD_CAESAR) {
        shift = get_int("  Caesar shift value used: ", 1, 25);
    }
    printf("\n");
    get_password(password, MAX_PASSWORD_LEN, "  Enter password: ");
    if (djb2_hash(password) != hdr.pwd_hash) {
        printf("[ERROR] Incorrect password!\n\n");
        printf("  Forgot your password?\n");
        printf("  You set this question when encrypting:\n");
        printf("  \"%s\"\n\n", questions[hdr.sec_q_index - 1]);
        get_text("  Try password recovery? (y/n): ", rec_choice, sizeof(rec_choice));
        if (rec_choice[0] == 'y' || rec_choice[0] == 'Y') {
            if (!verify_security_answer(hdr.sec_q_index, hdr.sec_a_hash,
                                        hdr.pwd_stored, password)) {
                printf("[ERROR] Recovery failed. Cannot decrypt.\n");
                free(fb.data);
                memset(password, 0, sizeof(password));
                wait_enter();
                return;
            }
            printf("[OK] Decrypting with recovered password...\n\n");
        } else {
            free(fb.data);
            memset(password, 0, sizeof(password));
            wait_enter();
            return;
        }
    }
    printf("[INFO] Decrypting...\n");
    t1 = clock();
    dec_data = NULL;
    dec_size = 0;
    if (hdr.method == METHOD_CAESAR) {
        caesar_decrypt(fb.data, fb.size, shift);
        dec_data = fb.data;
        dec_size = fb.size;
        fb.data  = NULL;
    } else if (hdr.method == METHOD_XOR) {
        xor_process(fb.data, fb.size, password);
        dec_data = fb.data;
        dec_size = fb.size;
        fb.data  = NULL;
    } else {
        dec_data = aes_decrypt_buf(fb.data, fb.size, password, &dec_size);
        if (!dec_data) {
            printf("[ERROR] AES decryption failed. Data may be corrupted.\n");
            free(fb.data);
            memset(password, 0, sizeof(password));
            wait_enter();
            return;
        }
        free(fb.data);
        fb.data = NULL;
    }
    t2      = clock();
    elapsed = (double)(t2 - t1) / CLOCKS_PER_SEC;
    printf("[INFO] Restoring original file: %s\n", src);
    if (!write_plain_inplace(src, dec_data, dec_size)) {
        free(dec_data);
        memset(password, 0, sizeof(password));
        wait_enter();
        return;
    }
    free(dec_data); 
    log_event("DECRYPT", src, hdr.method);
    print_line();
    printf("[OK] Decryption successful! File restored in-place.\n");
    printf("  File   : %s\n", src);
    printf("  Method : %s\n",
           hdr.method == METHOD_CAESAR ? "Caesar" :
           hdr.method == METHOD_XOR    ? "XOR"    : "AES-128");
    printf("  Time   : %.4f seconds\n", elapsed);
    print_line();

    memset(password, 0, sizeof(password));
    wait_enter();
}

int main(void) {
    int choice;

    clear_screen();
    print_banner();
    printf("  Welcome! This tool encrypts and decrypts files.\n");
    wait_enter();

    while (1) {
        clear_screen();
        print_banner();
        printf("  Main Menu\n");
        print_line();
        printf("    1. Encrypt a file (in-place)\n");
        printf("    2. Decrypt a file (in-place)\n");
        printf("    3. Exit\n");
        print_line();
        choice = get_int("  Your choice (1-3): ", 1, 3);
        if (choice == 1) {
            do_encrypt();
        } else if (choice == 2) {
            do_decrypt();
        } else {
            clear_screen();
            print_banner();
            printf("[OK] Goodbye!\n\n");
            break;
        }
    }
    return 0;
}