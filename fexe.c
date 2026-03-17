#if !defined(_WIN32)
  #define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef _WIN32
  #include <windows.h>
  #include <direct.h>
  #include <io.h>
  #include <process.h>
  #define PATH_SEP "\\"
  #define MKDIR(p) _mkdir(p)
  #define STAT _stat
  #define STAT_STRUCT struct _stat
  #define popen _popen
  #define pclose _pclose
  #define getcwd _getcwd
  #define unlink _unlink
  #define strdup _strdup
#else
  #include <unistd.h>
  #include <sys/wait.h>
  #include <sys/types.h>
  #include <dirent.h>
  #define PATH_SEP "/"
  #define MKDIR(p) mkdir(p, 0755)
  #define STAT stat
  #define STAT_STRUCT struct stat
#endif

#ifdef __APPLE__
  #define OS_NAME "macos"
#elif defined(_WIN32)
  #define OS_NAME "windows"
#elif defined(__ANDROID__)
  #define OS_NAME "android"
#else
  #define OS_NAME "linux"
#endif

#define FEXE_VERSION "1.0.0"
#define MAX_LINE 65536
#define MAX_KEY 512
#define MAX_VAL 65536
#define MAX_FILES 256
#define MAX_VERSIONS 64
#define MAX_VARIANTS 64
#define MAX_FEATURES 128
#define MAX_COMMANDS 16
#define MAX_PERMS 32

typedef struct {
    char key[MAX_KEY];
    char value[MAX_VAL];
} KVPair;

typedef struct {
    char name[512];
    char content[1 << 20];
    int content_len;
} FexeFile;

typedef struct {
    char os[64];
    char cmd[1024];
} OsCommand;

typedef struct {
    char id[128];
    char label[256];
    int enabled;
} Feature;

typedef struct {
    char version[64];
    char description[1024];
    char date[64];
    FexeFile files[MAX_FILES];
    int file_count;
    OsCommand run_cmds[MAX_COMMANDS];
    int run_cmd_count;
} FexeVersion;

typedef struct {
    char name[256];
    int enabled;
} Permission;

typedef struct {
    char variant_name[256];
    Feature features[MAX_FEATURES];
    int feature_count;
    FexeFile files[MAX_FILES];
    int file_count;
} FexeVariant;

typedef struct {
    char name[512];
    char description[2048];
    char author[512];
    char license[256];
    char homepage[512];
    char repository[512];
    char created[64];
    char updated[64];
    char pgp_signature[4096];
    char sha256[128];
    FexeVersion versions[MAX_VERSIONS];
    int version_count;
    FexeVariant variants[MAX_VARIANTS];
    int variant_count;
    Permission sandbox_perms[MAX_PERMS];
    int perm_count;
    int sandboxed;
} FexePackage;

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[fexe error] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

static void info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stdout, "[fexe] ");
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    va_end(ap);
}

static char *trim(char *s) {
    size_t i=0,j;
    while (isspace((unsigned char)s[i])) i++;
    if (i>0) memmove(s,s+i,strlen(s)-i+1);
    j=strlen(s);
    while (j>0 && isspace((unsigned char)s[j-1])) j--;
    s[j]=0;
    return s;
}

static int starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static void strip_quotes(char *s) {
    size_t len = strlen(s);
    if (len >= 2 && s[0] == '"' && s[len-1] == '"') {
        memmove(s, s+1, len-2);
        s[len-2] = 0;
    }
}

static uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define S0(x) (ROTR32(x,2)^ROTR32(x,13)^ROTR32(x,22))
#define S1(x) (ROTR32(x,6)^ROTR32(x,11)^ROTR32(x,25))
#define G0(x) (ROTR32(x,7)^ROTR32(x,18)^((x)>>3))
#define G1(x) (ROTR32(x,17)^ROTR32(x,19)^((x)>>10))

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buf[64];
    uint32_t buflen;
} SHA256Ctx;

static void sha256_transform(SHA256Ctx *ctx, const uint8_t *data) {
    uint32_t w[64], a,b,c,d,e,f,g,h,t1,t2;
    for (int i=0;i<16;i++) w[i]=((uint32_t)data[i*4]<<24)|((uint32_t)data[i*4+1]<<16)|((uint32_t)data[i*4+2]<<8)|(uint32_t)data[i*4+3];
    for (int i=16;i<64;i++) w[i]=G1(w[i-2])+w[i-7]+G0(w[i-15])+w[i-16];
    a=ctx->state[0];b=ctx->state[1];c=ctx->state[2];d=ctx->state[3];
    e=ctx->state[4];f=ctx->state[5];g=ctx->state[6];h=ctx->state[7];
    for (int i=0;i<64;i++) {
        t1=h+S1(e)+CH(e,f,g)+sha256_k[i]+w[i];
        t2=S0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=d;
    ctx->state[4]+=e;ctx->state[5]+=f;ctx->state[6]+=g;ctx->state[7]+=h;
}

static void sha256_init(SHA256Ctx *ctx) {
    ctx->state[0]=0x6a09e667;ctx->state[1]=0xbb67ae85;ctx->state[2]=0x3c6ef372;ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f;ctx->state[5]=0x9b05688c;ctx->state[6]=0x1f83d9ab;ctx->state[7]=0x5be0cd19;
    ctx->bitlen=0;ctx->buflen=0;
}

static void sha256_update(SHA256Ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i=0;i<len;i++) {
        ctx->buf[ctx->buflen++]=data[i];
        if (ctx->buflen==64) { sha256_transform(ctx,ctx->buf); ctx->bitlen+=512; ctx->buflen=0; }
    }
}

static void sha256_final(SHA256Ctx *ctx, uint8_t *digest) {
    uint32_t i=ctx->buflen;
    ctx->buf[i++]=0x80;
    if (ctx->buflen<56) { while(i<56) ctx->buf[i++]=0; }
    else { while(i<64) ctx->buf[i++]=0; sha256_transform(ctx,ctx->buf); memset(ctx->buf,0,56); }
    ctx->bitlen+=ctx->buflen*8;
    for (int j=7;j>=0;j--) { ctx->buf[56+(7-j)]=(ctx->bitlen>>(j*8))&0xff; }
    sha256_transform(ctx,ctx->buf);
    for (int j=0;j<8;j++) { digest[j*4]=(ctx->state[j]>>24)&0xff; digest[j*4+1]=(ctx->state[j]>>16)&0xff; digest[j*4+2]=(ctx->state[j]>>8)&0xff; digest[j*4+3]=ctx->state[j]&0xff; }
}

static void compute_sha256(const char *data, size_t len, char *out) {
    SHA256Ctx ctx;
    uint8_t digest[32];
    sha256_init(&ctx);
    sha256_update(&ctx,(const uint8_t*)data,len);
    sha256_final(&ctx,digest);
    for (int i=0;i<32;i++) sprintf(out+i*2,"%02x",digest[i]);
    out[64]=0;
}

static int file_exists(const char *path) {
    STAT_STRUCT st;
    return STAT(path,&st)==0;
}

static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path,"rb");
    if (!f) return NULL;
    fseek(f,0,SEEK_END);
    long sz = ftell(f);
    fseek(f,0,SEEK_SET);
    char *buf = (char*)malloc(sz+1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf,1,sz,f);
    buf[sz]=0;
    fclose(f);
    if (out_len) *out_len=(size_t)sz;
    return buf;
}

static int write_file(const char *path, const char *data, size_t len) {
    FILE *f = fopen(path,"wb");
    if (!f) return -1;
    fwrite(data,1,len,f);
    fclose(f);
    return 0;
}

static void makedirs(const char *path) {
    char tmp[4096];
    strncpy(tmp,path,sizeof(tmp)-1);
    size_t len = strlen(tmp);
    for (size_t i=1;i<len;i++) {
        if (tmp[i]=='/' || tmp[i]=='\\') {
            char c = tmp[i]; tmp[i]=0;
            MKDIR(tmp);
            tmp[i]=c;
        }
    }
    MKDIR(tmp);
}

static void input_line(const char *prompt, char *buf, size_t sz) {
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(buf, (int)sz, stdin)) buf[0]=0;
    size_t l = strlen(buf);
    if (l>0 && buf[l-1]=='\n') buf[l-1]=0;
}

typedef struct {
    char **lines;
    int count;
    int cap;
    int pos;
} LineReader;

static LineReader *lr_new(const char *text) {
    LineReader *lr = (LineReader*)calloc(1,sizeof(LineReader));
    lr->cap=256; lr->count=0;
    lr->lines=(char**)malloc(lr->cap*sizeof(char*));
    const char *p=text;
    while (*p) {
        const char *nl=strchr(p,'\n');
        size_t len = nl ? (size_t)(nl-p) : strlen(p);
        char *line=(char*)malloc(len+1);
        memcpy(line,p,len); line[len]=0;
        if (lr->count>=lr->cap) { lr->cap*=2; lr->lines=(char**)realloc(lr->lines,lr->cap*sizeof(char*)); }
        lr->lines[lr->count++]=line;
        p = nl ? nl+1 : p+len;
    }
    lr->pos=0;
    return lr;
}

static void lr_free(LineReader *lr) {
    for (int i=0;i<lr->count;i++) free(lr->lines[i]);
    free(lr->lines);
    free(lr);
}

static int lr_has(LineReader *lr) { return lr->pos < lr->count; }
static char *lr_peek(LineReader *lr) { return lr->pos < lr->count ? lr->lines[lr->pos] : NULL; }
static char *lr_next(LineReader *lr) { return lr->pos < lr->count ? lr->lines[lr->pos++] : NULL; }

static int is_section_header(const char *line, const char *name) {
    char pat[512];
    snprintf(pat,sizeof(pat),"[%s]",name);
    char *t = trim(strdup(line));
    int r = strcmp(t,pat)==0;
    free(t);
    return r;
}

static int is_section_start(const char *line) {
    char *t = trim(strdup(line));
    int r = t[0]=='[' && t[strlen(t)-1]==']';
    free(t);
    return r;
}

static int parse_kv(const char *line, char *key, char *val) {
    const char *eq = strchr(line,'=');
    if (!eq) return 0;
    size_t klen = (size_t)(eq-line);
    strncpy(key,line,klen); key[klen]=0;
    char *kt=trim(key); memmove(key,kt,strlen(kt)+1);
    strcpy(val,eq+1);
    char *vt=trim(val); memmove(val,vt,strlen(vt)+1);
    strip_quotes(val);
    return 1;
}

static FexeVersion *find_version(FexePackage *pkg, const char *ver) {
    for (int i=0;i<pkg->version_count;i++)
        if (strcmp(pkg->versions[i].version,ver)==0) return &pkg->versions[i];
    return NULL;
}

static FexeVersion *latest_version(FexePackage *pkg) {
    if (pkg->version_count==0) return NULL;
    return &pkg->versions[pkg->version_count-1];
}

static FexePackage *parse_fexe(const char *text) {
    FexePackage *pkg = (FexePackage*)calloc(1,sizeof(FexePackage));
    pkg->sandboxed=1;
    LineReader *lr = lr_new(text);
    char key[MAX_KEY], val[MAX_VAL];

    while (lr_has(lr)) {
        char *raw = lr_next(lr);
        char *line = trim(strdup(raw));
        if (line[0]==0 || line[0]=='#') { free(line); continue; }

        if (is_section_header(line,"package")) {
            free(line);
            while (lr_has(lr)) {
                char *rl = lr_peek(lr);
                char *tl = trim(strdup(rl));
                if (is_section_start(tl)) { free(tl); break; }
                lr_next(lr);
                if (tl[0]==0||tl[0]=='#') { free(tl); continue; }
                if (parse_kv(tl,key,val)) {
                    if (strcmp(key,"name")==0) strncpy(pkg->name,val,sizeof(pkg->name)-1);
                    else if (strcmp(key,"description")==0) strncpy(pkg->description,val,sizeof(pkg->description)-1);
                    else if (strcmp(key,"author")==0) strncpy(pkg->author,val,sizeof(pkg->author)-1);
                    else if (strcmp(key,"license")==0) strncpy(pkg->license,val,sizeof(pkg->license)-1);
                    else if (strcmp(key,"homepage")==0) strncpy(pkg->homepage,val,sizeof(pkg->homepage)-1);
                    else if (strcmp(key,"repository")==0) strncpy(pkg->repository,val,sizeof(pkg->repository)-1);
                    else if (strcmp(key,"created")==0) strncpy(pkg->created,val,sizeof(pkg->created)-1);
                    else if (strcmp(key,"updated")==0) strncpy(pkg->updated,val,sizeof(pkg->updated)-1);
                    else if (strcmp(key,"sandboxed")==0) pkg->sandboxed=(strcmp(val,"true")==0||strcmp(val,"yes")==0||strcmp(val,"1")==0);
                }
                free(tl);
            }
            continue;
        }

        if (is_section_header(line,"integrity")) {
            free(line);
            while (lr_has(lr)) {
                char *rl = lr_peek(lr);
                char *tl = trim(strdup(rl));
                if (is_section_start(tl)) { free(tl); break; }
                lr_next(lr);
                if (tl[0]==0||tl[0]=='#') { free(tl); continue; }
                if (parse_kv(tl,key,val)) {
                    if (strcmp(key,"sha256")==0) strncpy(pkg->sha256,val,sizeof(pkg->sha256)-1);
                    else if (strcmp(key,"pgp")==0) strncpy(pkg->pgp_signature,val,sizeof(pkg->pgp_signature)-1);
                }
                free(tl);
            }
            continue;
        }

        if (is_section_header(line,"permissions")) {
            free(line);
            while (lr_has(lr)) {
                char *rl = lr_peek(lr);
                char *tl = trim(strdup(rl));
                if (is_section_start(tl)) { free(tl); break; }
                lr_next(lr);
                if (tl[0]==0||tl[0]=='#') { free(tl); continue; }
                if (parse_kv(tl,key,val)) {
                    if (pkg->perm_count<MAX_PERMS) {
                        strncpy(pkg->sandbox_perms[pkg->perm_count].name,key,255);
                        pkg->sandbox_perms[pkg->perm_count].enabled=(strcmp(val,"true")==0||strcmp(val,"allow")==0||strcmp(val,"yes")==0||strcmp(val,"1")==0);
                        pkg->perm_count++;
                    }
                }
                free(tl);
            }
            continue;
        }

        if (starts_with(line,"[version.")) {
            char ver_id[128]={0};
            sscanf(line,"[version.%127[^]]",ver_id);
            free(line);
            if (pkg->version_count>=MAX_VERSIONS) continue;
            FexeVersion *v = &pkg->versions[pkg->version_count++];
            strncpy(v->version,ver_id,sizeof(v->version)-1);
            int in_file=0;
            char cur_filename[512]={0};
            char file_content[1<<20]={0};
            int file_content_len=0;

            while (lr_has(lr)) {
                char *rl = lr_peek(lr);
                char *tl = trim(strdup(rl));

                if (is_section_start(tl) && !starts_with(tl,"[file.") && !starts_with(tl,"[run.")) {
                    if (in_file && cur_filename[0]) {
                        if (v->file_count<MAX_FILES) {
                            strncpy(v->files[v->file_count].name,cur_filename,511);
                            memcpy(v->files[v->file_count].content,file_content,file_content_len);
                            v->files[v->file_count].content_len=file_content_len;
                            v->file_count++;
                        }
                        in_file=0; cur_filename[0]=0; file_content[0]=0; file_content_len=0;
                    }
                    free(tl); break;
                }

                lr_next(lr);

                if (starts_with(tl,"[file.")) {
                    if (in_file && cur_filename[0]) {
                        if (v->file_count<MAX_FILES) {
                            strncpy(v->files[v->file_count].name,cur_filename,511);
                            memcpy(v->files[v->file_count].content,file_content,file_content_len);
                            v->files[v->file_count].content_len=file_content_len;
                            v->file_count++;
                        }
                    }
                    sscanf(tl,"[file.%511[^]]",cur_filename);
                    file_content[0]=0; file_content_len=0; in_file=1;
                    free(tl); continue;
                }

                if (starts_with(tl,"[run.")) {
                    if (in_file && cur_filename[0]) {
                        if (v->file_count<MAX_FILES) {
                            strncpy(v->files[v->file_count].name,cur_filename,511);
                            memcpy(v->files[v->file_count].content,file_content,file_content_len);
                            v->files[v->file_count].content_len=file_content_len;
                            v->file_count++;
                        }
                        in_file=0; cur_filename[0]=0; file_content[0]=0; file_content_len=0;
                    }
                    char run_os[64]={0};
                    sscanf(tl,"[run.%63[^]]",run_os);
                    free(tl);
                    while (lr_has(lr)) {
                        char *rrl = lr_peek(lr);
                        char *ttl = trim(strdup(rrl));
                        if (is_section_start(ttl)) { free(ttl); break; }
                        lr_next(lr);
                        if (ttl[0]==0||ttl[0]=='#') { free(ttl); continue; }
                        if (parse_kv(ttl,key,val) && strcmp(key,"cmd")==0) {
                            if (v->run_cmd_count<MAX_COMMANDS) {
                                strncpy(v->run_cmds[v->run_cmd_count].os,run_os,63);
                                strncpy(v->run_cmds[v->run_cmd_count].cmd,val,1023);
                                v->run_cmd_count++;
                            }
                        }
                        free(ttl);
                    }
                    continue;
                }

                if (in_file) {
                    char *orig = lr->lines[lr->pos-1];
                    size_t olen = strlen(orig);
                    if (file_content_len + olen + 2 < (1<<20)) {
                        memcpy(file_content+file_content_len,orig,olen);
                        file_content_len+=olen;
                        file_content[file_content_len++]='\n';
                        file_content[file_content_len]=0;
                    }
                } else {
                    if (parse_kv(tl,key,val)) {
                        if (strcmp(key,"description")==0) strncpy(v->description,val,sizeof(v->description)-1);
                        else if (strcmp(key,"date")==0) strncpy(v->date,val,sizeof(v->date)-1);
                    }
                }
                free(tl);
            }
            if (in_file && cur_filename[0]) {
                if (v->file_count<MAX_FILES) {
                    strncpy(v->files[v->file_count].name,cur_filename,511);
                    memcpy(v->files[v->file_count].content,file_content,file_content_len);
                    v->files[v->file_count].content_len=file_content_len;
                    v->file_count++;
                }
            }
            continue;
        }

        if (starts_with(line,"[variant.")) {
            char var_id[256]={0};
            sscanf(line,"[variant.%255[^]]",var_id);
            free(line);
            if (pkg->variant_count>=MAX_VARIANTS) continue;
            FexeVariant *vt = &pkg->variants[pkg->variant_count++];
            strncpy(vt->variant_name,var_id,255);

            while (lr_has(lr)) {
                char *rl = lr_peek(lr);
                char *tl = trim(strdup(rl));
                if (is_section_start(tl) && !starts_with(tl,"[feature.") && !starts_with(tl,"[file.")) {
                    free(tl); break;
                }
                lr_next(lr);
                if (starts_with(tl,"[feature.")) {
                    char feat_id[128]={0};
                    sscanf(tl,"[feature.%127[^]]",feat_id);
                    free(tl);
                    while (lr_has(lr)) {
                        char *rrl = lr_peek(lr);
                        char *ttl = trim(strdup(rrl));
                        if (is_section_start(ttl)) { free(ttl); break; }
                        lr_next(lr);
                        if (ttl[0]==0||ttl[0]=='#') { free(ttl); continue; }
                        if (parse_kv(ttl,key,val)) {
                            if (strcmp(key,"enabled")==0 && vt->feature_count<MAX_FEATURES) {
                                strncpy(vt->features[vt->feature_count].id,feat_id,127);
                                vt->features[vt->feature_count].enabled=(strcmp(val,"true")==0||strcmp(val,"yes")==0||strcmp(val,"1")==0);
                                vt->feature_count++;
                            } else if (strcmp(key,"label")==0 && vt->feature_count>0) {
                                strncpy(vt->features[vt->feature_count-1].label,val,255);
                            }
                        }
                        free(ttl);
                    }
                    continue;
                }
                if (tl[0]==0||tl[0]=='#') { free(tl); continue; }
                free(tl);
            }
            continue;
        }

        free(line);
    }

    lr_free(lr);
    return pkg;
}

static char *get_fexe_dir(void) {
    static char dir[4096];
#ifdef _WIN32
    const char *appdata = getenv("APPDATA");
    if (!appdata) appdata = getenv("USERPROFILE");
    snprintf(dir,sizeof(dir),"%s\\fexe",appdata?appdata:".");
#else
    const char *home = getenv("HOME");
    if (!home) home = ".";
    snprintf(dir,sizeof(dir),"%s/.fexe",home);
#endif
    return dir;
}

static int check_permission(FexePackage *pkg, const char *perm) {
    if (!pkg->sandboxed) return 1;
    for (int i=0;i<pkg->perm_count;i++)
        if (strcmp(pkg->sandbox_perms[i].name,perm)==0) return pkg->sandbox_perms[i].enabled;
    return 0;
}

static void print_sandbox_report(FexePackage *pkg) {
    if (!pkg->sandboxed) { info("Sandbox: DISABLED (full access)"); return; }
    info("Sandbox: ENABLED");
    for (int i=0;i<pkg->perm_count;i++) {
        printf("  %-20s %s\n", pkg->sandbox_perms[i].name, pkg->sandbox_perms[i].enabled?"ALLOW":"DENY");
    }
}

static int ask_user_permission(const char *perm) {
    char buf[16];
    printf("[fexe] Package requests permission: %s\n", perm);
    printf("[fexe] Allow? [y/N] ");
    fflush(stdout);
    if (!fgets(buf,sizeof(buf),stdin)) return 0;
    return buf[0]=='y'||buf[0]=='Y';
}

static void apply_variant(FexeVersion *v, FexeVariant *var, const char **remove_feats, int nremove, const char **add_feats, int nadd) {
    (void)v;
    printf("[fexe] Applying variant: %s\n", var->variant_name);
    for (int i=0;i<var->feature_count;i++) {
        int enabled = var->features[i].enabled;
        for (int j=0;j<nremove;j++) if (strcmp(remove_feats[j],var->features[i].id)==0) enabled=0;
        for (int j=0;j<nadd;j++) if (strcmp(add_feats[j],var->features[i].id)==0) enabled=1;
        printf("  feature %-24s %s\n", var->features[i].id, enabled?"ON":"OFF");
    }
}

static int run_version(FexePackage *pkg, FexeVersion *v, const char **remove_feats, int nremove, const char **add_feats, int nadd, int interactive_perms) {
    char tmpdir[4096];
    char *fexe_home = get_fexe_dir();
    snprintf(tmpdir,sizeof(tmpdir),"%s%srun_%s_%s",fexe_home,PATH_SEP,pkg->name,v->version);
    for (char *p=tmpdir+strlen(fexe_home)+1;*p;p++) if (*p==' '||*p=='/'||*p=='\\') *p='_';
    makedirs(tmpdir);

    for (int i=0;i<v->file_count;i++) {
        char fpath[4096];
        snprintf(fpath,sizeof(fpath),"%s%s%s",tmpdir,PATH_SEP,v->files[i].name);
        char *sl = strrchr(fpath, '/');
        char *bs = strrchr(fpath, '\\');
        char *last = sl>bs?sl:bs;
        if (last && last!=fpath) {
            char dpath[4096];
            size_t dlen=(size_t)(last-fpath);
            strncpy(dpath,fpath,dlen); dpath[dlen]=0;
            makedirs(dpath);
        }
        if (write_file(fpath,v->files[i].content,(size_t)v->files[i].content_len)<0) {
            fprintf(stderr,"[fexe] Failed to write %s\n",fpath);
            return 1;
        }
        info("Extracted: %s",v->files[i].name);
    }

    if (pkg->sandboxed && interactive_perms) {
        for (int i=0;i<pkg->perm_count;i++) {
            if (!pkg->sandbox_perms[i].enabled) {
                if (ask_user_permission(pkg->sandbox_perms[i].name))
                    pkg->sandbox_perms[i].enabled=1;
            }
        }
    }

    print_sandbox_report(pkg);

    if (nremove>0||nadd>0) {
        for (int i=0;i<pkg->variant_count;i++)
            apply_variant(v,&pkg->variants[i],remove_feats,nremove,add_feats,nadd);
    }

    const char *cmd = NULL;
    for (int i=0;i<v->run_cmd_count;i++) {
        if (strcmp(v->run_cmds[i].os,OS_NAME)==0) { cmd=v->run_cmds[i].cmd; break; }
        if (strcmp(v->run_cmds[i].os,"all")==0 && !cmd) cmd=v->run_cmds[i].cmd;
    }

    if (!cmd) {
        fprintf(stderr,"[fexe] No run command for OS: %s\n",OS_NAME);
        return 1;
    }

    char full_cmd[2048];
    snprintf(full_cmd,sizeof(full_cmd),"cd \"%s\" && %s",tmpdir,cmd);
    info("Running: %s", cmd);
    int ret = system(full_cmd);
#ifdef _WIN32
    return ret;
#else
    return WEXITSTATUS(ret);
#endif
}

static void cmd_run(int argc, char **argv) {
    if (argc < 3) die("Usage: fexe run [--remove feat] [--add feat] <file.fexe>");

    const char *fexe_path = NULL;
    const char *remove_feats[MAX_FEATURES]; int nremove=0;
    const char *add_feats[MAX_FEATURES]; int nadd=0;

    for (int i=2;i<argc;i++) {
        if (strcmp(argv[i],"--remove")==0 && i+1<argc) { remove_feats[nremove++]=argv[++i]; }
        else if (strcmp(argv[i],"--add")==0 && i+1<argc) { add_feats[nadd++]=argv[++i]; }
        else fexe_path=argv[i];
    }

    if (!fexe_path) die("No .fexe file specified");

    size_t flen;
    char *text = read_file(fexe_path,&flen);
    if (!text) die("Cannot open: %s", fexe_path);

    FexePackage *pkg = parse_fexe(text);
    free(text);

    FexeVersion *v = latest_version(pkg);
    if (!v) die("No versions found in package");

    info("Package: %s", pkg->name);
    info("Version: %s", v->version);
    info("Description: %s", pkg->description);

    int ret = run_version(pkg,v,remove_feats,nremove,add_feats,nadd,1);
    free(pkg);
    exit(ret);
}

static void cmd_version(int argc, char **argv) {
    if (argc < 4) die("Usage: fexe version <ver> <file.fexe>");
    const char *ver = argv[2];
    const char *fexe_path = argv[3];

    size_t flen;
    char *text = read_file(fexe_path,&flen);
    if (!text) die("Cannot open: %s", fexe_path);

    FexePackage *pkg = parse_fexe(text);
    free(text);

    FexeVersion *v = find_version(pkg,ver);
    if (!v) die("Version not found: %s", ver);

    info("Package: %s", pkg->name);
    info("Version: %s", v->version);

    int ret = run_version(pkg,v,NULL,0,NULL,0,1);
    free(pkg);
    exit(ret);
}

static void cmd_init(int argc, char **argv) {
    if (argc < 3) die("Usage: fexe init <output.fexe>");
    const char *out = argv[2];

    char name[512]={0}, description[1024]={0}, author[256]={0};
    char license[128]={0}, homepage[512]={0};
    char ver[64]={0}, ver_desc[512]={0};
    char lang[64]={0};

    printf("\n  fexe init - create a new .fexe package\n\n");
    input_line("  Package name: ",name,sizeof(name));
    input_line("  Description: ",description,sizeof(description));
    input_line("  Author: ",author,sizeof(author));
    input_line("  License (e.g. MIT): ",license,sizeof(license));
    input_line("  Homepage (optional): ",homepage,sizeof(homepage));
    input_line("  Initial version (e.g. 1.0.0): ",ver,sizeof(ver));
    if (!ver[0]) strncpy(ver,"1.0.0",sizeof(ver)-1);
    input_line("  Version description: ",ver_desc,sizeof(ver_desc));
    input_line("  Language/runtime (e.g. python, node, bash, c): ",lang,sizeof(lang));

    char run_all[256]={0}, run_win[256]={0}, run_mac[256]={0}, run_linux[256]={0};
    printf("  Run commands (leave blank to skip):\n");
    input_line("  Run command (all): ",run_all,sizeof(run_all));
    if (!run_all[0]) {
        input_line("  Run command (windows): ",run_win,sizeof(run_win));
        input_line("  Run command (macos): ",run_mac,sizeof(run_mac));
        input_line("  Run command (linux): ",run_linux,sizeof(run_linux));
    }

    char mainfile[256]={0};
    input_line("  Main file name (e.g. main.py): ",mainfile,sizeof(mainfile));

    char sandbox[8]={0};
    input_line("  Enable sandbox? [Y/n]: ",sandbox,sizeof(sandbox));
    int is_sandboxed = !(sandbox[0]=='n'||sandbox[0]=='N');

    time_t now=time(NULL);
    struct tm *tm_info=localtime(&now);
    char today[32];
    strftime(today,sizeof(today),"%Y-%m-%d",tm_info);

    FILE *f=fopen(out,"w");
    if (!f) die("Cannot create: %s", out);

    fprintf(f,"[package]\n");
    fprintf(f,"name        = \"%s\"\n",name);
    fprintf(f,"description = \"%s\"\n",description);
    fprintf(f,"author      = \"%s\"\n",author);
    fprintf(f,"license     = \"%s\"\n",license);
    if (homepage[0]) fprintf(f,"homepage    = \"%s\"\n",homepage);
    fprintf(f,"created     = \"%s\"\n",today);
    fprintf(f,"updated     = \"%s\"\n",today);
    fprintf(f,"sandboxed   = %s\n\n",is_sandboxed?"true":"false");

    if (is_sandboxed) {
        fprintf(f,"[permissions]\n");
        fprintf(f,"network    = false\n");
        fprintf(f,"filesystem = false\n");
        fprintf(f,"env        = false\n");
        fprintf(f,"process    = false\n\n");
    }

    fprintf(f,"[integrity]\n");
    fprintf(f,"sha256 = \"\"\n");
    fprintf(f,"pgp    = \"\"\n\n");

    fprintf(f,"[version.%s]\n",ver);
    fprintf(f,"description = \"%s\"\n",ver_desc);
    fprintf(f,"date        = \"%s\"\n\n",today);

    if (run_all[0]) {
        fprintf(f,"[run.all]\n");
        fprintf(f,"cmd = \"%s\"\n\n",run_all);
    } else {
        if (run_win[0]) { fprintf(f,"[run.windows]\n"); fprintf(f,"cmd = \"%s\"\n\n",run_win); }
        if (run_mac[0]) { fprintf(f,"[run.macos]\n"); fprintf(f,"cmd = \"%s\"\n\n",run_mac); }
        if (run_linux[0]) { fprintf(f,"[run.linux]\n"); fprintf(f,"cmd = \"%s\"\n\n",run_linux); }
        if (!run_win[0]&&!run_mac[0]&&!run_linux[0]) {
            fprintf(f,"[run.all]\n");
            fprintf(f,"cmd = \"echo 'no run command defined'\"\n\n");
        }
    }

    if (mainfile[0]) {
        fprintf(f,"[file.%s]\n",mainfile);
        if (strstr(mainfile,".py")) fprintf(f,"print('Hello from %s via fexe!')\n",name);
        else if (strstr(mainfile,".js")) fprintf(f,"console.log('Hello from %s via fexe!');\n",name);
        else if (strstr(mainfile,".sh")) fprintf(f,"#!/bin/sh\necho 'Hello from %s via fexe!'\n",name);
        else if (strstr(mainfile,".c")) fprintf(f,"#include <stdio.h>\nint main(){printf(\"Hello from %s via fexe!\\n\");return 0;}\n",name);
        else fprintf(f,"# %s main file\n",name);
        fprintf(f,"\n");
    }

    fclose(f);
    info("Created: %s", out);
    printf("\n  Edit %s to add your code and fill in sha256/pgp.\n\n", out);
}

static void cmd_install(int argc, char **argv) {
    if (argc < 3) die("Usage: fexe install <url>");
    const char *url = argv[2];

    char *fexe_home = get_fexe_dir();
    makedirs(fexe_home);

    const char *slash = strrchr(url,'/');
    const char *fname = slash ? slash+1 : url;
    if (!fname[0]) fname="package.fexe";

    char dest[4096];
    snprintf(dest,sizeof(dest),"%s%s%s",fexe_home,PATH_SEP,fname);

    char fetch_cmd[4096];
#ifdef _WIN32
    snprintf(fetch_cmd,sizeof(fetch_cmd),"powershell -Command \"Invoke-WebRequest -Uri '%s' -OutFile '%s'\"",url,dest);
#else
    snprintf(fetch_cmd,sizeof(fetch_cmd),"curl -fsSL \"%s\" -o \"%s\" 2>/dev/null || wget -q \"%s\" -O \"%s\"",url,dest,url,dest);
#endif

    info("Downloading: %s", url);
    int ret = system(fetch_cmd);
    if (ret != 0 || !file_exists(dest)) die("Failed to download: %s", url);

    size_t flen;
    char *text = read_file(dest,&flen);
    if (!text) die("Cannot read downloaded file");

    FexePackage *pkg = parse_fexe(text);

    char actual_hash[65];
    compute_sha256(text,flen,actual_hash);

    if (pkg->sha256[0]) {
        if (strcmp(actual_hash,pkg->sha256)!=0) {
            fprintf(stderr,"[fexe] SHA256 MISMATCH!\n  Expected: %s\n  Got:      %s\n",pkg->sha256,actual_hash);
            free(text); free(pkg); unlink(dest);
            exit(1);
        }
        info("SHA256 OK: %s", actual_hash);
    } else {
        info("SHA256 (no check): %s", actual_hash);
    }

    free(text);

    info("Installed: %s -> %s", pkg->name, dest);
    printf("\n  Run with: fexe run %s\n\n", dest);
    free(pkg);
}

static void cmd_info(int argc, char **argv) {
    if (argc < 3) die("Usage: fexe info <file.fexe>");
    size_t flen;
    char *text = read_file(argv[2],&flen);
    if (!text) die("Cannot open: %s", argv[2]);
    FexePackage *pkg = parse_fexe(text);

    char hash[65];
    compute_sha256(text,flen,hash);
    free(text);

    printf("\n  Name:        %s\n",pkg->name);
    printf("  Description: %s\n",pkg->description);
    printf("  Author:      %s\n",pkg->author);
    printf("  License:     %s\n",pkg->license);
    if (pkg->homepage[0]) printf("  Homepage:    %s\n",pkg->homepage);
    printf("  Created:     %s\n",pkg->created);
    printf("  Updated:     %s\n",pkg->updated);
    printf("  Sandboxed:   %s\n",pkg->sandboxed?"yes":"no");
    printf("  SHA256:      %s\n",hash);
    printf("  Versions:\n");
    for (int i=0;i<pkg->version_count;i++)
        printf("    %-12s %s\n",pkg->versions[i].version,pkg->versions[i].description);
    if (pkg->variant_count>0) {
        printf("  Variants:\n");
        for (int i=0;i<pkg->variant_count;i++) printf("    %s\n",pkg->variants[i].variant_name);
    }
    if (pkg->perm_count>0) {
        printf("  Permissions:\n");
        for (int i=0;i<pkg->perm_count;i++)
            printf("    %-20s %s\n",pkg->sandbox_perms[i].name,pkg->sandbox_perms[i].enabled?"allow":"deny");
    }
    printf("\n");
    free(pkg);
}

static void cmd_verify(int argc, char **argv) {
    if (argc < 3) die("Usage: fexe verify <file.fexe>");
    size_t flen;
    char *text = read_file(argv[2],&flen);
    if (!text) die("Cannot open: %s", argv[2]);
    FexePackage *pkg = parse_fexe(text);

    char actual[65];
    compute_sha256(text,flen,actual);
    free(text);

    if (!pkg->sha256[0]) { info("No SHA256 in package, computed: %s", actual); free(pkg); return; }
    if (strcmp(actual,pkg->sha256)==0) { info("Integrity OK: %s", actual); }
    else {
        fprintf(stderr,"[fexe] INTEGRITY FAIL\n  Expected: %s\n  Got:      %s\n",pkg->sha256,actual);
        free(pkg); exit(1);
    }
    free(pkg);
}

static void cmd_hash(int argc, char **argv) {
    if (argc < 3) die("Usage: fexe hash <file.fexe>");
    size_t flen;
    char *text = read_file(argv[2],&flen);
    if (!text) die("Cannot open: %s", argv[2]);
    char hash[65];
    compute_sha256(text,flen,hash);
    free(text);
    printf("%s\n",hash);
}

static void cmd_list(int argc, char **argv) {
    (void)argc; (void)argv;
    char *fexe_home = get_fexe_dir();
#ifdef _WIN32
    WIN32_FIND_DATA fd;
    char pat[4096];
    snprintf(pat,sizeof(pat),"%s\\*.fexe",fexe_home);
    HANDLE h=FindFirstFile(pat,&fd);
    if (h==INVALID_HANDLE_VALUE) { info("No packages installed"); return; }
    do { printf("  %s\n",fd.cFileName); } while(FindNextFile(h,&fd));
    FindClose(h);
#else
    DIR *d=opendir(fexe_home);
    if (!d) { info("No packages installed"); return; }
    struct dirent *ent;
    while ((ent=readdir(d))) {
        const char *dot=strrchr(ent->d_name,'.');
        if (dot && strcmp(dot,".fexe")==0) printf("  %s\n",ent->d_name);
    }
    closedir(d);
#endif
}

static void print_usage(void) {
    printf("\n  fexe v%s - the fuck exe package runner\n\n", FEXE_VERSION);
    printf("  Usage:\n");
    printf("    fexe init <output.fexe>                    create a new fexe package\n");
    printf("    fexe run [--remove feat] [--add feat] <f>  run a .fexe file\n");
    printf("    fexe version <ver> <file.fexe>             run specific version\n");
    printf("    fexe install <url>                         download and install\n");
    printf("    fexe info <file.fexe>                      show package info\n");
    printf("    fexe verify <file.fexe>                    verify sha256 integrity\n");
    printf("    fexe hash <file.fexe>                      print sha256 of file\n");
    printf("    fexe list                                   list installed packages\n\n");
}

int main(int argc, char **argv) {
    if (argc < 2) { print_usage(); return 0; }

    const char *cmd = argv[1];
    if (strcmp(cmd,"init")==0) cmd_init(argc,argv);
    else if (strcmp(cmd,"run")==0) cmd_run(argc,argv);
    else if (strcmp(cmd,"version")==0) cmd_version(argc,argv);
    else if (strcmp(cmd,"install")==0) cmd_install(argc,argv);
    else if (strcmp(cmd,"info")==0) cmd_info(argc,argv);
    else if (strcmp(cmd,"verify")==0) cmd_verify(argc,argv);
    else if (strcmp(cmd,"hash")==0) cmd_hash(argc,argv);
    else if (strcmp(cmd,"list")==0) cmd_list(argc,argv);
    else if (strcmp(cmd,"--version")==0||strcmp(cmd,"-v")==0) printf("fexe %s\n",FEXE_VERSION);
    else { fprintf(stderr,"[fexe] Unknown command: %s\n",cmd); print_usage(); return 1; }

    return 0;
}
