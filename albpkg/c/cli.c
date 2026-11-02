/* ALBPKG/1 C command line interface.
 *
 * Passphrases never come from argv. Cryptographic operations are delegated to
 * albpkg.c and OpenSSL EVP; this file handles bounded text/file framing and the
 * local contact database.
 */
#define _POSIX_C_SOURCE 200809L
#include "albpkg.h"
#include "openssl_abi.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#include <direct.h>
#include <io.h>
#include <fcntl.h>
#define sync_fd _commit
#define duplicate_fd _dup
#define fd_to_file _fdopen
#define close_fd _close
#else
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#define sync_fd fsync
#define duplicate_fd dup
#define fd_to_file fdopen
#define close_fd close
#endif

#define PATH_CAP 32768u
#define PUBID_LEN 3150u
#define CONTACT_MAX 3230u
#define PUBLIC_MAX 8192u
#define PACKAGE_HEADER 1194u

static const char PUBLIC_BEGIN[]="-----BEGIN ALBPKG PUBLIC IDENTITY-----\n";
static const char PUBLIC_SUITE[]="suite: ALBPKG-1\n";
static const char PUBLIC_FPR[]="fingerprint: ";
static const char PUBLIC_END[]="-----END ALBPKG PUBLIC IDENTITY-----\n";
static const unsigned char CONTACT_MAGIC[8]={'A','L','B','C','T','C','1',0};

typedef struct {
 const char *home,*identity,*command,*to;
 const char *positional[4];
 size_t positional_count;
 int overwrite,passphrase_fd;
} options;

static const char USAGE[]=
"albpkg 1.0.0 -- signed post-quantum file packages\n\n"
"Usage: albpkg [global options] <command> [arguments]\n\n"
"Commands:\n"
"  generate-identity\n"
"  export-public-identity <out>\n"
"  show-identity\n"
"  migrate-legacy-identity <old>\n"
"  import-contact <name> <file>\n"
"  verify-contact <contact> <full-fingerprint>\n"
"  list-contacts\n"
"  revoke-contact <contact>\n"
"  seal <in> <out> --to <contact>\n"
"  open <in> <out>\n\n"
"Global options: --home <dir> --identity <file> --passphrase-fd <n>\n"
"                --overwrite --help --version\n\n"
"Passphrases are read from a protected prompt, --passphrase-fd, or the file\n"
"named by ALBPKG_PASSPHRASE_FILE. They are never accepted in argv.\n";

static int fail(const char *message){fprintf(stderr,"albpkg: %s\n",message);return 2;}
static int checked_join(char out[PATH_CAP],const char*a,const char*b){size_t an=strlen(a),bn=strlen(b);if(an+1+bn+1>PATH_CAP)return 0;memcpy(out,a,an);if(an&&a[an-1]!='/'&&a[an-1]!='\\')out[an++]='/';memcpy(out+an,b,bn+1);return 1;}
static int ascii_alnum(unsigned char c){return (c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9');}

#ifdef _WIN32
static wchar_t *wide(const char *text){int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text,-1,NULL,0);wchar_t*out;if(!n)return NULL;out=(wchar_t*)calloc((size_t)n,sizeof(*out));if(out&&!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text,-1,out,n)){free(out);out=NULL;}return out;}
static char *narrow(const wchar_t *text){int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,text,-1,NULL,0,NULL,NULL);char*out;if(!n)return NULL;out=(char*)calloc((size_t)n,1);if(out&&!WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,text,-1,out,n,NULL,NULL)){free(out);out=NULL;}return out;}
static FILE *open_read(const char*p){wchar_t*w=wide(p);FILE*f=w?_wfopen(w,L"rb"):NULL;free(w);return f;}
static FILE *open_new(const char*p){wchar_t*w=wide(p);PSECURITY_DESCRIPTOR sd=NULL;SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,FALSE};HANDLE h=INVALID_HANDLE_VALUE;int fd;FILE*f=NULL;if(w&&ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;OW)",SDDL_REVISION_1,&sd,NULL)){sa.lpSecurityDescriptor=sd;h=CreateFileW(w,GENERIC_READ|GENERIC_WRITE,0,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);}if(sd)LocalFree(sd);free(w);if(h==INVALID_HANDLE_VALUE)return NULL;fd=_open_osfhandle((intptr_t)h,_O_BINARY|_O_RDWR);if(fd<0){CloseHandle(h);return NULL;}f=_fdopen(fd,"w+b");if(!f)_close(fd);return f;}
static int remove_file(const char*p){wchar_t*w=wide(p);int ok=w&&DeleteFileW(w);free(w);return ok;}
static int publish_file(const char*a,const char*b,int overwrite){wchar_t*wa=wide(a),*wb=wide(b);DWORD flags=MOVEFILE_WRITE_THROUGH|(overwrite?MOVEFILE_REPLACE_EXISTING:0);int ok=wa&&wb&&MoveFileExW(wa,wb,flags);free(wa);free(wb);return ok;}
static int make_dir(const char*p){wchar_t*w=wide(p);DWORD attr;int ok=0;if(!w)return 0;if(CreateDirectoryW(w,NULL))ok=1;else if(GetLastError()==ERROR_ALREADY_EXISTS){attr=GetFileAttributesW(w);ok=attr!=INVALID_FILE_ATTRIBUTES&&(attr&FILE_ATTRIBUTE_DIRECTORY);}free(w);return ok;}
static int file_exists(const char*p){wchar_t*w=wide(p);DWORD attr=w?GetFileAttributesW(w):INVALID_FILE_ATTRIBUTES;free(w);return attr!=INVALID_FILE_ATTRIBUTES&&!(attr&FILE_ATTRIBUTE_DIRECTORY);}
#else
static FILE *open_read(const char*p){return fopen(p,"rb");}
static FILE *open_new(const char*p){int fd=open(p,O_WRONLY|O_CREAT|O_EXCL,0600);FILE*f;if(fd<0)return NULL;f=fdopen(fd,"wb");if(!f)close(fd);return f;}
static int remove_file(const char*p){return unlink(p)==0;}
static int publish_file(const char*a,const char*b,int overwrite){if(overwrite)return rename(a,b)==0;if(link(a,b))return 0;unlink(a);return 1;}
static int make_dir(const char*p){return mkdir(p,0700)==0||errno==EEXIST;}
static int file_exists(const char*p){struct stat st;return stat(p,&st)==0&&S_ISREG(st.st_mode);}
#endif

static int read_bounded(const char*path,size_t maximum,unsigned char**out,size_t*length){FILE*f=NULL;unsigned char*data=NULL;size_t used=0,n;*out=NULL;*length=0;f=open_read(path);if(!f)return 0;data=(unsigned char*)malloc(maximum+1);if(!data)goto done;while((n=fread(data+used,1,maximum+1-used,f))>0){used+=n;if(used>maximum)goto done;}if(ferror(f))goto done;*out=data;*length=used;data=NULL;
done:if(f)fclose(f);free(data);return *out!=NULL;}

static int write_atomic(const char*path,const unsigned char*data,size_t length,int overwrite){unsigned char random[12];char temporary[PATH_CAP];FILE*f=NULL;size_t pn=strlen(path),i;int ok=0;if(pn+32>=PATH_CAP||RAND_bytes(random,sizeof(random))<=0)return 0;memcpy(temporary,path,pn);memcpy(temporary+pn,".alb-",5);for(i=0;i<sizeof(random);i++)sprintf(temporary+pn+5+i*2,"%02x",random[i]);strcpy(temporary+pn+29,".t");f=open_new(temporary);if(!f)return 0;if(fwrite(data,1,length,f)!=length||fflush(f)||sync_fd(fileno(f)))goto done;if(fclose(f)){f=NULL;goto done;}f=NULL;if(!publish_file(temporary,path,overwrite))goto done;ok=1;
done:if(f)fclose(f);if(!ok)remove_file(temporary);return ok;}

static void hex_plain(const unsigned char*in,size_t n,char*out){static const char h[]="0123456789abcdef";size_t i;for(i=0;i<n;i++){out[i*2]=h[in[i]>>4];out[i*2+1]=h[in[i]&15];}out[n*2]=0;}
static void fingerprint_text(const unsigned char fpr[32],char out[72]){char plain[65];size_t i,o=0;hex_plain(fpr,32,plain);for(i=0;i<64;i++){if(i&&i%8==0)out[o++]='-';out[o++]=plain[i];}out[o]=0;}
static int nibble(int c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static int parse_fingerprint(const char*text,unsigned char out[32]){char plain[65];size_t i,n=strlen(text),p=0;int a,b;if(n!=64&&n!=71)return 0;for(i=0;i<n;i++){if(n==71&&(i==8||i==17||i==26||i==35||i==44||i==53||i==62)){if(text[i]!='-')return 0;continue;}if(text[i]=='-'||p>=64||nibble((unsigned char)text[i])<0)return 0;plain[p++]=text[i];}if(p!=64)return 0;for(i=0;i<32;i++){a=nibble(plain[i*2]);b=nibble(plain[i*2+1]);out[i]=(unsigned char)((a<<4)|b);}return 1;}
static int valid_name(const char*name){size_t i,n=strlen(name);if(!n||n>64||!ascii_alnum((unsigned char)name[0]))return 0;for(i=1;i<n;i++)if(!ascii_alnum((unsigned char)name[i])&&name[i]!='.'&&name[i]!='_'&&name[i]!='@'&&name[i]!='+'&&name[i]!='-')return 0;return 1;}

static int armor_public(const unsigned char pubid[PUBID_LEN],unsigned char*out,size_t capacity,size_t*out_length){unsigned char fpr[32],base64[4300];char hex[65];int encoded;size_t needed,pos=0,i,take;if(alb_fingerprint(pubid,fpr)||!(encoded=EVP_EncodeBlock(base64,pubid,PUBID_LEN)))return 0;hex_plain(fpr,32,hex);needed=strlen(PUBLIC_BEGIN)+strlen(PUBLIC_SUITE)+strlen(PUBLIC_FPR)+64+1+(size_t)encoded+((size_t)encoded+63)/64+strlen(PUBLIC_END);if(needed>capacity)return 0;memcpy(out+pos,PUBLIC_BEGIN,strlen(PUBLIC_BEGIN));pos+=strlen(PUBLIC_BEGIN);memcpy(out+pos,PUBLIC_SUITE,strlen(PUBLIC_SUITE));pos+=strlen(PUBLIC_SUITE);memcpy(out+pos,PUBLIC_FPR,strlen(PUBLIC_FPR));pos+=strlen(PUBLIC_FPR);memcpy(out+pos,hex,64);pos+=64;out[pos++]='\n';for(i=0;i<(size_t)encoded;i+=take){take=(size_t)encoded-i;if(take>64)take=64;memcpy(out+pos,base64+i,take);pos+=take;out[pos++]='\n';}memcpy(out+pos,PUBLIC_END,strlen(PUBLIC_END));pos+=strlen(PUBLIC_END);*out_length=pos;return 1;}

static int parse_public(const unsigned char*text,size_t length,unsigned char pubid[PUBID_LEN]){size_t prefix=strlen(PUBLIC_BEGIN)+strlen(PUBLIC_SUITE)+strlen(PUBLIC_FPR),at=0,body_end,i,b64n=0,padding=0,canonical_len;unsigned char b64[4300],declared[32],actual[32],canonical[PUBLIC_MAX];int decoded;alb_contact validated;if(length<prefix+65+strlen(PUBLIC_END)||memcmp(text,PUBLIC_BEGIN,strlen(PUBLIC_BEGIN)))return 0;at=strlen(PUBLIC_BEGIN);if(memcmp(text+at,PUBLIC_SUITE,strlen(PUBLIC_SUITE)))return 0;at+=strlen(PUBLIC_SUITE);if(memcmp(text+at,PUBLIC_FPR,strlen(PUBLIC_FPR)))return 0;at+=strlen(PUBLIC_FPR);{char fpr[65];memcpy(fpr,text+at,64);fpr[64]=0;if(!parse_fingerprint(fpr,declared)||text[at+64]!='\n')return 0;}at+=65;if(length<strlen(PUBLIC_END)||memcmp(text+length-strlen(PUBLIC_END),PUBLIC_END,strlen(PUBLIC_END)))return 0;body_end=length-strlen(PUBLIC_END);for(i=at;i<body_end;i++){unsigned char c=text[i];if(c=='\n')continue;if(!(ascii_alnum(c)||c=='+'||c=='/'||c=='=')||b64n>=sizeof(b64))return 0;b64[b64n++]=c;}if(!b64n||b64n%4||b64n>INT_MAX)return 0;decoded=EVP_DecodeBlock(pubid,b64,(int)b64n);if(decoded<0)return 0;if(b64[b64n-1]=='=')padding++;if(b64n>1&&b64[b64n-2]=='=')padding++;if((size_t)decoded-padding!=PUBID_LEN||alb_import_contact(pubid,PUBID_LEN,&validated)||alb_fingerprint(pubid,actual)||CRYPTO_memcmp(actual,declared,32))return 0;if(!armor_public(pubid,canonical,sizeof(canonical),&canonical_len)||canonical_len!=length||memcmp(canonical,text,length))return 0;return 1;}

static int contact_path(const char*directory,const unsigned char pubid[PUBID_LEN],char out[PATH_CAP]){unsigned char fpr[32];char leaf[73];if(alb_fingerprint(pubid,fpr))return 0;hex_plain(fpr,32,leaf);strcat(leaf,".contact");return checked_join(out,directory,leaf);}
static int save_contact(const char*directory,const char*name,const alb_contact*contact){unsigned char blob[CONTACT_MAX];char path[PATH_CAP];size_t nn=strlen(name),n=10+nn+PUBID_LEN;if(!valid_name(name)||nn>255||!contact_path(directory,contact->pubid,path))return 0;memcpy(blob,CONTACT_MAGIC,8);blob[8]=(unsigned char)contact->trust;blob[9]=(unsigned char)nn;memcpy(blob+10,name,nn);memcpy(blob+10+nn,contact->pubid,PUBID_LEN);return write_atomic(path,blob,n,1);}
static int load_contact_file(const char*path,char name[65],alb_contact*out){unsigned char*blob=NULL;size_t n=0,nn;int trust,ok=0;if(!read_bounded(path,CONTACT_MAX,&blob,&n)||n<10+PUBID_LEN||memcmp(blob,CONTACT_MAGIC,8))goto done;trust=blob[8];nn=blob[9];if(trust<ALB_UNVERIFIED||trust>ALB_REVOKED||nn<1||nn>64||n!=10+nn+PUBID_LEN)goto done;memcpy(name,blob+10,nn);name[nn]=0;if(!valid_name(name)||alb_import_contact(blob+10+nn,PUBID_LEN,out))goto done;out->trust=trust;ok=1;
done:if(blob){OPENSSL_cleanse(blob,n);free(blob);}return ok;}

typedef int (*contact_visit)(const char*,const char*,alb_contact*,void*);
static int visit_contacts(const char*directory,contact_visit visit,void*user){int ok=1;
#ifdef _WIN32
 char pattern[PATH_CAP],path[PATH_CAP],*leaf;wchar_t*wpattern;WIN32_FIND_DATAW data;HANDLE h;if(!checked_join(pattern,directory,"*.contact"))return 0;wpattern=wide(pattern);if(!wpattern)return 0;h=FindFirstFileW(wpattern,&data);free(wpattern);if(h==INVALID_HANDLE_VALUE)return GetLastError()==ERROR_FILE_NOT_FOUND;do{leaf=narrow(data.cFileName);if(!leaf){ok=0;break;}if(!(data.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&checked_join(path,directory,leaf)){char name[65];alb_contact c;if(!load_contact_file(path,name,&c)||!visit(path,name,&c,user)){free(leaf);ok=0;break;}}free(leaf);}while(FindNextFileW(h,&data));if(GetLastError()!=ERROR_NO_MORE_FILES)ok=0;FindClose(h);
#else
 DIR*d=opendir(directory);struct dirent*entry;char path[PATH_CAP];if(!d)return errno==ENOENT;while((entry=readdir(d))!=NULL){size_t n=strlen(entry->d_name);if(n<=8||strcmp(entry->d_name+n-8,".contact"))continue;if(!checked_join(path,directory,entry->d_name)){ok=0;break;}{char name[65];alb_contact c;if(!load_contact_file(path,name,&c)||!visit(path,name,&c,user)){ok=0;break;}}}closedir(d);
#endif
 return ok;}

typedef struct{const char*selector;unsigned char wanted[32];int by_fpr,matches;alb_contact contact;char name[65];} resolver;
static int resolve_visit(const char*path,const char*name,alb_contact*c,void*user){resolver*r=(resolver*)user;unsigned char fpr[32];(void)path;if(alb_fingerprint(c->pubid,fpr))return 0;if((r->by_fpr&&!CRYPTO_memcmp(fpr,r->wanted,32))||(!r->by_fpr&&!strcmp(name,r->selector))){r->matches++;r->contact=*c;strcpy(r->name,name);}return 1;}
static int resolve_contact(const char*directory,const char*selector,alb_contact*out,char name[65]){resolver r;memset(&r,0,sizeof(r));r.selector=selector;r.by_fpr=parse_fingerprint(selector,r.wanted);if(!r.by_fpr&&!valid_name(selector))return 0;if(!visit_contacts(directory,resolve_visit,&r)||r.matches!=1)return 0;*out=r.contact;strcpy(name,r.name);return 1;}

typedef struct{const char*directory,*name;const unsigned char*new_fpr;int failed;} import_context;
static int import_visit(const char*path,const char*name,alb_contact*c,void*user){import_context*ctx=(import_context*)user;unsigned char fpr[32];(void)path;if(alb_fingerprint(c->pubid,fpr))return 0;if(!CRYPTO_memcmp(fpr,ctx->new_fpr,32)){if(strcmp(name,ctx->name))ctx->failed=1;return !ctx->failed;}if(!strcmp(name,ctx->name)&&c->trust!=ALB_REVOKED){c->trust=ALB_UNVERIFIED;if(!save_contact(ctx->directory,name,c))ctx->failed=1;}return !ctx->failed;}

static int import_contact_file(const char*directory,const char*name,const char*source,alb_contact*out){unsigned char*text=NULL,pubid[PUBID_LEN],fpr[32];size_t n=0;char path[PATH_CAP],existing_name[65];alb_contact existing;import_context ctx;int ok=0;if(!valid_name(name)||!read_bounded(source,PUBLIC_MAX,&text,&n)||!parse_public(text,n,pubid)||alb_fingerprint(pubid,fpr)||!contact_path(directory,pubid,path))goto done;if(file_exists(path)){if(!load_contact_file(path,existing_name,&existing)||strcmp(existing_name,name))goto done;*out=existing;ok=1;goto done;}ctx.directory=directory;ctx.name=name;ctx.new_fpr=fpr;ctx.failed=0;if(!visit_contacts(directory,import_visit,&ctx)||ctx.failed||alb_import_contact(pubid,PUBID_LEN,out)||!save_contact(directory,name,out))goto done;ok=1;
done:free(text);return ok;}

typedef struct{int count;} list_context;
static int list_visit(const char*path,const char*name,alb_contact*c,void*user){list_context*ctx=(list_context*)user;unsigned char fpr[32];char display[72];const char*trust=c->trust==ALB_VERIFIED?"verified":c->trust==ALB_REVOKED?"revoked":"unverified";(void)path;if(alb_fingerprint(c->pubid,fpr))return 0;fingerprint_text(fpr,display);printf("%-20s  %-10s  %s\n",name,trust,display);ctx->count++;return 1;}

static int read_secret_line(FILE*f,unsigned char*out,size_t capacity,size_t*length){size_t n=0;int ch;while((ch=fgetc(f))!=EOF&&ch!='\n'){if(ch=='\r')continue;if(n>=capacity)return 0;out[n++]=(unsigned char)ch;}if(ch==EOF&&ferror(f))return 0;*length=n;return 1;}
static int terminal_secret(const char*prompt,unsigned char*out,size_t capacity,size_t*length){int ok=0;
#ifdef _WIN32
 HANDLE input=GetStdHandle(STD_INPUT_HANDLE);DWORD mode;if(input==INVALID_HANDLE_VALUE||!GetConsoleMode(input,&mode))return 0;fprintf(stderr,"%s: ",prompt);fflush(stderr);if(!SetConsoleMode(input,mode&~ENABLE_ECHO_INPUT))return 0;ok=read_secret_line(stdin,out,capacity,length);SetConsoleMode(input,mode);fputc('\n',stderr);
#else
 struct termios oldmode,newmode;if(!isatty(STDIN_FILENO)||tcgetattr(STDIN_FILENO,&oldmode))return 0;newmode=oldmode;newmode.c_lflag&=(tcflag_t)~ECHO;fprintf(stderr,"%s: ",prompt);fflush(stderr);if(tcsetattr(STDIN_FILENO,TCSAFLUSH,&newmode))return 0;ok=read_secret_line(stdin,out,capacity,length);tcsetattr(STDIN_FILENO,TCSAFLUSH,&oldmode);fputc('\n',stderr);
#endif
 return ok;}

static int passphrase_callback(void*user,unsigned char*out,size_t capacity,size_t*length,int confirm){options*opts=(options*)user;const char*named=getenv("ALBPKG_PASSPHRASE_FILE");FILE*f=NULL;unsigned char again[1024];size_t second=0;int duplicate=-1,ok=0;if(capacity>1024)capacity=1024;if(opts->passphrase_fd>=0){duplicate=duplicate_fd(opts->passphrase_fd);if(duplicate<0)return 0;f=fd_to_file(duplicate,"rb");if(!f){close_fd(duplicate);return 0;}}else if(named)f=open_read(named);if(f){ok=read_secret_line(f,out,capacity,length);fclose(f);return ok;}if(!terminal_secret(confirm?"New identity passphrase":"Identity passphrase",out,capacity,length))return 0;if(confirm){if(!terminal_secret("Confirm identity passphrase",again,sizeof(again),&second)||second!=*length||CRYPTO_memcmp(out,again,second)){OPENSSL_cleanse(again,sizeof(again));OPENSSL_cleanse(out,capacity);*length=0;return 0;}OPENSSL_cleanse(again,sizeof(again));}return 1;}

static int parse_options(int argc,char**argv,options*out){static char default_home[PATH_CAP];const char*profile;int i;memset(out,0,sizeof(*out));out->passphrase_fd=-1;out->home=getenv("ALBPKG_HOME");if(!out->home||!*out->home){profile=getenv(
#ifdef _WIN32
 "USERPROFILE"
#else
 "HOME"
#endif
 );if(!profile||!*profile)profile=".";if(!checked_join(default_home,profile,".albpkg"))return 0;out->home=default_home;}for(i=1;i<argc;i++){const char*t=argv[i];if(!strcmp(t,"--passphrase")||!strncmp(t,"--passphrase=",13))return 0;if(!strcmp(t,"--home")||!strcmp(t,"--identity")||!strcmp(t,"--passphrase-fd")||!strcmp(t,"--to")){if(++i>=argc)return 0;if(!strcmp(t,"--home"))out->home=argv[i];else if(!strcmp(t,"--identity"))out->identity=argv[i];else if(!strcmp(t,"--to"))out->to=argv[i];else{char*end;long n=strtol(argv[i],&end,10);if(*end||n<0||n>INT_MAX)return 0;out->passphrase_fd=(int)n;}continue;}if(!strcmp(t,"--overwrite")){out->overwrite=1;continue;}if(!strcmp(t,"--help")||!strcmp(t,"-h")){out->command="--help";continue;}if(!strcmp(t,"--version")){out->command="--version";continue;}if(t[0]=='-')return 0;if(!out->command)out->command=t;else{if(out->positional_count>=4)return 0;out->positional[out->positional_count++]=t;}}return out->command!=NULL;}

static int identity_path(const options*opts,char out[PATH_CAP]){return opts->identity?(strlen(opts->identity)<PATH_CAP?(strcpy(out,opts->identity),1):0):checked_join(out,opts->home,"identity.key");}
static int prepare_home(const options*opts,char contacts[PATH_CAP]){if(!make_dir(opts->home)||!checked_join(contacts,opts->home,"contacts")||!make_dir(contacts))return 0;return 1;}
static int export_identity(const alb_identity*identity,const char*path,int overwrite){unsigned char pubid[PUBID_LEN],armored[PUBLIC_MAX];size_t n;if(alb_export_public_identity(identity,pubid,sizeof(pubid))||!armor_public(pubid,armored,sizeof(armored),&n))return 0;return write_atomic(path,armored,n,overwrite);}

int main(int argc,char**argv){options opts;char identity_file[PATH_CAP],contacts[PATH_CAP],name[65];alb_identity*identity=NULL;alb_contact contact;unsigned char pubid[PUBID_LEN],fpr[32];char display[72];int code=2;if(!parse_options(argc,argv,&opts)){fputs(USAGE,stderr);return fail("invalid arguments");}if(!strcmp(opts.command,"--help")){fputs(USAGE,stdout);return 0;}if(!strcmp(opts.command,"--version")){puts("albpkg 1.0.0");return 0;}if(!identity_path(&opts,identity_file)||!prepare_home(&opts,contacts))return fail("cannot create or resolve the configuration directory");

 if(!strcmp(opts.command,"generate-identity")){if(opts.positional_count)return fail("generate-identity takes no arguments");if(alb_generate_identity(&identity)||alb_save_identity(identity,identity_file,passphrase_callback,&opts,opts.overwrite))goto crypto_error;if(alb_export_public_identity(identity,pubid,sizeof(pubid))||alb_fingerprint(pubid,fpr))goto crypto_error;fingerprint_text(fpr,display);printf("identity written to %s\nsuite:       ALBPKG-1\nfingerprint: %s\n",identity_file,display);code=0;goto done;}
 if(!strcmp(opts.command,"export-public-identity")||!strcmp(opts.command,"show-identity")){if((!strcmp(opts.command,"show-identity")&&opts.positional_count)||(!strcmp(opts.command,"export-public-identity")&&opts.positional_count!=1))return fail("wrong number of arguments");if(alb_load_identity(identity_file,passphrase_callback,&opts,&identity))goto crypto_error;if(alb_export_public_identity(identity,pubid,sizeof(pubid))||alb_fingerprint(pubid,fpr))goto crypto_error;fingerprint_text(fpr,display);if(!strcmp(opts.command,"show-identity"))printf("suite:       ALBPKG-1\nfingerprint: %s\n",display);else{if(!export_identity(identity,opts.positional[0],opts.overwrite))goto io_error;printf("public identity written to %s\nfingerprint: %s\n",opts.positional[0],display);}code=0;goto done;}
 if(!strcmp(opts.command,"migrate-legacy-identity")){if(opts.positional_count!=1||!strcmp(opts.positional[0],identity_file))return fail("migration requires distinct legacy source and destination paths");if(alb_migrate_legacy_identity(opts.positional[0],identity_file,passphrase_callback,&opts,opts.overwrite,&identity))goto crypto_error;if(alb_export_public_identity(identity,pubid,sizeof(pubid))||alb_fingerprint(pubid,fpr))goto crypto_error;fingerprint_text(fpr,display);printf("migrated identity written to %s\noriginal retained at %s\nfingerprint: %s\n",identity_file,opts.positional[0],display);code=0;goto done;}
 if(!strcmp(opts.command,"import-contact")){if(opts.positional_count!=2)return fail("import-contact requires a name and public identity file");if(!import_contact_file(contacts,opts.positional[0],opts.positional[1],&contact))goto format_error;if(alb_fingerprint(contact.pubid,fpr))goto crypto_error;fingerprint_text(fpr,display);printf("imported '%s' as %s\nfingerprint: %s\n",opts.positional[0],contact.trust==ALB_VERIFIED?"verified":contact.trust==ALB_REVOKED?"revoked":"unverified",display);code=0;goto done;}
 if(!strcmp(opts.command,"verify-contact")){unsigned char supplied[32];if(opts.positional_count!=2||!parse_fingerprint(opts.positional[1],supplied))return fail("verify-contact requires a contact and full 64-hex fingerprint");if(!resolve_contact(contacts,opts.positional[0],&contact,name)||alb_verify_contact(&contact,supplied)||!save_contact(contacts,name,&contact))goto trust_error;fingerprint_text(supplied,display);printf("'%s' is now verified\nfingerprint: %s\n",name,display);code=0;goto done;}
 if(!strcmp(opts.command,"revoke-contact")){if(opts.positional_count!=1)return fail("revoke-contact requires a contact");if(!resolve_contact(contacts,opts.positional[0],&contact,name))goto trust_error;alb_revoke_contact(&contact);if(!save_contact(contacts,name,&contact))goto io_error;printf("'%s' is revoked and will be rejected from now on\n",name);code=0;goto done;}
 if(!strcmp(opts.command,"list-contacts")){list_context ctx={0};if(opts.positional_count)return fail("list-contacts takes no arguments");if(!visit_contacts(contacts,list_visit,&ctx))goto format_error;if(!ctx.count)puts("no contacts");return 0;}
 if(!strcmp(opts.command,"seal")){if(opts.positional_count!=2||!opts.to)return fail("seal requires input, output, and --to");if(!resolve_contact(contacts,opts.to,&contact,name)||contact.trust!=ALB_VERIFIED)goto trust_error;if(alb_load_identity(identity_file,passphrase_callback,&opts,&identity)||alb_seal_file_mode(identity,&contact,opts.positional[0],opts.positional[1],opts.overwrite,NULL,NULL))goto crypto_error;printf("sealed package: %s\n",opts.positional[1]);code=0;goto done;}
 if(!strcmp(opts.command,"open")){FILE*f;unsigned char header[PACKAGE_HEADER];if(opts.positional_count!=2)return fail("open requires input and output");f=open_read(opts.positional[0]);if(!f||fread(header,1,sizeof(header),f)!=sizeof(header)){if(f)fclose(f);goto format_error;}fclose(f);hex_plain(header+24,32,display);if(!resolve_contact(contacts,display,&contact,name)||contact.trust!=ALB_VERIFIED)goto trust_error;if(alb_load_identity(identity_file,passphrase_callback,&opts,&identity)||alb_open_file_mode(identity,&contact,opts.positional[0],opts.positional[1],opts.overwrite,NULL,NULL))goto crypto_error;printf("opened package to %s\n",opts.positional[1]);code=0;goto done;}
 fputs(USAGE,stderr);return fail("unknown command");
format_error:code=fail("invalid or noncanonical input");goto done;
trust_error:code=fail("contact is missing, ambiguous, unverified, revoked, or has the wrong fingerprint");goto done;
io_error:code=fail("file operation failed; the destination may already exist");goto done;
crypto_error:fprintf(stderr,"albpkg: %s\n",alb_error_string(alb_last_error()));code=2;
done:alb_identity_free(identity);return code;
}
