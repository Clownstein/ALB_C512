/* Independent C implementation of ALBPKG/1 package framing and state machine.
 * All primitive operations use OpenSSL EVP. See FORMAT.md and RELEASE_STATUS.
 */
#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L
#include "albpkg.h"
#include "openssl_abi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <io.h>
#include <fcntl.h>
#define seek64 _fseeki64
#define tell64 _ftelli64
#define syncfd _commit
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#define seek64 fseeko
#define tell64 ftello
#define syncfd fsync
#endif
#define CHUNK 1048576u
#define HEADER 1194u
#define MAXFILE UINT64_C(1099511627776)
#define MAXCHUNKS UINT64_C(1048576)
#define MAXPACKAGE (MAXFILE+HEADER+MAXCHUNKS*21+32+3309+12)
#ifdef _MSC_VER
#define ALB_TLS __declspec(thread)
#else
#define ALB_TLS __thread
#endif
static ALB_TLS alb_error_code alb_error_state=ALB_ERR_NONE;
static void set_error(alb_error_code code){if(alb_error_state==ALB_ERR_NONE)alb_error_state=code;}
static void clear_error(void){alb_error_state=ALB_ERR_NONE;}
alb_error_code alb_last_error(void){return alb_error_state;}
const char *alb_error_string(alb_error_code code){switch(code){case ALB_ERR_NONE:return "no error";case ALB_ERR_ARGUMENT:return "invalid argument";case ALB_ERR_PROVIDER:return "required cryptographic provider operation failed";case ALB_ERR_MEMORY:return "memory allocation failed";case ALB_ERR_IO:return "file operation failed";case ALB_ERR_FORMAT:return "input is malformed or noncanonical";case ALB_ERR_AUTHENTICATION:return "authentication failed";case ALB_ERR_TRUST:return "contact is not verified or is revoked";case ALB_ERR_PERMISSION:return "private file permissions are not owner-only";case ALB_ERR_CANCELLED:return "operation cancelled";case ALB_ERR_LIMIT:return "size or counter limit exceeded";case ALB_ERR_EXISTS:return "destination already exists";default:return "internal operation failed";}}
#define CHECK(x) do { if(!(x))goto done; } while(0)
#define CHECK_AS(x,e) do { if(!(x)){set_error((e));goto done;} } while(0)
struct alb_identity { EVP_PKEY *kem; EVP_PKEY *sig; unsigned char pubid[3150]; };
static void put(unsigned char*p,uint64_t n,unsigned size){while(size){p[--size]=(unsigned char)n;n>>=8;}}
static uint64_t get(const unsigned char*p,unsigned size){uint64_t n=0;while(size--)n=(n<<8)|*p++;return n;}
static int digest(const EVP_MD*md,const void*p,size_t n,unsigned char*out){EVP_MD_CTX*c=EVP_MD_CTX_new();int ok=c&&EVP_DigestInit_ex(c,md,NULL)>0&&EVP_DigestUpdate(c,p,n)>0&&EVP_DigestFinal_ex(c,out,NULL)>0;EVP_MD_CTX_free(c);return ok;}
int alb_fingerprint(const unsigned char p[3150],unsigned char out[32]){clear_error();if(!p||!out){set_error(ALB_ERR_ARGUMENT);return -1;}if(!digest(EVP_sha256(),p,3150,out)){set_error(ALB_ERR_PROVIDER);return -1;}return 0;}
static EVP_PKEY *fromdata(const char*alg,const char*field,const unsigned char*bytes,size_t n,int selection){
 EVP_PKEY_CTX*c=EVP_PKEY_CTX_new_from_name(NULL,alg,NULL);EVP_PKEY*k=NULL;
 OSSL_PARAM p[2]={OSSL_PARAM_construct_octet_string(field,(void*)bytes,n),OSSL_PARAM_construct_end()};
 if(!c||EVP_PKEY_fromdata_init(c)<=0||EVP_PKEY_fromdata(c,&k,selection,p)<=0){EVP_PKEY_free(k);k=NULL;}
 EVP_PKEY_CTX_free(c);return k;
}
static EVP_PKEY *generate(const char*alg){EVP_PKEY_CTX*c=EVP_PKEY_CTX_new_from_name(NULL,alg,NULL);EVP_PKEY*k=NULL;if(!c||EVP_PKEY_keygen_init(c)<=0||EVP_PKEY_generate(c,&k)<=0){EVP_PKEY_free(k);k=NULL;}EVP_PKEY_CTX_free(c);return k;}
static int fill_public(alb_identity*i){size_t n=0;memcpy(i->pubid,"ALBPKID1",8);put(i->pubid+8,1,2);put(i->pubid+10,1184,2);put(i->pubid+1196,1952,2);
 return EVP_PKEY_get_octet_string_param(i->kem,"pub",i->pubid+12,1184,&n)>0&&n==1184&&EVP_PKEY_get_octet_string_param(i->sig,"pub",i->pubid+1198,1952,&n)>0&&n==1952;
}
void alb_identity_free(alb_identity*i){if(i){EVP_PKEY_free(i->kem);EVP_PKEY_free(i->sig);OPENSSL_cleanse(i,sizeof(*i));free(i);}}
int alb_generate_identity(alb_identity**out){alb_identity*i;clear_error();if(!out){set_error(ALB_ERR_ARGUMENT);return -1;}*out=NULL;if(OpenSSL_version_num()<0x30500000UL){set_error(ALB_ERR_PROVIDER);return -1;}i=calloc(1,sizeof(*i));if(!i){set_error(ALB_ERR_MEMORY);return -1;}i->kem=generate("ML-KEM-768");i->sig=generate("ML-DSA-65");if(!i->kem||!i->sig||!fill_public(i)){set_error(ALB_ERR_PROVIDER);alb_identity_free(i);return -1;}*out=i;return 0;}
int alb_identity_from_seeds(const unsigned char*k,const unsigned char*s,alb_identity**out){alb_identity*i;clear_error();if(!k||!s||!out){set_error(ALB_ERR_ARGUMENT);return -1;}*out=NULL;i=calloc(1,sizeof(*i));if(!i){set_error(ALB_ERR_MEMORY);return -1;}i->kem=fromdata("ML-KEM-768","seed",k,64,EVP_PKEY_KEYPAIR);i->sig=fromdata("ML-DSA-65","seed",s,32,EVP_PKEY_KEYPAIR);if(!i->kem||!i->sig||!fill_public(i)){set_error(ALB_ERR_PROVIDER);alb_identity_free(i);return -1;}*out=i;return 0;}
int alb_export_public_identity(const alb_identity*i,unsigned char*out,size_t cap){clear_error();if(!i||!out||cap<3150){set_error(ALB_ERR_ARGUMENT);return -1;}memcpy(out,i->pubid,3150);return 0;}
int alb_import_contact(const unsigned char*p,size_t n,alb_contact*out){EVP_PKEY*k=NULL,*s=NULL;int ok=0;clear_error();if(!p||!out){set_error(ALB_ERR_ARGUMENT);return -1;}if(n!=3150){set_error(ALB_ERR_FORMAT);return -1;}memset(out,0,sizeof(*out));if(memcmp(p,"ALBPKID1",8)||get(p+8,2)!=1||get(p+10,2)!=1184||get(p+1196,2)!=1952){set_error(ALB_ERR_FORMAT);return -1;}k=fromdata("ML-KEM-768","pub",p+12,1184,EVP_PKEY_PUBLIC_KEY);s=fromdata("ML-DSA-65","pub",p+1198,1952,EVP_PKEY_PUBLIC_KEY);if(k&&s){memcpy(out->pubid,p,n);ok=1;}else set_error(ALB_ERR_PROVIDER);EVP_PKEY_free(k);EVP_PKEY_free(s);return ok?0:-1;}
int alb_verify_contact(alb_contact*c,const unsigned char*f){unsigned char expected[32];clear_error();if(!c||!f){set_error(ALB_ERR_ARGUMENT);return -1;}if(c->trust==ALB_REVOKED){set_error(ALB_ERR_TRUST);return -1;}if(alb_fingerprint(c->pubid,expected)){set_error(ALB_ERR_PROVIDER);return -1;}if(CRYPTO_memcmp(f,expected,32)){set_error(ALB_ERR_AUTHENTICATION);return -1;}c->trust=ALB_VERIFIED;return 0;}
void alb_revoke_contact(alb_contact*c){if(c)c->trust=ALB_REVOKED;}
static int hkdf(const unsigned char*secret,const unsigned char*hd,const char*domain,uint64_t index,int indexed,unsigned char*out){
 unsigned char info[64];size_t n=strlen(domain);int ok=0;EVP_KDF*k=NULL;EVP_KDF_CTX*c=NULL;OSSL_PARAM p[5];
 if(n+8>sizeof(info))return 0;memcpy(info,domain,n);if(indexed){put(info+n,index,8);n+=8;}
 k=EVP_KDF_fetch(NULL,"HKDF",NULL);if(!k)goto done;c=EVP_KDF_CTX_new(k);if(!c)goto done;
 p[0]=OSSL_PARAM_construct_utf8_string("digest","SHA256",0);p[1]=OSSL_PARAM_construct_octet_string("key",(void*)secret,32);
 p[2]=OSSL_PARAM_construct_octet_string("salt",(void*)hd,32);p[3]=OSSL_PARAM_construct_octet_string("info",info,n);p[4]=OSSL_PARAM_construct_end();
 ok=EVP_KDF_derive(c,out,32,p)>0;
done:EVP_KDF_CTX_free(c);EVP_KDF_free(k);return ok;
}
static int aead(int enc,const unsigned char*key,const unsigned char*aad,size_t an,const unsigned char*in,size_t n,unsigned char*out){
 EVP_CIPHER_CTX*c=NULL;int written=0,last=0,ok=0;unsigned char nonce[12]={0};
 if(n>CHUNK+16||an>4096||an>INT_MAX||(!enc&&n<16))return 0;
 c=EVP_CIPHER_CTX_new();CHECK(c);CHECK(EVP_CipherInit_ex(c,EVP_aes_256_gcm(),NULL,key,nonce,enc)>0);
 CHECK(EVP_CipherUpdate(c,NULL,&written,aad,(int)an)>0);
 if(!enc){n-=16;CHECK(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,16,(void*)(in+n))>0);}
 CHECK(EVP_CipherUpdate(c,out,&written,in,(int)n)>0);CHECK(written==(int)n);CHECK(EVP_CipherFinal_ex(c,out+written,&last)>0);CHECK(last==0);
 if(enc)CHECK(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,out+n)>0);ok=1;
done:if(!ok&&out)OPENSSL_cleanse(out,n);EVP_CIPHER_CTX_free(c);return ok;
}
static size_t chunk_aad(unsigned char*out,const unsigned char*hd,uint64_t index,uint32_t n,int final){memcpy(out,"ALBPKG1-CHUNK",13);memcpy(out+13,hd,32);put(out+45,index,8);put(out+53,n,4);out[57]=(unsigned char)final;return 58;}
static size_t done_aad(unsigned char*out,const unsigned char*hd,uint64_t total,uint64_t count){memcpy(out,"ALBPKG1-COMPLETE",16);memcpy(out+16,hd,32);put(out+48,total,8);put(out+56,count,8);return 64;}
static int sign_digest(EVP_PKEY*k,const unsigned char*hash,unsigned char*sig,int verify){unsigned char msg[77];EVP_MD_CTX*c=EVP_MD_CTX_new();size_t n=3309;int ok=0;memcpy(msg,"ALBPKG1-SIGV1",13);memcpy(msg+13,hash,64);if(c){if(verify)ok=EVP_DigestVerifyInit_ex(c,NULL,NULL,NULL,NULL,k,NULL)>0&&EVP_DigestVerify(c,sig,3309,msg,sizeof(msg))>0;else ok=EVP_DigestSignInit_ex(c,NULL,NULL,NULL,NULL,k,NULL)>0&&EVP_DigestSign(c,sig,&n,msg,sizeof(msg))>0&&n==3309;}EVP_MD_CTX_free(c);return ok;}
#ifdef _WIN32
static wchar_t *wide(const char*p){int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,p,-1,NULL,0);wchar_t*w;if(!n)return NULL;w=calloc((size_t)n,sizeof(*w));if(w&&!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,p,-1,w,n)){free(w);w=NULL;}return w;}
static FILE *readfile(const char*p){wchar_t*w=wide(p);FILE*f=w?_wfopen(w,L"rb"):NULL;free(w);return f;}
static int handle_owner_only(HANDLE handle){
 PSECURITY_DESCRIPTOR descriptor=NULL;PSID owner=NULL,owner_rights=NULL;PACL dacl=NULL;TOKEN_USER*token_user=NULL;HANDLE token=NULL;DWORD result,i,token_size=0;int ok=0;
 result=GetSecurityInfo(handle,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,NULL,&dacl,NULL,&descriptor);
 if(result!=ERROR_SUCCESS||!owner||!IsValidSid(owner)||!dacl)goto done;
 if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))goto done;
 (void)GetTokenInformation(token,TokenUser,NULL,0,&token_size);
 if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER||token_size<sizeof(TOKEN_USER))goto done;
 token_user=(TOKEN_USER*)malloc(token_size);if(!token_user)goto done;
 if(!GetTokenInformation(token,TokenUser,token_user,token_size,&token_size)||!IsValidSid(token_user->User.Sid)||!EqualSid(owner,token_user->User.Sid))goto done;
 if(!ConvertStringSidToSidW(L"S-1-3-4",&owner_rights))goto done;
 ok=1;
 for(i=0;i<dacl->AceCount;i++){void*raw=NULL;ACE_HEADER*header;PSID sid;if(!GetAce(dacl,i,&raw)){ok=0;break;}header=(ACE_HEADER*)raw;if(header->AceType==ACCESS_DENIED_ACE_TYPE)continue;if(header->AceType!=ACCESS_ALLOWED_ACE_TYPE){ok=0;break;}sid=(PSID)&((ACCESS_ALLOWED_ACE*)raw)->SidStart;if(!IsValidSid(sid)||(!EqualSid(sid,owner)&&!EqualSid(sid,owner_rights))){ok=0;break;}}
done:if(token_user)free(token_user);if(token)CloseHandle(token);if(owner_rights)LocalFree(owner_rights);if(descriptor)LocalFree(descriptor);return ok;
}
static FILE *private_readfile(const char*p){wchar_t*w=wide(p);FILE*f=w?_wfopen(w,L"rb"):NULL;intptr_t handle;if(!f){set_error(ALB_ERR_IO);free(w);return NULL;}handle=_get_osfhandle(_fileno(f));if(handle==-1||!handle_owner_only((HANDLE)handle)){set_error(ALB_ERR_PERMISSION);fclose(f);f=NULL;}free(w);return f;}
static void unlinkfile(const char*p){wchar_t*w=wide(p);if(w){DeleteFileW(w);free(w);}}
static FILE *privatefile(const char*p){wchar_t*w=wide(p);PSECURITY_DESCRIPTOR sd=NULL;SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,FALSE};HANDLE h=INVALID_HANDLE_VALUE;int fd;FILE*f=NULL;
 if(w&&ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;OW)",SDDL_REVISION_1,&sd,NULL)){sa.lpSecurityDescriptor=sd;h=CreateFileW(w,GENERIC_READ|GENERIC_WRITE,0,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);}if(sd)LocalFree(sd);free(w);if(h==INVALID_HANDLE_VALUE)return NULL;
 fd=_open_osfhandle((intptr_t)h,_O_BINARY|_O_RDWR);if(fd<0){CloseHandle(h);return NULL;}f=_fdopen(fd,"w+b");if(!f)_close(fd);return f;
}
static int publish_mode(const char*a,const char*b,int overwrite){wchar_t*wa=wide(a),*wb=wide(b);DWORD flags=MOVEFILE_WRITE_THROUGH|(overwrite?MOVEFILE_REPLACE_EXISTING:0);int ok=wa&&wb&&MoveFileExW(wa,wb,flags);free(wa);free(wb);return ok;}
#else
static FILE *readfile(const char*p){return fopen(p,"rb");}
static FILE *private_readfile(const char*p){int fd;struct stat st;FILE*f;
#ifdef O_NOFOLLOW
 fd=open(p,O_RDONLY|O_NOFOLLOW);
#else
 fd=open(p,O_RDONLY);
#endif
 if(fd<0){set_error(ALB_ERR_IO);return NULL;}if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&077)){set_error(ALB_ERR_PERMISSION);close(fd);return NULL;}f=fdopen(fd,"rb");if(!f){set_error(ALB_ERR_IO);close(fd);}return f;}
static void unlinkfile(const char*p){unlink(p);}
static FILE *privatefile(const char*p){int fd=open(p,O_RDWR|O_CREAT|O_EXCL,0600);FILE*f;if(fd<0)return NULL;f=fdopen(fd,"w+b");if(!f)close(fd);return f;}
static int publish_mode(const char*a,const char*b,int overwrite){if(overwrite)return rename(a,b)==0;if(link(a,b))return 0;unlink(a);return 1;}
#endif
static FILE *temporary(const char*destination,char**name){unsigned char rnd[16];size_t n=strlen(destination);FILE*f;unsigned i;*name=NULL;if(n>30000||RAND_bytes(rnd,16)<=0)return NULL;*name=malloc(n+40);if(!*name)return NULL;memcpy(*name,destination,n);memcpy(*name+n,".alb-",5);for(i=0;i<16;i++)sprintf(*name+n+5+i*2,"%02x",rnd[i]);strcpy(*name+n+37,".t");f=privatefile(*name);if(!f){free(*name);*name=NULL;}return f;}
static int writehash(FILE*f,EVP_MD_CTX*h,const void*p,size_t n){return fwrite(p,1,n,f)==n&&EVP_DigestUpdate(h,p,n)>0;}
static int cancelled(alb_cancel cb,void*u){return cb&&cb(u);}
int alb_seal_file_mode(const alb_identity*sender,const alb_contact*recipient,const char*src,const char*dst,int overwrite,alb_cancel cb,void*u){
 FILE*in=NULL,*out=NULL;char*name=NULL;EVP_PKEY*pub=NULL;EVP_PKEY_CTX*kem=NULL;EVP_MD_CTX*h=NULL;unsigned char *plain=NULL,*next=NULL,*cipher=NULL;
 unsigned char header[HEADER]={0},ss[32]={0},master[32]={0},key[32]={0},hd[32],aad[64],frame[5],donept[16],donect[32],hash[64],sig[3309],trailer[12];size_t cn=1088,sn=32,n,look;uint64_t total=0,index=0;int ok=0,final;
 clear_error();if(!sender||!recipient||!src||!dst||(overwrite!=0&&overwrite!=1)){set_error(ALB_ERR_ARGUMENT);goto done;}if(recipient->trust!=ALB_VERIFIED){set_error(ALB_ERR_TRUST);goto done;}
 in=readfile(src);CHECK_AS(in,ALB_ERR_IO);out=temporary(dst,&name);CHECK_AS(out,ALB_ERR_IO);
 plain=malloc(CHUNK);next=malloc(CHUNK);cipher=malloc(CHUNK+16);CHECK_AS(plain&&next&&cipher,ALB_ERR_MEMORY);
 pub=fromdata("ML-KEM-768","pub",recipient->pubid+12,1184,EVP_PKEY_PUBLIC_KEY);CHECK(pub);kem=EVP_PKEY_CTX_new_from_pkey(NULL,pub,NULL);CHECK(kem);
 memcpy(header,"ALBPKG1\0",8);put(header+8,1,2);put(header+10,1,2);put(header+12,HEADER,4);put(header+20,CHUNK,4);
 CHECK(!alb_fingerprint(sender->pubid,header+24)&&!alb_fingerprint(recipient->pubid,header+56));CHECK(RAND_bytes(header+88,16)>0);put(header+104,1088,2);
 CHECK(EVP_PKEY_encapsulate_init(kem,NULL)>0&&EVP_PKEY_encapsulate(kem,header+106,&cn,ss,&sn)>0&&cn==1088&&sn==32);
 CHECK(digest(EVP_sha256(),header,HEADER,hd)&&hkdf(ss,hd,"ALBPKG1 master v1",0,0,master));
 h=EVP_MD_CTX_new();CHECK(h&&EVP_DigestInit_ex(h,EVP_sha512(),NULL)>0);CHECK(writehash(out,h,header,HEADER));
 n=fread(plain,1,CHUNK,in);CHECK(!ferror(in));
 for(;;){CHECK_AS(!cancelled(cb,u),ALB_ERR_CANCELLED);look=fread(next,1,CHUNK,in);CHECK_AS(!ferror(in),ALB_ERR_IO);final=look==0;
  CHECK_AS(index<MAXCHUNKS&&n<=MAXFILE-total,ALB_ERR_LIMIT);CHECK_AS(final||n==CHUNK,ALB_ERR_IO);CHECK_AS(hkdf(master,hd,"ALBPKG1 chunk v1",index,1,key),ALB_ERR_PROVIDER);
  CHECK(aead(1,key,aad,chunk_aad(aad,hd,index,(uint32_t)n,final),plain,n,cipher));frame[0]=(unsigned char)final;put(frame+1,n,4);CHECK(writehash(out,h,frame,5)&&writehash(out,h,cipher,n+16));
  total+=n;index++;if(final)break;{unsigned char*swap=plain;plain=next;next=swap;}n=look;
 }
 put(donept,total,8);put(donept+8,index,8);CHECK(hkdf(master,hd,"ALBPKG1 complete v1",0,0,key));CHECK(aead(1,key,aad,done_aad(aad,hd,total,index),donept,16,donect));CHECK(writehash(out,h,donect,32));
 CHECK_AS(EVP_DigestFinal_ex(h,hash,NULL)>0&&sign_digest(sender->sig,hash,sig,0),ALB_ERR_PROVIDER);put(trailer,3309,4);memcpy(trailer+4,"ALBPKGSG",8);CHECK_AS(fwrite(sig,1,3309,out)==3309&&fwrite(trailer,1,12,out)==12,ALB_ERR_IO);CHECK_AS(!fflush(out)&&!syncfd(fileno(out)),ALB_ERR_IO);CHECK_AS(!cancelled(cb,u),ALB_ERR_CANCELLED);{int closed=fclose(out);out=NULL;CHECK_AS(!closed,ALB_ERR_IO);}CHECK_AS(publish_mode(name,dst,overwrite),overwrite?ALB_ERR_IO:ALB_ERR_EXISTS);ok=1;
done:if(in)fclose(in);if(out)fclose(out);if(name){if(!ok)unlinkfile(name);free(name);}EVP_PKEY_free(pub);EVP_PKEY_CTX_free(kem);EVP_MD_CTX_free(h);
 if(plain){OPENSSL_cleanse(plain,CHUNK);free(plain);}if(next){OPENSSL_cleanse(next,CHUNK);free(next);}free(cipher);OPENSSL_cleanse(ss,32);OPENSSL_cleanse(master,32);OPENSSL_cleanse(key,32);if(!ok&&alb_error_state==ALB_ERR_NONE)set_error(ALB_ERR_INTERNAL);return ok?0:-1;
}
int alb_seal_file(const alb_identity*sender,const alb_contact*recipient,const char*src,const char*dst,alb_cancel cb,void*u){return alb_seal_file_mode(sender,recipient,src,dst,0,cb,u);}
int alb_open_file_mode(const alb_identity*recipient,const alb_contact*sender,const char*src,const char*dst,int overwrite,alb_cancel cb,void*u){
 FILE*in=NULL,*spool=NULL,*out=NULL;char*spoolname=NULL,*outname=NULL;EVP_PKEY*pub=NULL;EVP_PKEY_CTX*kem=NULL;EVP_MD_CTX*h=NULL;unsigned char *buf=NULL,*plain=NULL;
 unsigned char header[HEADER],hd[32],fpr[32],ss[32]={0},master[32]={0},key[32]={0},hash[64],sig[3309],trailer[12],frame[5],aad[64],donept[32],expected[16];
 uint64_t size=0,body=0,left=0,total=0,count=0,bodyread=HEADER;size_t n,sn=32;uint32_t len;int ok=0,final=0;
 clear_error();if(!recipient||!sender||!src||!dst||(overwrite!=0&&overwrite!=1)){set_error(ALB_ERR_ARGUMENT);goto done;}if(sender->trust!=ALB_VERIFIED){set_error(ALB_ERR_TRUST);goto done;}buf=malloc(CHUNK+16);plain=malloc(CHUNK+16);CHECK_AS(buf&&plain,ALB_ERR_MEMORY);in=readfile(src);CHECK_AS(in,ALB_ERR_IO);spool=temporary(dst,&spoolname);CHECK_AS(spool,ALB_ERR_IO);
 while((n=fread(buf,1,CHUNK,in))>0){CHECK_AS(!cancelled(cb,u),ALB_ERR_CANCELLED);CHECK_AS(n<=MAXPACKAGE-size,ALB_ERR_LIMIT);size+=n;CHECK_AS(fwrite(buf,1,n,spool)==n,ALB_ERR_IO);}CHECK_AS(!ferror(in),ALB_ERR_IO);CHECK_AS(!fflush(spool),ALB_ERR_IO);CHECK_AS(size>=HEADER+21+32+3309+12,ALB_ERR_FORMAT);CHECK_AS(!seek64(spool,0,SEEK_SET),ALB_ERR_IO);CHECK_AS(fread(header,1,HEADER,spool)==HEADER,ALB_ERR_IO);
 CHECK_AS(!memcmp(header,"ALBPKG1\0",8)&&get(header+8,2)==1&&get(header+10,2)==1&&get(header+12,4)==HEADER&&get(header+16,4)==0&&get(header+20,4)==CHUNK&&get(header+104,2)==1088,ALB_ERR_FORMAT);
 CHECK(!alb_fingerprint(sender->pubid,fpr)&&!CRYPTO_memcmp(fpr,header+24,32));CHECK(!alb_fingerprint(recipient->pubid,fpr)&&!CRYPTO_memcmp(fpr,header+56,32));CHECK(digest(EVP_sha256(),header,HEADER,hd));
 body=size-3309-12;CHECK(!seek64(spool,(int64_t)body,SEEK_SET));CHECK(fread(sig,1,3309,spool)==3309&&fread(trailer,1,12,spool)==12);CHECK(get(trailer,4)==3309&&!memcmp(trailer+4,"ALBPKGSG",8));
 CHECK(!seek64(spool,0,SEEK_SET));h=EVP_MD_CTX_new();CHECK(h&&EVP_DigestInit_ex(h,EVP_sha512(),NULL)>0);left=body;
 while(left){CHECK(!cancelled(cb,u));n=left>CHUNK?CHUNK:(size_t)left;CHECK(fread(buf,1,n,spool)==n&&EVP_DigestUpdate(h,buf,n)>0);left-=n;}
 CHECK_AS(EVP_DigestFinal_ex(h,hash,NULL)>0,ALB_ERR_PROVIDER);pub=fromdata("ML-DSA-65","pub",sender->pubid+1198,1952,EVP_PKEY_PUBLIC_KEY);CHECK_AS(pub,ALB_ERR_PROVIDER);CHECK_AS(sign_digest(pub,hash,sig,1),ALB_ERR_AUTHENTICATION);
 kem=EVP_PKEY_CTX_new_from_pkey(NULL,recipient->kem,NULL);CHECK(kem&&EVP_PKEY_decapsulate_init(kem,NULL)>0&&EVP_PKEY_decapsulate(kem,ss,&sn,header+106,1088)>0&&sn==32);CHECK(hkdf(ss,hd,"ALBPKG1 master v1",0,0,master));
 CHECK(!seek64(spool,HEADER,SEEK_SET));out=temporary(dst,&outname);CHECK(out);
 while(!final){CHECK(!cancelled(cb,u));CHECK(count<MAXCHUNKS&&bodyread+5<=body);CHECK(fread(frame,1,5,spool)==5);bodyread+=5;final=frame[0];len=(uint32_t)get(frame+1,4);CHECK(final<=1&&len<=CHUNK&&(final||len==CHUNK));CHECK(len||(!count&&final));CHECK((uint64_t)len<=MAXFILE-total&&bodyread+len+16<=body);CHECK(fread(buf,1,len+16,spool)==len+16);bodyread+=len+16;
  CHECK(hkdf(master,hd,"ALBPKG1 chunk v1",count,1,key));CHECK(aead(0,key,aad,chunk_aad(aad,hd,count,len,final),buf,len+16,plain));CHECK(fwrite(plain,1,len,out)==len);OPENSSL_cleanse(plain,len);total+=len;count++;
 }
 CHECK_AS(bodyread+32==body&&fread(buf,1,32,spool)==32,ALB_ERR_FORMAT);CHECK_AS(hkdf(master,hd,"ALBPKG1 complete v1",0,0,key),ALB_ERR_PROVIDER);CHECK_AS(aead(0,key,aad,done_aad(aad,hd,total,count),buf,32,donept),ALB_ERR_AUTHENTICATION);put(expected,total,8);put(expected+8,count,8);CHECK_AS(!CRYPTO_memcmp(expected,donept,16),ALB_ERR_AUTHENTICATION);CHECK_AS(!fflush(out)&&!syncfd(fileno(out)),ALB_ERR_IO);CHECK_AS(!cancelled(cb,u),ALB_ERR_CANCELLED);{int closed=fclose(out);out=NULL;CHECK_AS(!closed,ALB_ERR_IO);}CHECK_AS(publish_mode(outname,dst,overwrite),overwrite?ALB_ERR_IO:ALB_ERR_EXISTS);ok=1;
done:if(in)fclose(in);if(spool)fclose(spool);if(out)fclose(out);if(spoolname){unlinkfile(spoolname);free(spoolname);}if(outname){if(!ok)unlinkfile(outname);free(outname);}EVP_PKEY_free(pub);EVP_PKEY_CTX_free(kem);EVP_MD_CTX_free(h);free(buf);if(plain){OPENSSL_cleanse(plain,CHUNK+16);free(plain);}OPENSSL_cleanse(ss,32);OPENSSL_cleanse(master,32);OPENSSL_cleanse(key,32);if(!ok&&alb_error_state==ALB_ERR_NONE)set_error(ALB_ERR_INTERNAL);return ok?0:-1;
}
int alb_open_file(const alb_identity*recipient,const alb_contact*sender,const char*src,const char*dst,alb_cancel cb,void*u){return alb_open_file_mode(recipient,sender,src,dst,0,cb,u);}

/* ---- Encrypted PKCS#8 identity persistence ---------------------------- */
#define IDENTITY_MAX 65536u
#define DER_MAX 4096u
static const unsigned char OID_PBES2[]={0x2a,0x86,0x48,0x86,0xf7,0x0d,1,5,13};
static const unsigned char OID_PBKDF2[]={0x2a,0x86,0x48,0x86,0xf7,0x0d,1,5,12};
static const unsigned char OID_HMAC256[]={0x2a,0x86,0x48,0x86,0xf7,0x0d,2,9};
static const unsigned char OID_AES256CBC[]={0x60,0x86,0x48,1,0x65,3,4,1,0x2a};
static const unsigned char OID_MLKEM768[]={0x60,0x86,0x48,1,0x65,3,4,4,2};
static const unsigned char OID_MLDSA65[]={0x60,0x86,0x48,1,0x65,3,4,3,0x12};
static const char ID_HEAD[]="ALBPKG PRIVATE IDENTITY 1\n";
static const char PEM_HEAD[]="-----BEGIN ENCRYPTED PRIVATE KEY-----\n";
static const char PEM_TAIL[]="-----END ENCRYPTED PRIVATE KEY-----\n";

static size_t der_len(unsigned char*out,size_t n){size_t bytes=0,x=n,i;if(n<128){out[0]=(unsigned char)n;return 1;}while(x){bytes++;x>>=8;}out[0]=(unsigned char)(0x80|bytes);for(i=0;i<bytes;i++)out[bytes-i]=(unsigned char)(n>>(i*8));return bytes+1;}
static size_t der_tlv(unsigned char tag,const unsigned char*v,size_t n,unsigned char*out,size_t cap){unsigned char len[sizeof(size_t)+1];size_t ln=der_len(len,n);if(cap<1+ln||n>cap-1-ln)return 0;out[0]=tag;memcpy(out+1,len,ln);if(n)memcpy(out+1+ln,v,n);return 1+ln+n;}
static size_t der_join(unsigned char tag,const unsigned char **parts,const size_t*lens,size_t count,unsigned char*out,size_t cap){unsigned char tmp[DER_MAX];size_t i,n=0;for(i=0;i<count;i++){if(lens[i]>sizeof(tmp)-n)return 0;memcpy(tmp+n,parts[i],lens[i]);n+=lens[i];}return der_tlv(tag,tmp,n,out,cap);}
static size_t der_oid(const unsigned char*oid,size_t n,unsigned char*out,size_t cap){return der_tlv(6,oid,n,out,cap);}
static size_t der_oct(const unsigned char*v,size_t n,unsigned char*out,size_t cap){return der_tlv(4,v,n,out,cap);}
static size_t der_int(unsigned value,unsigned char*out,size_t cap){unsigned char raw[5];size_t n=0,i;do{raw[4-n++]=(unsigned char)value;value>>=8;}while(value);i=5-n;if(raw[i]&0x80){raw[--i]=0;n++;}return der_tlv(2,raw+i,n,out,cap);}
static size_t plain_pkcs8(const unsigned char*seed,size_t sn,const unsigned char*algorithm_oid,size_t oid_len,unsigned char*out,size_t cap){
 unsigned char inner[128],private_key[140],oid_tlv[32],algorithm[40],version[8];
 const unsigned char*parts[3];size_t lens[3],inner_len,private_len,oid_tlv_len,algorithm_len,version_len;
 inner_len=der_tlv(0x80,seed,sn,inner,sizeof(inner));
 private_len=der_oct(inner,inner_len,private_key,sizeof(private_key));
 oid_tlv_len=der_oid(algorithm_oid,oid_len,oid_tlv,sizeof(oid_tlv));
 if(!inner_len||!private_len||!oid_tlv_len)return 0;
 {const unsigned char*p[]={oid_tlv};size_t l[]={oid_tlv_len};algorithm_len=der_join(0x30,p,l,1,algorithm,sizeof(algorithm));}
 version_len=der_int(0,version,sizeof(version));
 parts[0]=version;parts[1]=algorithm;parts[2]=private_key;
 lens[0]=version_len;lens[1]=algorithm_len;lens[2]=private_len;
 return der_join(0x30,parts,lens,3,out,cap);
}

typedef struct{const unsigned char*p;size_t n,off;} dreader;
static int d_take(dreader*r,unsigned tag,const unsigned char**v,size_t*n){unsigned first,count;size_t size=0,i;if(!r||r->off>=r->n||r->p[r->off++]!=tag||r->off>=r->n)return 0;first=r->p[r->off++];if(first<128)size=first;else{count=first&127;if(!count||count>4||r->off+count>r->n||r->p[r->off]==0||(count==1&&r->p[r->off]<128))return 0;for(i=0;i<count;i++)size=size*256+r->p[r->off++];}if(size>r->n-r->off)return 0;*v=r->p+r->off;*n=size;r->off+=size;return 1;}
static int d_seq(dreader*r,dreader*out){const unsigned char*p;size_t n;if(!d_take(r,0x30,&p,&n))return 0;out->p=p;out->n=n;out->off=0;return 1;}
static int d_oid(dreader*r,const unsigned char*expected,size_t n){const unsigned char*p;size_t z;return d_take(r,6,&p,&z)&&z==n&&!memcmp(p,expected,n);}
static int d_finish(const dreader*r){return r->off==r->n;}
static int d_uint(dreader*r,unsigned*out){const unsigned char*p;size_t n,i;unsigned x=0;if(!d_take(r,2,&p,&n)||!n||n>5||(p[0]&0x80)||(n>1&&p[0]==0&&p[1]<0x80))return 0;for(i=0;i<n;i++){if(x>(UINT_MAX-p[i])/256)return 0;x=x*256+p[i];}*out=x;return 1;}
static int parse_plain_pkcs8(const unsigned char*blob,size_t bn,const unsigned char*oid,size_t on,unsigned char*seed,size_t sn){dreader root={blob,bn,0},outer,alg,inner;const unsigned char*p;size_t n;unsigned version;if(!d_seq(&root,&outer)||!d_uint(&outer,&version)||version||!d_seq(&outer,&alg)||!d_oid(&alg,oid,on)||!d_finish(&alg)||!d_take(&outer,4,&p,&n)||!d_finish(&outer)||!d_finish(&root))return 0;inner.p=p;inner.n=n;inner.off=0;if(!d_take(&inner,0x80,&p,&n)||n!=sn||!d_finish(&inner))return 0;memcpy(seed,p,n);return 1;}

static int cbc_crypt(int enc,const unsigned char key[32],const unsigned char iv[16],const unsigned char*in,size_t n,unsigned char*out,size_t cap,size_t*outn){EVP_CIPHER_CTX*c=NULL;int a=0,b=0;int ok=0;if(n>INT_MAX||cap<n||cap>INT_MAX)return 0;c=EVP_CIPHER_CTX_new();if(c&&EVP_CipherInit_ex(c,EVP_aes_256_cbc(),NULL,key,iv,enc)>0&&EVP_CipherUpdate(c,out,&a,in,(int)n)>0&&a>=0&&(size_t)a<=cap&&EVP_CipherFinal_ex(c,out+a,&b)>0&&b>=0&&(size_t)b<=cap-(size_t)a){*outn=(size_t)a+(size_t)b;ok=1;}EVP_CIPHER_CTX_free(c);return ok;}
static int encrypt_pkcs8(const unsigned char*plain,size_t plain_len,const unsigned char*pass,size_t pass_len,unsigned char*out,size_t cap,size_t*out_len){
 unsigned char salt[16],iv[16],key[32],ciphertext[DER_MAX],hmac_oid[32],prf[48],salt_tlv[32],iterations[8],pbkdf_params[96],pbkdf_oid[32],kdf[160],iv_tlv[32],aes_oid[32],scheme[80],pbes_oid[32],pbes_params[256],algorithm[320],encrypted[DER_MAX];
 const unsigned char*parts[3];size_t lens[3],cipher_len=0,hmac_oid_len,prf_len,salt_len,iterations_len,pbkdf_params_len,pbkdf_oid_len,kdf_len,iv_len,aes_oid_len,scheme_len,pbes_params_len,pbes_oid_len,algorithm_len,encrypted_len,result_len;int ok=0;
 if(pass_len>INT_MAX||plain_len>DER_MAX||RAND_bytes(salt,16)<=0||RAND_bytes(iv,16)<=0||PKCS5_PBKDF2_HMAC((const char*)pass,(int)pass_len,salt,16,600000,EVP_sha256(),32,key)<=0)goto done;
 if(!cbc_crypt(1,key,iv,plain,plain_len,ciphertext,sizeof(ciphertext),&cipher_len))goto done;
 hmac_oid_len=der_oid(OID_HMAC256,sizeof(OID_HMAC256),hmac_oid,sizeof(hmac_oid));
 {unsigned char null_parameters[]={5,0};parts[0]=hmac_oid;parts[1]=null_parameters;lens[0]=hmac_oid_len;lens[1]=2;prf_len=der_join(0x30,parts,lens,2,prf,sizeof(prf));}
 salt_len=der_oct(salt,16,salt_tlv,sizeof(salt_tlv));iterations_len=der_int(600000,iterations,sizeof(iterations));
 parts[0]=salt_tlv;parts[1]=iterations;parts[2]=prf;lens[0]=salt_len;lens[1]=iterations_len;lens[2]=prf_len;pbkdf_params_len=der_join(0x30,parts,lens,3,pbkdf_params,sizeof(pbkdf_params));
 pbkdf_oid_len=der_oid(OID_PBKDF2,sizeof(OID_PBKDF2),pbkdf_oid,sizeof(pbkdf_oid));parts[0]=pbkdf_oid;parts[1]=pbkdf_params;lens[0]=pbkdf_oid_len;lens[1]=pbkdf_params_len;kdf_len=der_join(0x30,parts,lens,2,kdf,sizeof(kdf));
 aes_oid_len=der_oid(OID_AES256CBC,sizeof(OID_AES256CBC),aes_oid,sizeof(aes_oid));iv_len=der_oct(iv,16,iv_tlv,sizeof(iv_tlv));parts[0]=aes_oid;parts[1]=iv_tlv;lens[0]=aes_oid_len;lens[1]=iv_len;scheme_len=der_join(0x30,parts,lens,2,scheme,sizeof(scheme));
 parts[0]=kdf;parts[1]=scheme;lens[0]=kdf_len;lens[1]=scheme_len;pbes_params_len=der_join(0x30,parts,lens,2,pbes_params,sizeof(pbes_params));
 pbes_oid_len=der_oid(OID_PBES2,sizeof(OID_PBES2),pbes_oid,sizeof(pbes_oid));parts[0]=pbes_oid;parts[1]=pbes_params;lens[0]=pbes_oid_len;lens[1]=pbes_params_len;algorithm_len=der_join(0x30,parts,lens,2,algorithm,sizeof(algorithm));
 encrypted_len=der_oct(ciphertext,cipher_len,encrypted,sizeof(encrypted));parts[0]=algorithm;parts[1]=encrypted;lens[0]=algorithm_len;lens[1]=encrypted_len;result_len=der_join(0x30,parts,lens,2,out,cap);
 if(!result_len)goto done;*out_len=result_len;ok=1;
done:OPENSSL_cleanse(key,sizeof(key));OPENSSL_cleanse(ciphertext,sizeof(ciphertext));return ok;
}

static int decrypt_pkcs8(const unsigned char*blob,size_t blob_len,const unsigned char*pass,size_t pass_len,unsigned char*out,size_t cap,size_t*out_len){
 dreader root={blob,blob_len,0},outer,algorithm,params,kdf,kdf_params,prf,scheme;const unsigned char*salt,*null_parameters,*iv,*ciphertext;size_t salt_len,null_len,iv_len,cipher_len;unsigned iterations;unsigned char key[32];int ok=0;
 if(pass_len>INT_MAX||blob_len>DER_MAX||!d_seq(&root,&outer)||!d_seq(&outer,&algorithm)||!d_oid(&algorithm,OID_PBES2,sizeof(OID_PBES2))||!d_seq(&algorithm,&params)||!d_seq(&params,&kdf)||!d_oid(&kdf,OID_PBKDF2,sizeof(OID_PBKDF2))||!d_seq(&kdf,&kdf_params)||!d_take(&kdf_params,4,&salt,&salt_len)||salt_len!=16||!d_uint(&kdf_params,&iterations)||iterations<600000||iterations>10000000||!d_seq(&kdf_params,&prf)||!d_oid(&prf,OID_HMAC256,sizeof(OID_HMAC256))||!d_take(&prf,5,&null_parameters,&null_len)||null_len||!d_finish(&prf)||!d_finish(&kdf_params)||!d_finish(&kdf)||!d_seq(&params,&scheme)||!d_oid(&scheme,OID_AES256CBC,sizeof(OID_AES256CBC))||!d_take(&scheme,4,&iv,&iv_len)||iv_len!=16||!d_finish(&scheme)||!d_finish(&params)||!d_finish(&algorithm)||!d_take(&outer,4,&ciphertext,&cipher_len)||!d_finish(&outer)||!d_finish(&root)||!cipher_len||cipher_len>DER_MAX||cipher_len%16||PKCS5_PBKDF2_HMAC((const char*)pass,(int)pass_len,salt,16,(int)iterations,EVP_sha256(),32,key)<=0)goto done;
 ok=cbc_crypt(0,key,iv,ciphertext,cipher_len,out,cap,out_len);
done:OPENSSL_cleanse(key,sizeof(key));if(!ok&&out)OPENSSL_cleanse(out,cap);return ok;
}

static size_t pem_write(const unsigned char*der,size_t der_len,unsigned char*out,size_t cap){unsigned char base64[DER_MAX*2];int encoded;size_t needed,pos=0,i,take;if(der_len>INT_MAX)return 0;encoded=EVP_EncodeBlock(base64,der,(int)der_len);if(encoded<=0)return 0;needed=strlen(PEM_HEAD)+(size_t)encoded+((size_t)encoded+63)/64+strlen(PEM_TAIL);if(needed>cap)return 0;memcpy(out+pos,PEM_HEAD,strlen(PEM_HEAD));pos+=strlen(PEM_HEAD);for(i=0;i<(size_t)encoded;i+=take){take=(size_t)encoded-i;if(take>64)take=64;memcpy(out+pos,base64+i,take);pos+=take;out[pos++]='\n';}memcpy(out+pos,PEM_TAIL,strlen(PEM_TAIL));pos+=strlen(PEM_TAIL);return pos;}
static size_t find_bytes(const unsigned char*hay,size_t hn,const char*needle,size_t nn,size_t start){size_t i;if(nn>hn||start>hn-nn)return SIZE_MAX;for(i=start;i<=hn-nn;i++)if(!memcmp(hay+i,needle,nn))return i;return SIZE_MAX;}
static int pem_take(const unsigned char*blob,size_t blob_len,size_t start,unsigned char*der,size_t cap,size_t*der_len,size_t*next){size_t head_len=strlen(PEM_HEAD),tail_len=strlen(PEM_TAIL),body_start,end,i,line=0,b64_len=0;unsigned char b64[DER_MAX*2],canonical[DER_MAX*2];int decoded;size_t canonical_len,padding=0;if(start>blob_len||head_len>blob_len-start||memcmp(blob+start,PEM_HEAD,head_len))return 0;body_start=start+head_len;end=find_bytes(blob,blob_len,PEM_TAIL,tail_len,body_start);if(end==SIZE_MAX||end==body_start||blob[end-1]!='\n')return 0;for(i=body_start;i<end;i++){unsigned char ch=blob[i];if(ch=='\n'){if(!line||line>64||(i+1<end&&line!=64))return 0;line=0;continue;}if(!(ch>='A'&&ch<='Z')&&!(ch>='a'&&ch<='z')&&!(ch>='0'&&ch<='9')&&ch!='+'&&ch!='/'&&ch!='=')return 0;if(b64_len>=sizeof(b64))return 0;b64[b64_len++]=ch;line++;}if(!b64_len||b64_len%4||b64_len>INT_MAX)return 0;decoded=EVP_DecodeBlock(der,b64,(int)b64_len);if(decoded<0)return 0;if(b64[b64_len-1]=='=')padding++;if(b64_len>1&&b64[b64_len-2]=='=')padding++;if((size_t)decoded<padding||(size_t)decoded-padding>cap)return 0;*der_len=(size_t)decoded-padding;*next=end+tail_len;canonical_len=pem_write(der,*der_len,canonical,sizeof(canonical));if(canonical_len!=*next-start||memcmp(canonical,blob+start,canonical_len))return 0;return 1;}

static int get_passphrase(alb_passphrase callback,void*user,int confirm,unsigned char pass[1024],size_t*length){*length=0;if(!callback||!callback(user,pass,1024,length,confirm)||*length<8||*length>1024){OPENSSL_cleanse(pass,1024);*length=0;return 0;}return 1;}
int alb_save_identity(const alb_identity*identity,const char*path,alb_passphrase callback,void*user,int overwrite){unsigned char kem_seed[64],sig_seed[32],kem_plain[128],sig_plain[96],kem_der[DER_MAX],sig_der[DER_MAX],blob[IDENTITY_MAX],pass[1024];size_t n,kem_plain_len,sig_plain_len,kem_der_len,sig_der_len,blob_len=0,pass_len=0;FILE*out=NULL;char*temporary_name=NULL;int ok=0;clear_error();if(!identity||!path||!callback||(overwrite!=0&&overwrite!=1)){set_error(ALB_ERR_ARGUMENT);goto done;}n=sizeof(kem_seed);if(EVP_PKEY_get_octet_string_param(identity->kem,"seed",kem_seed,sizeof(kem_seed),&n)<=0||n!=sizeof(kem_seed)){set_error(ALB_ERR_PROVIDER);goto done;}n=sizeof(sig_seed);if(EVP_PKEY_get_octet_string_param(identity->sig,"seed",sig_seed,sizeof(sig_seed),&n)<=0||n!=sizeof(sig_seed)){set_error(ALB_ERR_PROVIDER);goto done;}if(!get_passphrase(callback,user,1,pass,&pass_len)){set_error(ALB_ERR_AUTHENTICATION);goto done;}kem_plain_len=plain_pkcs8(kem_seed,sizeof(kem_seed),OID_MLKEM768,sizeof(OID_MLKEM768),kem_plain,sizeof(kem_plain));sig_plain_len=plain_pkcs8(sig_seed,sizeof(sig_seed),OID_MLDSA65,sizeof(OID_MLDSA65),sig_plain,sizeof(sig_plain));if(!kem_plain_len||!sig_plain_len||!encrypt_pkcs8(kem_plain,kem_plain_len,pass,pass_len,kem_der,sizeof(kem_der),&kem_der_len)||!encrypt_pkcs8(sig_plain,sig_plain_len,pass,pass_len,sig_der,sizeof(sig_der),&sig_der_len)){set_error(ALB_ERR_PROVIDER);goto done;}memcpy(blob,ID_HEAD,strlen(ID_HEAD));blob_len=strlen(ID_HEAD);n=pem_write(kem_der,kem_der_len,blob+blob_len,sizeof(blob)-blob_len);if(!n){set_error(ALB_ERR_INTERNAL);goto done;}blob_len+=n;n=pem_write(sig_der,sig_der_len,blob+blob_len,sizeof(blob)-blob_len);if(!n){set_error(ALB_ERR_INTERNAL);goto done;}blob_len+=n;out=temporary(path,&temporary_name);if(!out||fwrite(blob,1,blob_len,out)!=blob_len||fflush(out)||syncfd(fileno(out))){set_error(ALB_ERR_IO);goto done;}{int closed=fclose(out);out=NULL;if(closed){set_error(ALB_ERR_IO);goto done;}}if(!publish_mode(temporary_name,path,overwrite)){set_error(overwrite?ALB_ERR_IO:ALB_ERR_EXISTS);goto done;}ok=1;
done:if(out)fclose(out);if(temporary_name){if(!ok)unlinkfile(temporary_name);free(temporary_name);}OPENSSL_cleanse(pass,sizeof(pass));OPENSSL_cleanse(kem_seed,sizeof(kem_seed));OPENSSL_cleanse(sig_seed,sizeof(sig_seed));OPENSSL_cleanse(kem_plain,sizeof(kem_plain));OPENSSL_cleanse(sig_plain,sizeof(sig_plain));OPENSSL_cleanse(kem_der,sizeof(kem_der));OPENSSL_cleanse(sig_der,sizeof(sig_der));return ok?0:-1;}
int alb_load_identity(const char*path,alb_passphrase callback,void*user,alb_identity**out_identity){FILE*in=NULL;unsigned char*blob=NULL;unsigned char kem_der[DER_MAX],sig_der[DER_MAX],kem_plain[DER_MAX],sig_plain[DER_MAX],kem_seed[64],sig_seed[32],pass[1024];size_t size=0,start,kem_der_len,sig_der_len,kem_plain_len,sig_plain_len,pass_len=0;int64_t signed_size;int ok=0;clear_error();if(!path||!callback||!out_identity){set_error(ALB_ERR_ARGUMENT);return -1;}*out_identity=NULL;in=private_readfile(path);if(!in)goto done;if(seek64(in,0,SEEK_END)){set_error(ALB_ERR_IO);goto done;}signed_size=tell64(in);if(signed_size<0){set_error(ALB_ERR_IO);goto done;}if((uint64_t)signed_size>IDENTITY_MAX){set_error(ALB_ERR_LIMIT);goto done;}if(seek64(in,0,SEEK_SET)){set_error(ALB_ERR_IO);goto done;}size=(size_t)signed_size;blob=malloc(size?size:1);if(!blob){set_error(ALB_ERR_MEMORY);goto done;}if(fread(blob,1,size,in)!=size){set_error(ALB_ERR_IO);goto done;}if(size<strlen(ID_HEAD)||memcmp(blob,ID_HEAD,strlen(ID_HEAD))){set_error(ALB_ERR_FORMAT);goto done;}start=strlen(ID_HEAD);if(!pem_take(blob,size,start,kem_der,sizeof(kem_der),&kem_der_len,&start)||!pem_take(blob,size,start,sig_der,sizeof(sig_der),&sig_der_len,&start)||start!=size){set_error(ALB_ERR_FORMAT);goto done;}if(!get_passphrase(callback,user,0,pass,&pass_len)||!decrypt_pkcs8(kem_der,kem_der_len,pass,pass_len,kem_plain,sizeof(kem_plain),&kem_plain_len)||!decrypt_pkcs8(sig_der,sig_der_len,pass,pass_len,sig_plain,sizeof(sig_plain),&sig_plain_len)){set_error(ALB_ERR_AUTHENTICATION);goto done;}if(!parse_plain_pkcs8(kem_plain,kem_plain_len,OID_MLKEM768,sizeof(OID_MLKEM768),kem_seed,sizeof(kem_seed))||!parse_plain_pkcs8(sig_plain,sig_plain_len,OID_MLDSA65,sizeof(OID_MLDSA65),sig_seed,sizeof(sig_seed))){set_error(ALB_ERR_FORMAT);goto done;}if(alb_identity_from_seeds(kem_seed,sig_seed,out_identity)){set_error(ALB_ERR_PROVIDER);goto done;}ok=1;
done:if(in)fclose(in);if(blob){OPENSSL_cleanse(blob,size);free(blob);}OPENSSL_cleanse(pass,sizeof(pass));OPENSSL_cleanse(kem_der,sizeof(kem_der));OPENSSL_cleanse(sig_der,sizeof(sig_der));OPENSSL_cleanse(kem_plain,sizeof(kem_plain));OPENSSL_cleanse(sig_plain,sizeof(sig_plain));OPENSSL_cleanse(kem_seed,sizeof(kem_seed));OPENSSL_cleanse(sig_seed,sizeof(sig_seed));if(!ok&&out_identity&&*out_identity){alb_identity_free(*out_identity);*out_identity=NULL;}return ok?0:-1;}

static int load_legacy_identity(const char*path,alb_passphrase callback,void*user,alb_identity**out_identity){FILE*in=NULL;unsigned char*blob=NULL;unsigned char pass[1024],key[32],seeds[128],expected[32],stored[32];size_t size=0,pass_len=0,seeds_len=0;int64_t signed_size;uint32_t iterations,pubid_len,sealed_len;size_t prefix_len;alb_contact public_contact;int ok=0;*out_identity=NULL;in=private_readfile(path);if(!in)goto done;if(seek64(in,0,SEEK_END)){set_error(ALB_ERR_IO);goto done;}signed_size=tell64(in);if(signed_size<0){set_error(ALB_ERR_IO);goto done;}if((uint64_t)signed_size>IDENTITY_MAX){set_error(ALB_ERR_LIMIT);goto done;}if(seek64(in,0,SEEK_SET)){set_error(ALB_ERR_IO);goto done;}size=(size_t)signed_size;blob=malloc(size?size:1);if(!blob){set_error(ALB_ERR_MEMORY);goto done;}if(fread(blob,1,size,in)!=size){set_error(ALB_ERR_IO);goto done;}if(size<40||memcmp(blob,"ALBPKSK2",8)||get(blob+8,2)!=1||get(blob+10,2)!=1){set_error(ALB_ERR_FORMAT);goto done;}iterations=(uint32_t)get(blob+12,4);if(iterations<600000||iterations>10000000){set_error(ALB_ERR_LIMIT);goto done;}pubid_len=(uint32_t)get(blob+32,4);if(pubid_len!=3150||36u+pubid_len+4u>size){set_error(ALB_ERR_FORMAT);goto done;}if(alb_import_contact(blob+36,pubid_len,&public_contact)||alb_fingerprint(public_contact.pubid,stored)){set_error(ALB_ERR_FORMAT);goto done;}prefix_len=36u+pubid_len;sealed_len=(uint32_t)get(blob+prefix_len,4);if(sealed_len!=116||prefix_len+4u+sealed_len!=size){set_error(ALB_ERR_FORMAT);goto done;}if(!get_passphrase(callback,user,0,pass,&pass_len)||pass_len>INT_MAX||PKCS5_PBKDF2_HMAC((const char*)pass,(int)pass_len,blob+16,16,(int)iterations,EVP_sha256(),32,key)<=0){set_error(ALB_ERR_AUTHENTICATION);goto done;}if(!aead(0,key,blob,prefix_len,blob+prefix_len+4,sealed_len,seeds)){set_error(ALB_ERR_AUTHENTICATION);goto done;}seeds_len=sealed_len-16;if(seeds_len!=100||get(seeds,2)!=64||get(seeds+66,2)!=32){set_error(ALB_ERR_FORMAT);goto done;}if(alb_identity_from_seeds(seeds+2,seeds+68,out_identity)){set_error(ALB_ERR_PROVIDER);goto done;}if(alb_fingerprint((*out_identity)->pubid,expected)||CRYPTO_memcmp(expected,stored,32)){set_error(ALB_ERR_AUTHENTICATION);goto done;}ok=1;
done:if(in)fclose(in);if(blob){OPENSSL_cleanse(blob,size);free(blob);}OPENSSL_cleanse(pass,sizeof(pass));OPENSSL_cleanse(key,sizeof(key));OPENSSL_cleanse(seeds,sizeof(seeds));if(!ok&&*out_identity){alb_identity_free(*out_identity);*out_identity=NULL;}return ok?0:-1;}

#ifdef _WIN32
static wchar_t *canonical_migration_path(const char*path){
 wchar_t*input=wide(path),*full=NULL,*canonical=NULL,*slash,*leaf=NULL;DWORD needed,written;HANDLE handle=INVALID_HANDLE_VALUE;
 if(!input)return NULL;
 handle=CreateFileW(input,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,NULL);
 if(handle!=INVALID_HANDLE_VALUE){needed=GetFinalPathNameByHandleW(handle,NULL,0,FILE_NAME_NORMALIZED);if(needed){canonical=calloc((size_t)needed+1,sizeof(*canonical));if(canonical){written=GetFinalPathNameByHandleW(handle,canonical,needed+1,FILE_NAME_NORMALIZED);if(!written||written>needed){free(canonical);canonical=NULL;}}}CloseHandle(handle);free(input);return canonical;}
 if(GetLastError()!=ERROR_FILE_NOT_FOUND&&GetLastError()!=ERROR_PATH_NOT_FOUND){free(input);return NULL;}
 needed=GetFullPathNameW(input,0,NULL,NULL);if(!needed){free(input);return NULL;}full=calloc((size_t)needed+1,sizeof(*full));if(!full){free(input);return NULL;}written=GetFullPathNameW(input,needed+1,full,NULL);free(input);if(!written||written>needed){free(full);return NULL;}
 slash=wcsrchr(full,L'\\');if(!slash){free(full);return NULL;}leaf=calloc(wcslen(slash+1)+1,sizeof(*leaf));if(!leaf){free(full);return NULL;}wcscpy(leaf,slash+1);if(slash==full+2&&full[1]==L':')slash[1]=0;else if(slash==full)slash[1]=0;else *slash=0;
 handle=CreateFileW(full,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,NULL);if(handle==INVALID_HANDLE_VALUE){free(leaf);free(full);return NULL;}
 needed=GetFinalPathNameByHandleW(handle,NULL,0,FILE_NAME_NORMALIZED);if(needed){canonical=calloc((size_t)needed+wcslen(leaf)+3,sizeof(*canonical));if(canonical){written=GetFinalPathNameByHandleW(handle,canonical,needed+1,FILE_NAME_NORMALIZED);if(!written||written>needed){free(canonical);canonical=NULL;}else{size_t n=wcslen(canonical);if(n&&canonical[n-1]!=L'\\')canonical[n++]=L'\\';wcscpy(canonical+n,leaf);}}}CloseHandle(handle);free(leaf);free(full);return canonical;
}
static int same_migration_path(const char*a,const char*b){
 wchar_t*x=wide(a),*y=wide(b),*cx=NULL,*cy=NULL;HANDLE hx=INVALID_HANDLE_VALUE,hy=INVALID_HANDLE_VALUE;BY_HANDLE_FILE_INFORMATION ix,iy;int same=1;
 if(!x||!y)goto done;hx=CreateFileW(x,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,NULL);hy=CreateFileW(y,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,NULL);
 if(hx!=INVALID_HANDLE_VALUE&&hy!=INVALID_HANDLE_VALUE&&GetFileInformationByHandle(hx,&ix)&&GetFileInformationByHandle(hy,&iy)&&ix.dwVolumeSerialNumber==iy.dwVolumeSerialNumber&&ix.nFileIndexHigh==iy.nFileIndexHigh&&ix.nFileIndexLow==iy.nFileIndexLow){same=1;goto done;}
 cx=canonical_migration_path(a);cy=canonical_migration_path(b);if(!cx||!cy)goto done;same=CompareStringOrdinal(cx,-1,cy,-1,TRUE)==CSTR_EQUAL;
done:if(hx!=INVALID_HANDLE_VALUE)CloseHandle(hx);if(hy!=INVALID_HANDLE_VALUE)CloseHandle(hy);free(x);free(y);free(cx);free(cy);return same;
}
#else
static char *canonical_migration_path(const char*path){
 char*resolved=realpath(path,NULL),*copy,*slash,*parent,*leaf,*leaf_copy,*parent_real,*joined;size_t n;
 if(resolved)return resolved;copy=strdup(path);if(!copy)return NULL;slash=strrchr(copy,'/');if(!slash){parent=(char*)".";leaf=copy;}else{leaf=slash+1;if(!*leaf){free(copy);return NULL;}}
 leaf_copy=strdup(leaf);if(!leaf_copy){free(copy);return NULL;}if(slash){if(slash==copy){slash[1]=0;parent=copy;}else{*slash=0;parent=copy;}}
 parent_real=realpath(parent,NULL);if(!parent_real){free(leaf_copy);free(copy);return NULL;}n=strlen(parent_real)+strlen(leaf_copy)+2;joined=malloc(n);if(!joined){free(parent_real);free(leaf_copy);free(copy);return NULL;}snprintf(joined,n,"%s%s%s",parent_real,strcmp(parent_real,"/")?"/":"",leaf_copy);free(parent_real);free(leaf_copy);free(copy);return joined;
}
static int same_migration_path(const char*a,const char*b){
 char*x=canonical_migration_path(a),*y=canonical_migration_path(b);struct stat sx,sy;int same=1;
 if(x&&y)same=!strcmp(x,y);if(stat(a,&sx)==0&&stat(b,&sy)==0&&sx.st_dev==sy.st_dev&&sx.st_ino==sy.st_ino)same=1;free(x);free(y);return same;
}
#endif
int alb_migrate_legacy_identity(const char*source,const char*target,alb_passphrase callback,void*user,int overwrite,alb_identity**out_identity){alb_identity*identity=NULL;clear_error();if(!source||!target||!callback||!out_identity){set_error(ALB_ERR_ARGUMENT);return -1;}*out_identity=NULL;if((overwrite!=0&&overwrite!=1)||same_migration_path(source,target)){set_error(ALB_ERR_ARGUMENT);return -1;}if(load_legacy_identity(source,callback,user,&identity))return -1;if(alb_save_identity(identity,target,callback,user,overwrite)){alb_identity_free(identity);return -1;}*out_identity=identity;return 0;}
