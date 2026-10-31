/* HomeGate contributors, MIT. Fixed raw Ethernet + UDP WOL transport. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define MAX_IF 1025
static const unsigned char broadcast[6]={255,255,255,255,255,255};
static int valid_if(const char *s) {
 size_t n=strlen(s);if(!n||n>=IFNAMSIZ||!strcmp(s,".")||!strcmp(s,".."))return 0;
 for(size_t i=0;i<n;i++)if(!isalnum((unsigned char)s[i])&&!strchr("_.:-",s[i]))return 0;
 return 1;
}
static int hex(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static int mac(const char *s,unsigned char out[6]) {
 char flat[13];size_t len=strlen(s),at=0;
 if(len==17&&(s[2]==':'||s[2]=='-')) {
  for(size_t i=0;i<len;i++){if(i%3==2){if(s[i]!=s[2])return 0;}else flat[at++]=s[i];}
 }else if(len==14&&s[4]=='.'&&s[9]=='.'){
  for(size_t i=0;i<len;i++)if(i!=4&&i!=9)flat[at++]=s[i];
 }else return 0;
 if(at!=12)return 0;
 for(size_t i=0;i<6;i++){int a=hex(flat[i*2]),b=hex(flat[i*2+1]);if(a<0||b<0)return 0;out[i]=(unsigned char)((a<<4)|b);}
 return 1;
}
static void request(struct ifreq *r,const char *name){memset(r,0,sizeof(*r));memcpy(r->ifr_name,name,strlen(name));}
static int raw_send(int control,const char *name,const unsigned char target[6],int *sent) {
 struct ifreq r;request(&r,name);if(ioctl(control,SIOCGIFINDEX,&r)<0)return -1;int index=r.ifr_ifindex;
 request(&r,name);if(ioctl(control,SIOCGIFHWADDR,&r)<0||r.ifr_hwaddr.sa_family!=ARPHRD_ETHER)return -1;
 unsigned char frame[116];memcpy(frame,broadcast,6);memcpy(frame+6,r.ifr_hwaddr.sa_data,6);frame[12]=8;frame[13]=0x42;
 memset(frame+14,255,6);for(int i=0;i<16;i++)memcpy(frame+20+i*6,target,6);
 int fd=socket(AF_PACKET,SOCK_RAW|SOCK_CLOEXEC,htons(0x0842));if(fd<0)return -1;
 struct sockaddr_ll dst;memset(&dst,0,sizeof(dst));dst.sll_family=AF_PACKET;dst.sll_protocol=htons(0x0842);dst.sll_ifindex=index;dst.sll_halen=6;memcpy(dst.sll_addr,broadcast,6);
 struct timeval timeout={1,0};if(setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))<0){close(fd);return -1;}
 int result=0;for(int n=0;n<3;n++){
  if(sendto(fd,frame,sizeof(frame),MSG_DONTWAIT,(struct sockaddr*)&dst,sizeof(dst))!=(ssize_t)sizeof(frame)){result=-1;break;}
  (*sent)++;usleep(40000);
 }
 close(fd);return result;
}
static int udp_send(int control,const char *name,const unsigned char target[6],int *sent) {
 struct in_addr addresses[2];addresses[0].s_addr=INADDR_BROADCAST;addresses[1].s_addr=INADDR_BROADCAST;
 struct ifreq r;request(&r,name);if(ioctl(control,SIOCGIFBRDADDR,&r)==0&&r.ifr_broadaddr.sa_family==AF_INET)addresses[0]=((struct sockaddr_in*)&r.ifr_broadaddr)->sin_addr;
 int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);if(fd<0)return -1;
 int one=1;struct timeval timeout={1,0};
 if(setsockopt(fd,SOL_SOCKET,SO_BROADCAST,&one,sizeof(one))<0||setsockopt(fd,SOL_SOCKET,SO_BINDTODEVICE,name,strlen(name)+1)<0||setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))<0){close(fd);return -1;}
 unsigned char packet[102];memset(packet,255,6);for(int i=0;i<16;i++)memcpy(packet+6+i*6,target,6);
 int result=0;for(int n=0;n<3;n++){
  for(int a=0;a<2;a++){
   struct sockaddr_in dst;memset(&dst,0,sizeof(dst));dst.sin_family=AF_INET;dst.sin_port=htons(9);dst.sin_addr=addresses[a];
   if(sendto(fd,packet,sizeof(packet),MSG_DONTWAIT,(struct sockaddr*)&dst,sizeof(dst))!=(ssize_t)sizeof(packet)){result=-1;goto done;}
   (*sent)++;
  }usleep(80000);
 }
done:close(fd);return result;
}
static int compare(const void *a,const void *b){return strcmp(*(char *const*)a,*(char *const*)b);}
int main(int argc,char **argv) {
 if(argc==2&&!strcmp(argv[1],"--version")){puts("homegate-wol 1");return 0;}
 if(geteuid()!=0||argc<3||argc>MAX_IF+2||!valid_if(argv[1]))return 2;
 alarm(5);
 unsigned char target[6];if(!mac(argv[2],target))return 2;
 char *names[MAX_IF],*sent_names[MAX_IF],*warnings[MAX_IF+1];int count=1,success_count=0,warn_count=0;
 names[0]=argv[1];for(int i=3;i<argc;i++){if(!valid_if(argv[i]))return 2;names[count++]=argv[i];}
 qsort(names+1,(size_t)count-1,sizeof(*names),compare);
 int used=1;for(int i=1;i<count;i++){if(!strcmp(names[i],names[0])||(i>1&&!strcmp(names[i],names[i-1])))continue;names[used++]=names[i];}
 int control=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);if(control<0){puts("{\"api_version\":1,\"ok\":false,\"phase\":\"wol-transport\",\"raw_sent\":0,\"udp_sent\":0,\"interfaces\":[],\"warnings\":[\"control_unavailable\"]}");return 7;}
 struct ifreq selected;request(&selected,names[0]);if(ioctl(control,SIOCGIFINDEX,&selected)<0){close(control);puts("{\"api_version\":1,\"ok\":false,\"phase\":\"wol-transport\",\"raw_sent\":0,\"udp_sent\":0,\"interfaces\":[],\"warnings\":[\"interface_unavailable\"]}");return 7;}
 int raw=0,udp=0;for(int i=0;i<used;i++){int n=0;if(raw_send(control,names[i],target,&n)<0)warnings[warn_count++]=names[i];raw+=n;if(n)sent_names[success_count++]=names[i];}
 int udp_error=udp_send(control,names[0],target,&udp);close(control);
 printf("{\"api_version\":1,\"ok\":%s,\"phase\":\"wol-transport\",\"raw_sent\":%d,\"udp_sent\":%d,\"interfaces\":[",raw+udp>0?"true":"false",raw,udp);
 for(int i=0;i<success_count;i++){printf("%s\"%s\"",i?",":"",sent_names[i]);}
 printf("],\"warnings\":[");
 for(int i=0;i<warn_count;i++)printf("%s\"raw/%s failed\"",i?",":"",warnings[i]);
 if(udp_error){printf("%s\"udp/%s failed\"",warn_count?",":"",names[0]);}
 puts("]}");return raw+udp>0?0:7;
}
