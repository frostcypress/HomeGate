/* External transport fixture only: no credentials or capabilities changed. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
struct entry{int family,packets;char device[IFNAMSIZ];};static struct entry fdmap[4096];static char selected[IFNAMSIZ];
static int indexof(const char *s){return !strcmp(s,"br-lan")?10:!strcmp(s,"eth1")?11:!strcmp(s,"eth2")?12:0;}
static const char *mode(void){const char *s=getenv("HOMEGATE_WOL_FIXTURE_MODE");return s?s:"ok";}
static int bad(void){errno=EPERM;return -1;}
int socket(int family,int type,int protocol){
 if((family!=AF_INET&&family!=AF_PACKET)||(family==AF_INET&&(type&15)!=SOCK_DGRAM)||(family==AF_PACKET&&((type&15)!=SOCK_RAW||protocol!=htons(0x0842))))return bad();
 int fd=open("/dev/null",O_RDWR|O_CLOEXEC);if(fd<0)return fd;if(fd>=4096){close(fd);return bad();}memset(&fdmap[fd],0,sizeof(fdmap[fd]));fdmap[fd].family=family;return fd;
}
int ioctl(int fd,unsigned long request,...){
 va_list args;va_start(args,request);struct ifreq *r=va_arg(args,struct ifreq*);va_end(args);
 if(fd<0||fd>=4096||!fdmap[fd].family||!r){return bad();}
 int index=indexof(r->ifr_name);if(!index){errno=ENODEV;return -1;}
 if(request==SIOCGIFINDEX){if(!selected[0])strcpy(selected,r->ifr_name);r->ifr_ifindex=index;return 0;}
 if(request==SIOCGIFHWADDR){r->ifr_hwaddr.sa_family=ARPHRD_ETHER;unsigned char src[6]={0,17,34,51,68,(unsigned char)index};memcpy(r->ifr_hwaddr.sa_data,src,6);return 0;}
 if(request==SIOCGIFBRDADDR){struct sockaddr_in *s=(struct sockaddr_in*)&r->ifr_broadaddr;s->sin_family=AF_INET;s->sin_addr.s_addr=inet_addr("192.0.2.255");return 0;}return bad();
}
int setsockopt(int fd,int level,int option,const void *value,socklen_t length){
 if(fd<0||fd>=4096||!fdmap[fd].family||level!=SOL_SOCKET)return bad();
 if(option==SO_SNDTIMEO){if(length!=sizeof(struct timeval)||((const struct timeval*)value)->tv_sec!=1)return bad();return 0;}
 if(option==SO_BROADCAST){if(length!=sizeof(int)||*(const int*)value!=1)return bad();return 0;}
 if(option==SO_BINDTODEVICE){if(!length||length>=IFNAMSIZ+1||((const char*)value)[length-1]||strcmp(value,selected))return bad();strcpy(fdmap[fd].device,value);return !strcmp(mode(),"udp-fail")||!strcmp(mode(),"all-fail")?bad():0;}
 return bad();
}
ssize_t sendto(int fd,const void *data,size_t len,int flags,const struct sockaddr *address,socklen_t size){
 if(fd<0||fd>=4096||!fdmap[fd].family||flags!=MSG_DONTWAIT||!address)return bad();
 int family=fdmap[fd].family,index=0;unsigned char destination[4]={0};
 if(family==AF_PACKET){const struct sockaddr_ll *s=(const struct sockaddr_ll*)address;if(size!=sizeof(*s)||s->sll_family!=AF_PACKET||s->sll_protocol!=htons(0x0842)||s->sll_halen!=6||len!=116)return bad();index=s->sll_ifindex;for(int i=0;i<6;i++)if(s->sll_addr[i]!=255)return bad();}
 else{const struct sockaddr_in *s=(const struct sockaddr_in*)address;if(size!=sizeof(*s)||s->sin_family!=AF_INET||s->sin_port!=htons(9)||len!=102||!fdmap[fd].device[0])return bad();index=indexof(fdmap[fd].device);memcpy(destination,&s->sin_addr,4);}
 const char *m=mode();if(!strcmp(m,"hold")){sleep(45);return bad();}
 if(!strcmp(m,"all-fail")||(!strcmp(m,"raw-fail")&&family==AF_PACKET)||(!strcmp(m,"partial")&&family==AF_PACKET&&fdmap[fd].packets>=1))return bad();
 if(!strcmp(m,"short"))return (ssize_t)len-1;
 FILE *f=fopen("/teststate/wol-wire.bin","ab");if(!f)return bad();unsigned char header[12]={'W','O','L','1',(unsigned char)(family==AF_PACKET?1:2),(unsigned char)index,(unsigned char)(len>>8),(unsigned char)len,0,0,0,0};memcpy(header+8,destination,4);int ok=fwrite(header,1,12,f)==12&&fwrite(data,1,len,f)==len;if(fclose(f))ok=0;if(!ok)return bad();fdmap[fd].packets++;return (ssize_t)len;
}
