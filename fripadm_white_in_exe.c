#include<stdio.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<linux/ioctl.h>


/********/
#ifndef FR_IP_MEMDEV_MAJOR
#define FR_IP_MEMDEV_MAJOR 0
#endif
#ifndef FR_IP_MEMDEV_NR_DEVS
#define FR_IP_MEMDEV_NR_DEVS 2  
#endif
#ifndef FR_IP_MEMDEV_SIZE
#define FR_IP_MEMDEV_SIZE 4096
#endif

/* for fr_ip_ioctl_para_t's type */
/* in-black ip */
#define FR_IP_IOCTL_TYPE_FIND	1
#define FR_IP_IOCTL_TYPE_FIND_BYSTRINGS		2	// * :)
#define FR_IP_IOCTL_TYPE_MIRROR_INSERT_IP	3	
#define FR_IP_IOCTL_TYPE_MIRROR_INSERT_BYSTRINGS	4	// * :)
#define FR_IP_IOCTL_TYPE_MIRROR_DELETE_IP	5		// *  :)
#define FR_IP_IOCTL_TYPE_MIRROR_DELETE_IP_RANDOMLY		6 //*  :)
#define FR_IP_IOCTL_TYPE_MIRROR_DELETE_BYSTRINGS	7	// * :)
#define FR_IP_IOCTL_TYPE_MIRROR_DELETE_ALL		8	//*  :)
#define FR_IP_IOCTL_TYPE_SWITCH_MIRROR_UPDATE	9	// *  :)
#define FR_IP_IOCTL_TYPE_REBUILD	10	// *	:)
#define FR_IP_IOCTL_TYPE_COPY_HASH_STRUCT 	11	// *
#define FR_IP_IOCTL_TYPE_DUMP	12	//*  :)
#define FR_IP_IOCTL_TYPE_MIRROR_INSERT_IP_BINS	13	//*  :)
#define FR_IP_IOCTL_TYPE_MIRROR_DELETE_IP_BINS	14	//*  :)
/* in-white ip */
#define FR_IP_IOCTL_TYPE_WHITE_FIND	101
#define FR_IP_IOCTL_TYPE_WHITE_FIND_BYSTRINGS		102  // * :)
#define FR_IP_IOCTL_TYPE_WHITE_MIRROR_INSERT_IP		103
#define FR_IP_IOCTL_TYPE_WHITE_MIRROR_INSERT_BYSTRINGS	104  // * :)
#define FR_IP_IOCTL_TYPE_WHITE_MIRROR_DELETE_IP		105
#define FR_IP_IOCTL_TYPE_WHITE_MIRROR_DELETE_IP_RANDOMLY		106  // * :)
#define FR_IP_IOCTL_TYPE_WHITE_MIRROR_DELETE_BYSTRINGS	107	// * :)
#define FR_IP_IOCTL_TYPE_WHITE_MIRROR_DELETE_ALL		108	//*  :)
#define FR_IP_IOCTL_TYPE_WHITE_SWITCH_MIRROR_UPDATE	109	// *  :)
#define FR_IP_IOCTL_TYPE_WHITE_REBUILD	110	// *	:)
#define FR_IP_IOCTL_TYPE_WHITE_COPY_HASH_STRUCT 	111	// *
#define FR_IP_IOCTL_TYPE_WHITE_DUMP	112	//*  :)
#define FR_IP_IOCTL_TYPE_WHITE_MIRROR_INSERT_IP_BINS	113	//*  :)
#define FR_IP_IOCTL_TYPE_WHITE_MIRROR_DELETE_IP_BINS	114	//*  :)

struct fr_ip_mem_dev                                     
{                                                        
  char *data;                      
  unsigned long size;       
};

struct fr_ip_ioctl_para_t {
  void * ptr;
  unsigned int size;
  unsigned int type;
  unsigned int ret;
};

#define FR_IP_MEMDEV_IOC_MAGIC  'k'
#define FR_IP_MEMDEV_IOCPRINT   _IO(FR_IP_MEMDEV_IOC_MAGIC, 1)
#define FR_IP_MEMDEV_IOCGETDATA _IOR(FR_IP_MEMDEV_IOC_MAGIC, 2, int)
#define FR_IP_MEMDEV_IOCSETDATA _IOW(FR_IP_MEMDEV_IOC_MAGIC, 3, int)
#define FR_IP_MEMDEV_IOC_MAXNR 3

/********/

struct fr_ip_ioctl_para_t gl_para;

static unsigned int double_hash_find_bystrings(int fd,char * str, unsigned int size) {

		if ( (fd<0)||(str==NULL)||(size==0) ){
				fprintf(stderr,"double_hash_find_bystrings input invalid!\n");
				return 3;
		}
		
		gl_para.ptr=str;
		gl_para.size=size;
		gl_para.type=FR_IP_IOCTL_TYPE_FIND_BYSTRINGS;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_find_bystrings cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}

static unsigned int double_hash_mirror_insert_bystrings(int fd,char * str, unsigned int size) {

		if ( (fd<0)||(str==NULL)||(size==0) ){
				fprintf(stderr,"double_hash_mirror_insert_bystrings input invalid!\n");
				return 3;
		}

		gl_para.ptr=str;
		gl_para.size=size;
		gl_para.type=FR_IP_IOCTL_TYPE_MIRROR_INSERT_BYSTRINGS;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_mirror_insert_bystrings cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}

static unsigned int double_hash_mirror_insert_bins(int fd,char * str, unsigned int size) {

		if ( (fd<0)||(str==NULL)||(size==0) ){
				fprintf(stderr,"double_hash_mirror_insert_bins input invalid!\n");
				return 3;
		}

		gl_para.ptr=str;
		gl_para.size=size;
		gl_para.type=FR_IP_IOCTL_TYPE_MIRROR_INSERT_IP_BINS;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_mirror_insert_bins cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}

static unsigned int double_hash_mirror_delete_bystrings(int fd,char * str, unsigned int size) {

		if ( (fd<0)||(str==NULL)||(size==0) ){
				fprintf(stderr,"double_hash_mirror_delete_bystrings input invalid!\n");
				return 3;
		}

		gl_para.ptr=str;
		gl_para.size=size;
		gl_para.type=FR_IP_IOCTL_TYPE_MIRROR_DELETE_BYSTRINGS;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_mirror_delete_bystrings cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}

static unsigned int double_hash_mirror_delete_bins(int fd,char * str, unsigned int size) {

		if ( (fd<0)||(str==NULL)||(size==0) ){
				fprintf(stderr,"double_hash_mirror_delete_bins input invalid!\n");
				return 3;
		}

		gl_para.ptr=str;
		gl_para.size=size;
		gl_para.type=FR_IP_IOCTL_TYPE_MIRROR_DELETE_IP_BINS;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_mirror_delete_bins cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}

static unsigned int double_hash_mirror_delete_ip_randomly(int fd,unsigned int size) {

		if ( (fd<0)||(size==0) ){
				fprintf(stderr,"double_hash_mirror_delete_ip_randomly input invalid!\n");
				return 3;
		}

		gl_para.size=size;
		gl_para.type=FR_IP_IOCTL_TYPE_MIRROR_DELETE_IP_RANDOMLY;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_mirror_delete_ip_randomly cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}


static unsigned int double_hash_mirror_delete_all(int fd) {

		if ( (fd<0) ){
				fprintf(stderr,"double_hash_mirror_delete_all input invalid!\n");
				return 3;
		}

		gl_para.type=FR_IP_IOCTL_TYPE_MIRROR_DELETE_ALL;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_mirror_delete_all cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}

static unsigned int double_hash_switch_mirror_update(int fd) {

		if ( (fd<0) ){
				fprintf(stderr,"double_hash_switch_mirror_update input invalid!\n");
				return 3;
		}

		gl_para.type=FR_IP_IOCTL_TYPE_SWITCH_MIRROR_UPDATE;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_switch_mirror_update cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}


static unsigned int double_hash_rebuild(int fd,unsigned int modular, unsigned int rnd) {

		unsigned int in[2];

		if ( (fd<0)||(modular==0) ){
				fprintf(stderr,"double_hash_rebuild input invalid!\n");
				return 3;
		}

		in[0]=modular;
		in[1]=rnd;
		gl_para.ptr=in;
		gl_para.size=sizeof(unsigned int)*2;
		gl_para.type=FR_IP_IOCTL_TYPE_REBUILD;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_rebuild cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}

static unsigned int double_hash_dump(int fd) {

		if ( (fd<0) ){
				fprintf(stderr,"double_hash_dump input invalid!\n");
				return 3;
		}

		gl_para.type=FR_IP_IOCTL_TYPE_DUMP;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_switch_mirror_update cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}

static unsigned int double_hash_white_find_bystrings(int fd,char * str, unsigned int size) {

		if ( (fd<0)||(str==NULL)||(size==0) ){
				fprintf(stderr,"double_hash_white_find_bystrings input invalid!\n");
				return 3;
		}
		
		gl_para.ptr=str;
		gl_para.size=size;
		gl_para.type=FR_IP_IOCTL_TYPE_WHITE_FIND_BYSTRINGS;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_white_find_bystrings cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}

static unsigned int double_hash_white_mirror_insert_bystrings(int fd,char * str, unsigned int size) {

		if ( (fd<0)||(str==NULL)||(size==0) ){
				fprintf(stderr,"double_hash_white_mirror_insert_bystrings input invalid!\n");
				return 3;
		}

		gl_para.ptr=str;
		gl_para.size=size;
		gl_para.type=FR_IP_IOCTL_TYPE_WHITE_MIRROR_INSERT_BYSTRINGS;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_white_mirror_insert_bystrings cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}

static unsigned int double_hash_white_mirror_insert_bins(int fd,char * str, unsigned int size) {

		if ( (fd<0)||(str==NULL)||(size==0) ){
				fprintf(stderr,"double_hash_white_mirror_insert_bins input invalid!\n");
				return 3;
		}

		gl_para.ptr=str;
		gl_para.size=size;
		gl_para.type=FR_IP_IOCTL_TYPE_WHITE_MIRROR_INSERT_IP_BINS;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_white_mirror_insert_bins cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}

static unsigned int double_hash_white_mirror_delete_bystrings(int fd,char * str, unsigned int size) {

		if ( (fd<0)||(str==NULL)||(size==0) ){
				fprintf(stderr,"double_hash_white_mirror_delete_bystrings input invalid!\n");
				return 3;
		}

		gl_para.ptr=str;
		gl_para.size=size;
		gl_para.type=FR_IP_IOCTL_TYPE_WHITE_MIRROR_DELETE_BYSTRINGS;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_white_mirror_delete_bystrings cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}

static unsigned int double_hash_white_mirror_delete_bins(int fd,char * str, unsigned int size) {

		if ( (fd<0)||(str==NULL)||(size==0) ){
				fprintf(stderr,"double_hash_white_mirror_delete_bins input invalid!\n");
				return 3;
		}

		gl_para.ptr=str;
		gl_para.size=size;
		gl_para.type=FR_IP_IOCTL_TYPE_WHITE_MIRROR_DELETE_IP_BINS;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_white_mirror_delete_bins cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}

static unsigned int double_hash_white_mirror_delete_ip_randomly(int fd,unsigned int size) {

		if ( (fd<0)||(size==0) ){
				fprintf(stderr,"double_hash_white_mirror_delete_ip_randomly input invalid!\n");
				return 3;
		}

		gl_para.size=size;
		gl_para.type=FR_IP_IOCTL_TYPE_WHITE_MIRROR_DELETE_IP_RANDOMLY;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_white_mirror_delete_ip_randomly cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}


static unsigned int double_hash_white_mirror_delete_all(int fd) {

		if ( (fd<0) ){
				fprintf(stderr,"double_hash_white_mirror_delete_all input invalid!\n");
				return 3;
		}

		gl_para.type=FR_IP_IOCTL_TYPE_WHITE_MIRROR_DELETE_ALL;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_white_mirror_delete_all cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}

static unsigned int double_hash_white_switch_mirror_update(int fd) {

		if ( (fd<0) ){
				fprintf(stderr,"double_hash_white_switch_mirror_update input invalid!\n");
				return 3;
		}

		gl_para.type=FR_IP_IOCTL_TYPE_WHITE_SWITCH_MIRROR_UPDATE;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_white_switch_mirror_update cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}


static unsigned int double_hash_white_rebuild(int fd,unsigned int modular, unsigned int rnd) {

		unsigned int in[2];

		if ( (fd<0)||(modular==0) ){
				fprintf(stderr,"double_hash_white_rebuild input invalid!\n");
				return 3;
		}

		in[0]=modular;
		in[1]=rnd;
		gl_para.ptr=in;
		gl_para.size=sizeof(unsigned int)*2;
		gl_para.type=FR_IP_IOCTL_TYPE_WHITE_REBUILD;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_white_rebuild cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}

static unsigned int double_hash_white_dump(int fd) {

		if ( (fd<0) ){
				fprintf(stderr,"double_hash_white_dump input invalid!\n");
				return 3;
		}

		gl_para.type=FR_IP_IOCTL_TYPE_WHITE_DUMP;
		
		if (ioctl(fd, FR_IP_MEMDEV_IOCSETDATA, &gl_para) < 0)
			{
				fprintf(stderr,"double_hash_white_switch_mirror_update cmd MEMDEV_IOCSETDATA fail\n");
				return 4;
		}
		
		return gl_para.ret;
}


int main(int argc, char *argv[])
{
    int fd = 0;
    int type;
	unsigned int ret;
	
    fd = open("/dev/frdev0",O_RDWR);
    if (fd < 0)
    {
        fprintf(stderr,"Open Dev Mem0 Error!\n");
        return -1;
    }

	if(argc<=1) {
		fprintf(stderr,"%s usage: ... \n",argv[0]);
		ret=-1;
		goto end;
	}
	// fripadm 2 "192.168.31.98 "
	type=atoi(argv[1]);		
	if(type==FR_IP_IOCTL_TYPE_FIND_BYSTRINGS) {
		if(argc==3)  {
			ret=double_hash_white_find_bystrings(fd,argv[2],strlen(argv[2]));
			if(ret==1) {
				printf("%s is in the double_hash_white_table\n",argv[2]);
				ret=0;
				goto end;
			}
		}
		else {
			fprintf(stderr,"%s usage: ... \n",argv[0]);
			ret=-1;
			goto end;
		}
	}
	else if(type==FR_IP_IOCTL_TYPE_MIRROR_INSERT_BYSTRINGS) {
		if(argc==3)  {
			ret=double_hash_white_mirror_insert_bystrings(fd,argv[2],strlen(argv[2]));
			goto end;
		}
		else {
			fprintf(stderr,"%s usage: ... \n",argv[0]);
			ret=-1;
			goto end;
		}
	}
	else if(type==FR_IP_IOCTL_TYPE_MIRROR_DELETE_BYSTRINGS) {
		if(argc==3)  {
			ret=double_hash_white_mirror_delete_bystrings(fd,argv[2],strlen(argv[2]));
			goto end;
		}
		else {
			fprintf(stderr,"%s usage: ... \n",argv[0]);
			ret=-1;
			goto end;
		}
	}
	else if(type==FR_IP_IOCTL_TYPE_MIRROR_DELETE_ALL) {
		if(argc==2)  {
			ret=double_hash_white_mirror_delete_all(fd);
			goto end;
		}
		else {
			fprintf(stderr,"%s usage: ... \n",argv[0]);
			ret=-1;
			goto end;
		}
	}
	else if(type==FR_IP_IOCTL_TYPE_SWITCH_MIRROR_UPDATE) {
		if(argc==2)  {
			ret=double_hash_white_switch_mirror_update(fd);
			goto end;
		}
		else {
			fprintf(stderr,"%s usage: ... \n",argv[0]);
			ret=-1;
			goto end;
		}
	}
	else if(type==FR_IP_IOCTL_TYPE_REBUILD) {
		if(argc==4)  {
			ret=double_hash_white_rebuild(fd,(unsigned int)atoi(argv[2]),(unsigned int)atoi(argv[3]));
			goto end;
		}
		else {
			fprintf(stderr,"%s usage: ... \n",argv[0]);
			ret=-1;
			goto end;
		}
	}
	else if(type==FR_IP_IOCTL_TYPE_DUMP) {
		if(argc==2)  {
			ret=double_hash_white_dump(fd);
			goto end;
		}
		else {
			fprintf(stderr,"%s usage: ... \n",argv[0]);
			ret=-1;
			goto end;
		}
	}
	else {
		fprintf(stderr,"%s %d error: unknown type :( \n",argv[0],type);
		ret=-1;
		goto end;
	}
end:	
    close(fd);
    return ret;    
}



