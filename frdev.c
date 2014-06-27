#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <asm/io.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/ioctl.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/random.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/ip.h>

/*** platform depends ***/

/** user-define random function **/
static inline unsigned int fr_random_num() {
	return 0;
}
/** user-define malloc&free inetrface */
static inline void * fr_malloc(size_t size) {
/* random malloc */
	return kmalloc(size,GFP_KERNEL);
	//return malloc(size);
}
static inline void fr_free(void * ptr) {
/* corresponding to fr_malloc */
	kfree(ptr);
	//free(ptr);
}

static struct kmem_cache * fr_ip_hash_list_node_cache=NULL;
static struct kmem_cache * fr_ip_blur_list_node_cache=NULL;

static inline void * fr_ip_blur_list_node_malloc(size_t size) {
/* better linux slab malloc :struct fr_ip_blur_list_node */
	return kmem_cache_alloc(fr_ip_blur_list_node_cache, GFP_KERNEL);
	//return kmalloc(size,GFP_KERNEL);
	//return malloc(size);
}
static inline void fr_ip_blur_list_node_free(void * ptr) {
/* corresponding to fr_ip_blur_list_node_malloc */	
	//free(ptr);
	//kmalloc(size,GFP_KERNEL);
	//kfree(ptr);
	kmem_cache_free(fr_ip_blur_list_node_cache, ptr);
}
static inline void * fr_ip_hash_list_node_malloc(size_t size) {
/* better linux slab malloc :struct fr_ip_hash_list_node */
	//return malloc(size);
	//return kmalloc(size,GFP_KERNEL);
	//kfree(ptr);
	return kmem_cache_alloc(fr_ip_hash_list_node_cache, GFP_KERNEL);
}
static inline void fr_ip_hash_list_node_free(void * ptr) {
/* corresponding to fr_ip_hash_list_node_malloc */	
	//free(ptr);
	//kmalloc(size,GFP_KERNEL);
	//kfree(ptr);
	kmem_cache_free(fr_ip_hash_list_node_cache, ptr);
}

/***  jhash : copy from linux kernel codes' jhash.h  :-)   ***/

#define fr_jhash_mix(a, b, c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

/* The golden ration: an arbitrary value */
#define FR_JHASH_GOLDEN_RATIO	0x9e3779b9

static inline unsigned int fr_jhash_3words(unsigned int a, unsigned int b, unsigned int c, unsigned int initval)
{
	a += FR_JHASH_GOLDEN_RATIO;
	b += FR_JHASH_GOLDEN_RATIO;
	c += initval;

	fr_jhash_mix(a, b, c);

	return c;
}

static inline unsigned int fr_jhash_2words(unsigned int a, unsigned int b, unsigned int initval)
{
	return fr_jhash_3words(a, b, 0, initval);
}

static inline unsigned int fr_jhash_1word(unsigned int a, unsigned int initval)
{
	return fr_jhash_3words(a, 0, 0, initval);
}

/****** rwlock ******/
/*
struct rwlock_t_ {
	unsigned int lock;
	unsigned int payload;
};
typedef struct rwlock_t_ rwlock_t;

static inline void rwlock_init( rwlock_t * ptr ) {
	
}
*/

static inline void fr_read_lock( rwlock_t * ptr ) {
	read_lock( ptr );
}

static inline void fr_read_unlock( rwlock_t * ptr ) {
	read_unlock( ptr );
}

static inline void fr_write_lock( rwlock_t * ptr ) {
	write_lock( ptr );
}

static inline void fr_write_unlock( rwlock_t * ptr ) {
	write_unlock( ptr );
}

static unsigned long fr_write_lock_irq_flags;

static inline void fr_write_lock_atom( rwlock_t * ptr ) {
	//write_lock( ptr );
	write_lock_irqsave(ptr,fr_write_lock_irq_flags);
}

static inline void fr_write_unlock_atom( rwlock_t * ptr ) {
	//write_unlock( ptr );
	write_unlock_irqrestore(ptr,fr_write_lock_irq_flags);
}

/************/

struct fr_ip_blur_list_node {             //0                f
	struct fr_ip_blur_list_node * next;		//       1.2.3.4
	unsigned char atom0_upper_limit;        //atom0 atom1 atom2 atom3
	unsigned char atom0_lower_limit;  
	unsigned char atom1_upper_limit;
	unsigned char atom1_lower_limit;
	unsigned char atom2_upper_limit;
	unsigned char atom2_lower_limit;
	unsigned char atom3_upper_limit;
	unsigned char atom3_lower_limit;  
};

struct fr_ip_hash_list_node {
  struct fr_ip_hash_list_node * next;	 // 0                f
  unsigned int ip_hash; //here ip == ip_hash  //      1.2.3.4
};										//    unsigned int ip

struct fr_ip_hash_array {  /* core data */
	unsigned int modular;
	unsigned int (*hash_func)(unsigned int num,unsigned int initval);
	unsigned int hash_rnd;
	unsigned int ip_counter;
	unsigned int blur_ip_counter;
	unsigned int worst_load_factor;
	unsigned int worst_hash_index;
	void **      array_ptr;
	struct fr_ip_blur_list_node * blur_list_headptr;
	struct fr_ip_blur_list_node * blur_list_tailptr;
};

struct fr_ip_double_hash {
	struct fr_ip_hash_array * master_ptr;
	rwlock_t master_lock;
	struct fr_ip_hash_array * mirror_ptr;
	rwlock_t mirror_lock;
};


static void * 
fr_ip_double_hash_malloc(
	unsigned int modular,unsigned int (*hash_func)(unsigned int num,unsigned int initval),unsigned int rnd);

static unsigned int 
fr_ip_double_hash_destroy(struct fr_ip_double_hash * ptr);

static unsigned int 
fr_ip_double_hash_mirror_insert_ip(struct fr_ip_double_hash * ptr,unsigned int ip);

static unsigned int 
fr_ip_double_hash_mirror_insert_blurip_ptr(
	struct fr_ip_double_hash * ptr,struct fr_ip_blur_list_node * blurip_ptr);

static unsigned int 
fr_ip_double_hash_mirror_insert_bystrings(struct fr_ip_double_hash * ptr,char * ip_str);

static unsigned int 
fr_ip_double_hash_mirror_delete_ip(struct fr_ip_double_hash * ptr,unsigned int ip);

static unsigned int 
fr_ip_double_hash_mirror_delete_blurip_ptr(
	struct fr_ip_double_hash * ptr,struct fr_ip_blur_list_node * blurip_ptr);

static unsigned int 
fr_ip_double_hash_mirror_delete_bystrings(struct fr_ip_double_hash * ptr,char * ip_str); 

static unsigned int 
fr_ip_double_hash_mirror_delete_ip_randomly(struct fr_ip_double_hash * ptr,unsigned int num);

static unsigned int 
fr_ip_double_hash_mirror_delete_all(struct fr_ip_double_hash * ptr);

static unsigned int 
fr_ip_double_hash_switch_mirror_update(struct fr_ip_double_hash * ptr);

static unsigned int 
fr_ip_double_hash_rebuild(
	struct fr_ip_double_hash * ptr,unsigned int modular,
	unsigned int (*hash_func)(unsigned int num,unsigned int initval),unsigned int rnd);

static unsigned int 
fr_ip_double_hash_find_bool(
	struct fr_ip_double_hash * ptr,unsigned int ip);

static unsigned int 
fr_ip_double_hash_find_bystrings_bool(
	struct fr_ip_double_hash * ptr,char * ip_str);

static void * 
fr_ip_hash_array_malloc(
	unsigned int modular,unsigned int (*hash_func)(unsigned int num,unsigned int initval),unsigned int rnd);
	
static unsigned int 
fr_ip_hash_array_destroy(struct fr_ip_hash_array * ptr);

static unsigned int 
fr_ip_hash_array_insert_ip(struct fr_ip_hash_array * ptr,unsigned int ip);

static unsigned int 
fr_ip_hash_array_insert_blurip_ptr(
	struct fr_ip_hash_array * ptr,struct fr_ip_blur_list_node * blurip_ptr);

static unsigned int 
fr_ip_hash_array_delete_ip(struct fr_ip_hash_array * ptr,unsigned int ip);

static unsigned int 
fr_ip_hash_array_delete_blurip_ptr(
	struct fr_ip_hash_array * ptr,struct fr_ip_blur_list_node * blurip_ptr);

static unsigned int 
fr_ip_hash_array_delete_ip_randomly(struct fr_ip_hash_array * ptr,unsigned int num);

static unsigned int 
fr_ip_hash_array_find_ip_bystrings_bool(
	struct fr_ip_hash_array * array_ptr,char * ip_str); 

static unsigned int 
fr_ip_hash_array_find_ip_bool(
	struct fr_ip_hash_array * array_ptr,unsigned int ip);

static unsigned int 
fr_ip_hash_array_find_bool(
	struct fr_ip_hash_array * ptr,unsigned int ip);

static void * 
fr_ip_hash_array_malloc(
	unsigned int modular,unsigned int (*hash_func)(unsigned int num,unsigned int initval),unsigned int rnd) {

	struct fr_ip_hash_array * ptr;
	unsigned int i;

	if(hash_func==NULL) return NULL;
	if(modular==0) return NULL;

	ptr=(struct fr_ip_hash_array *)fr_malloc(sizeof(struct fr_ip_hash_array));
	if(ptr==NULL) return NULL;

	ptr->array_ptr=NULL;
	ptr->array_ptr=(void **)fr_malloc(modular*sizeof(void *));
	if(ptr->array_ptr==NULL) {
		fr_free(ptr);
		return NULL;
	}
	
	ptr->modular=modular;
	ptr->hash_func=hash_func;
	ptr->hash_rnd=rnd;
	ptr->ip_counter=0;
	ptr->blur_ip_counter=0;
	ptr->worst_load_factor=0;
	ptr->worst_hash_index=0;
	//ptr->array_ptr;
	ptr->blur_list_headptr=NULL;
	ptr->blur_list_tailptr=NULL;

	for(i=0;i<modular;i++)
		*(ptr->array_ptr+i)=NULL;

	return ptr;

}

static unsigned int 
fr_ip_hash_array_destroy(struct fr_ip_hash_array * array_ptr) {

	unsigned int i;
	void * next;
	void * now;	

	if(array_ptr==NULL)
		return 1;
	if(array_ptr->array_ptr==NULL)
		return 2;

	//free all ip_hash_list_nodes
	for(i=0;i<array_ptr->modular;i++) {
		next=*(array_ptr->array_ptr+i);
		while(next!=NULL) {
			now=next;
			next=(void *)(((struct fr_ip_hash_list_node *)(next))->next);
			fr_ip_hash_list_node_free(now);
		}
	}

	//free ip_hash_array array_ptr->array_ptr=fr_malloc( sizeof(void *)*modular );
	fr_free(array_ptr->array_ptr);

	//free all ip_blur_list_nodes
	next=(void *)(array_ptr->blur_list_headptr);
	while(next!=NULL) {
		now=next;
		next=(void *)(((struct fr_ip_blur_list_node *)(next))->next);
		fr_ip_blur_list_node_free(now);
	}
	
	//free struct fr_ip_hash_array 
	fr_free(array_ptr);
	
	return 0;	

}




// waiting for optimization ... if the hash effect is well,everything will be fine :) 
static unsigned int 
fr_ip_hash_array_insert_ip(struct fr_ip_hash_array * array_ptr,unsigned int ip) {

	void ** next;
	unsigned int ct;
	unsigned int index;
	
	if(array_ptr==NULL)
		return 1;
	if(array_ptr->array_ptr==NULL)
		return 2;

	//if the ip has been already saved in the hash-array ,just return 0 directly
	if(fr_ip_hash_array_find_ip_bool(array_ptr,ip))
		return 0;

	//hash key <--> hash function
	index=array_ptr->hash_func(ip,array_ptr->hash_rnd)%array_ptr->modular;
	next=array_ptr->array_ptr+index;
	ct=0;
	while(*next!=NULL) {
		ct++;
		next=(void **)(&(((struct fr_ip_hash_list_node *)(*next))->next));
	}
	
	*next=fr_ip_hash_list_node_malloc(sizeof(struct fr_ip_hash_list_node));

	if(*next!=NULL) {
		((struct fr_ip_hash_list_node *)(*next))->next=NULL;
		((struct fr_ip_hash_list_node *)(*next))->ip_hash=ip;
		array_ptr->ip_counter++;
		ct++;
		if(ct>array_ptr->worst_load_factor) {
			array_ptr->worst_hash_index=index;
			array_ptr->worst_load_factor=ct;
		}
		return 0;
	}
	else {
		return 3;
	}

}

static unsigned int 
fr_ip_hash_array_insert_blurip_ptr(	//just copy the data from the blur_ptr,not reference
	struct fr_ip_hash_array * array_ptr,struct fr_ip_blur_list_node * blur_ptr) {

	unsigned int ip;
	unsigned char * ptr;

	if(array_ptr==NULL||blur_ptr==NULL)
		return 1;
	if(array_ptr->array_ptr==NULL)
		return 2;
	
	//if the blurip has been already saved in the blurip list,just delete it directly
	//this codes waiting for optimization...
	fr_ip_hash_array_delete_blurip_ptr(array_ptr,blur_ptr);

	ptr=(unsigned char *)(&ip);
	if(
		(blur_ptr->atom0_lower_limit==blur_ptr->atom0_upper_limit)&&
		(blur_ptr->atom1_lower_limit==blur_ptr->atom1_upper_limit)&&
		(blur_ptr->atom2_lower_limit==blur_ptr->atom2_upper_limit)&&
		(blur_ptr->atom3_lower_limit==blur_ptr->atom3_upper_limit)
		) {
		*(ptr+0)=blur_ptr->atom0_lower_limit;
		*(ptr+1)=blur_ptr->atom1_lower_limit;
		*(ptr+2)=blur_ptr->atom2_lower_limit;
		*(ptr+3)=blur_ptr->atom3_lower_limit;
		return fr_ip_hash_array_insert_ip(array_ptr,ip);
	}
	else {
		ptr=(unsigned char *)fr_ip_blur_list_node_malloc(sizeof(struct fr_ip_blur_list_node));
		if(ptr==NULL) return 3;
		((struct fr_ip_blur_list_node *)(ptr))->atom0_lower_limit=blur_ptr->atom0_lower_limit;		
		((struct fr_ip_blur_list_node *)(ptr))->atom0_upper_limit=blur_ptr->atom0_upper_limit;
		((struct fr_ip_blur_list_node *)(ptr))->atom1_lower_limit=blur_ptr->atom1_lower_limit;		
		((struct fr_ip_blur_list_node *)(ptr))->atom1_upper_limit=blur_ptr->atom1_upper_limit;
		((struct fr_ip_blur_list_node *)(ptr))->atom2_lower_limit=blur_ptr->atom2_lower_limit;		
		((struct fr_ip_blur_list_node *)(ptr))->atom2_upper_limit=blur_ptr->atom2_upper_limit;
		((struct fr_ip_blur_list_node *)(ptr))->atom3_lower_limit=blur_ptr->atom3_lower_limit;		
		((struct fr_ip_blur_list_node *)(ptr))->atom3_upper_limit=blur_ptr->atom3_upper_limit;
		((struct fr_ip_blur_list_node *)(ptr))->next=NULL;
		blur_ptr=((struct fr_ip_blur_list_node *)(ptr));
		if(array_ptr->blur_list_tailptr==NULL) {
			array_ptr->blur_list_tailptr=blur_ptr;
			array_ptr->blur_list_headptr=blur_ptr;
			array_ptr->blur_ip_counter=1;
		}
		else {
			array_ptr->blur_list_tailptr->next=blur_ptr;
			array_ptr->blur_list_tailptr=blur_ptr;
			array_ptr->blur_ip_counter++;
		}
	}

	return 0;

}

static unsigned int 
fr_ip_hash_array_delete_ip(struct fr_ip_hash_array * array_ptr,unsigned int ip) {

	void ** next;
	void ** tmp;
	unsigned int index;

	if(array_ptr==NULL)
		return 1;
	if(array_ptr->array_ptr==NULL)
		return 2;

	index=array_ptr->hash_func(ip,array_ptr->hash_rnd)%array_ptr->modular;
	next=array_ptr->array_ptr+index;

	while(*next!=NULL) {
		if(((struct fr_ip_hash_list_node *)(*next))->ip_hash==ip) {
			tmp=(void **)((struct fr_ip_hash_list_node *)(*next))->next;
			fr_ip_hash_list_node_free(*next);
			*next=tmp;
			array_ptr->ip_counter--;
			if( 
				(index==array_ptr->worst_hash_index) &&
			    (array_ptr->worst_load_factor>0)
			   ) {
				array_ptr->worst_load_factor--;
			}
			return 0;
		}
		next=(void **)&(((struct fr_ip_hash_list_node *)(*next))->next);
	}

	return 3;
	
}

static unsigned int 
fr_ip_hash_array_delete_blurip_ptr(
	struct fr_ip_hash_array * array_ptr,struct fr_ip_blur_list_node * blur_ptr) {

	struct fr_ip_blur_list_node * pre;
	struct fr_ip_blur_list_node * now;
	struct fr_ip_blur_list_node * next;

	if(array_ptr==NULL||blur_ptr==NULL) {
		return 1;
	}
	if(array_ptr->array_ptr==NULL)
		return 2;

	pre=NULL;
	now=array_ptr->blur_list_headptr;

	while(now!=NULL) {
		if(
			(now->atom0_lower_limit==blur_ptr->atom0_lower_limit)&&
			(now->atom0_upper_limit==blur_ptr->atom0_upper_limit)&&
			(now->atom1_lower_limit==blur_ptr->atom1_lower_limit)&&
			(now->atom1_upper_limit==blur_ptr->atom1_upper_limit)&&
			(now->atom2_lower_limit==blur_ptr->atom2_lower_limit)&&
			(now->atom2_upper_limit==blur_ptr->atom2_upper_limit)&&
			(now->atom3_lower_limit==blur_ptr->atom3_lower_limit)&&
			(now->atom3_upper_limit==blur_ptr->atom3_upper_limit)
			) {
			next=now->next;
			array_ptr->blur_ip_counter--;
			if(array_ptr->blur_list_headptr==array_ptr->blur_list_tailptr) { // 1
				fr_ip_blur_list_node_free(now);
				array_ptr->blur_list_headptr=NULL;
				array_ptr->blur_list_tailptr=NULL;
				return 0;
			}
			else if(array_ptr->blur_list_headptr==now) { // 1 2 ...
				fr_ip_blur_list_node_free(now);
				array_ptr->blur_list_headptr=next;
				return 0;
			}
			else if(array_ptr->blur_list_tailptr==now) { // 1 2 ...
				fr_ip_blur_list_node_free(now);
				array_ptr->blur_list_tailptr=pre;
				pre->next=NULL;
				return 0;
			}
			else {
				fr_ip_blur_list_node_free(now); // 1 2 3...
				pre->next=next;
				return 0;
			}
		}
		pre=now;
		now=now->next;
	}

	return 3;
	
}

//ret : how many ip been deleted actually
static unsigned int 
fr_ip_hash_array_delete_ip_randomly(struct fr_ip_hash_array * array_ptr,unsigned int num) {

	unsigned int i;
	unsigned int counter;
	unsigned int gap;
	void * next;
	void * now;	

	if(array_ptr==NULL)
		return 0;
	if(array_ptr->array_ptr==NULL)
		return 0;
	if(array_ptr->ip_counter==0)
		return 0;

	if(num>array_ptr->ip_counter)
		num=array_ptr->ip_counter;
	if(num==0)
		return 0;

	counter=0;
	gap=fr_random_num()%array_ptr->modular;
	
	for(i=gap;i<array_ptr->modular;i++) {
		next=*(array_ptr->array_ptr+i);
		while(next!=NULL) {
			now=next;
			next=((struct fr_ip_hash_list_node *)(next))->next;
			fr_ip_hash_list_node_free(now);
			if( 
				(i==array_ptr->worst_hash_index) &&
			    (array_ptr->worst_load_factor>0)
			   ) {
				array_ptr->worst_load_factor--;
			}
			num--;
			counter++;
			if(num==0) {
				*(array_ptr->array_ptr+i)=next;
				goto END;
			}
			if(next==NULL)
				*(array_ptr->array_ptr+i)=NULL;
		}
	}
	if(num!=0)
		for(i=0;i<gap;i++) {
			next=*(array_ptr->array_ptr+i);
			while(next!=NULL) {
				now=next;
				next=((struct fr_ip_hash_list_node *)(next))->next;
				fr_ip_hash_list_node_free(now);
				if( 
					(i==array_ptr->worst_hash_index) &&
			    	(array_ptr->worst_load_factor>0)
			   	   ) {
					array_ptr->worst_load_factor--;
				}
				num--;
				counter++;
				if(num==0) {
					*(array_ptr->array_ptr+i)=next;
					goto END;
				}
				if(next==NULL)
				*(array_ptr->array_ptr+i)=NULL;
			}
		}
		
	//return counter;
	END:
		array_ptr->ip_counter=array_ptr->ip_counter-counter;
		return counter;

}


static unsigned int 
fr_ip_hash_array_find_ip_bool(
	struct fr_ip_hash_array * array_ptr,unsigned int ip) {

	void * next;
	unsigned char * iptr;
	
	if(array_ptr==NULL)
		return 0;
	if(array_ptr->array_ptr==NULL)
		return 0;

	//blur ip check
	/*
	iptr=(unsigned char *)(&ip);
	next=array_ptr->blur_list_headptr;
	while(next!=NULL) {
		if( (*(iptr+0)<=((struct fr_ip_blur_list_node *)next)->atom0_upper_limit) &&
			(*(iptr+0)>=((struct fr_ip_blur_list_node *)next)->atom0_lower_limit) &&
			(*(iptr+1)<=((struct fr_ip_blur_list_node *)next)->atom1_upper_limit) &&
			(*(iptr+1)>=((struct fr_ip_blur_list_node *)next)->atom1_lower_limit) &&
			(*(iptr+2)<=((struct fr_ip_blur_list_node *)next)->atom2_upper_limit) &&
			(*(iptr+2)>=((struct fr_ip_blur_list_node *)next)->atom2_lower_limit) &&
			(*(iptr+3)<=((struct fr_ip_blur_list_node *)next)->atom3_upper_limit) &&
			(*(iptr+3)>=((struct fr_ip_blur_list_node *)next)->atom3_lower_limit) 
			) {
			return 1;
		}
		next=(void *)((struct fr_ip_blur_list_node *)next)->next;
	}
	*/
	//ip check
	next=*(array_ptr->array_ptr+(array_ptr->hash_func(ip,array_ptr->hash_rnd)%array_ptr->modular));
	while(next!=NULL) {
		if(((struct fr_ip_hash_list_node *)(next))->ip_hash==ip) 
			return 1;
		next=(void *)(((struct fr_ip_hash_list_node *)(next))->next);
	}

	return 0;
		
}


static unsigned int 
fr_ip_hash_array_find_bool(
	struct fr_ip_hash_array * array_ptr,unsigned int ip) {

	void * next;
	unsigned char * iptr;
	
	if(array_ptr==NULL)
		return 0;
	if(array_ptr->array_ptr==NULL)
		return 0;

	//blur ip check
	iptr=(unsigned char *)(&ip);
	next=array_ptr->blur_list_headptr;
	while(next!=NULL) {
		if( (*(iptr+0)<=((struct fr_ip_blur_list_node *)next)->atom0_upper_limit) &&
			(*(iptr+0)>=((struct fr_ip_blur_list_node *)next)->atom0_lower_limit) &&
			(*(iptr+1)<=((struct fr_ip_blur_list_node *)next)->atom1_upper_limit) &&
			(*(iptr+1)>=((struct fr_ip_blur_list_node *)next)->atom1_lower_limit) &&
			(*(iptr+2)<=((struct fr_ip_blur_list_node *)next)->atom2_upper_limit) &&
			(*(iptr+2)>=((struct fr_ip_blur_list_node *)next)->atom2_lower_limit) &&
			(*(iptr+3)<=((struct fr_ip_blur_list_node *)next)->atom3_upper_limit) &&
			(*(iptr+3)>=((struct fr_ip_blur_list_node *)next)->atom3_lower_limit) 
			) {
			return 1;
		}
		next=(void *)((struct fr_ip_blur_list_node *)next)->next;
	}

	//ip check
	next=*(array_ptr->array_ptr+(array_ptr->hash_func(ip,array_ptr->hash_rnd)%array_ptr->modular));
	while(next!=NULL) {
		if(((struct fr_ip_hash_list_node *)(next))->ip_hash==ip) 
			return 1;
		next=(void *)(((struct fr_ip_hash_list_node *)(next))->next);
	}

	return 0;
		
}



/* blur_ip_syntax : RE 
digit  =: [0-9]
num  =: (digit){1,3}
atom =: num | (num'-'num) | '*'
ip      =: atom '.' atom '.' atom '.' atom
ips    =: (ip ' ')+
*/
// 1-220.*.100.33

static unsigned char fr_ip_blur_parse_str_head_u8(char * str) {
//   012.
	unsigned char ch0,ch1,ch2;
	if(str==NULL)
		return 0;
	if((str[0]>='0')&&(str[0]<='9')) {
		ch0=str[0]-'0';
		if((str[1]>='0')&&(str[1]<='9')) {
			ch1=str[1]-'0';
			if((str[2]>='0')&&(str[2]<='9')) {
				ch2=str[2]-'0';
				return (ch0*100+ch1*10+ch2);
			}
			else return (ch0*10+ch1);
		}
		else return ch0;
	}
	else return 0;
}

/* blur_ip_syntax : RE 
digit  =: [0-9]
num  =: (digit){1,3}
atom =: num | (num'-'num) | '*'
ip      =: atom '.' atom '.' atom '.' atom
ips    =: (ip ' ')+
*/
static inline int fr_ip_blur_parse_char_check_bool(char ch) {
	if(
		(ch>='0' && ch<='9' ) ||
		(ch=='-') || (ch=='.')||
		(ch=='*')
		)
		return 1;
	else
		return 0;
}

/* blur_ip_syntax : RE 
digit  =: [0-9]
num  =: (digit){1,3}
atom =: num | (num'-'num) | '*'
ip      =: atom '.' atom '.' atom '.' atom 
ips    =: (ip ' ')+
*/
//ret: 0 success , otherwise syntax error :(
// 1-220.*.100.33
static unsigned int fr_ip_blur_parse_atom
	(char * str,unsigned char * ip_upper,unsigned char * ip_lower) {
// syntax error detection here hasn't been taken very seriously,so that our function could be faster :)
// please be little careful with your input str 

	unsigned char i;
	
	if(str==NULL||ip_upper==NULL||ip_lower==NULL)
		return 1;

	if(str[0]=='*') {
		*ip_upper=255;
		*ip_lower=0;
		return 0;
	}
	else if((str[0]>='0')&&(str[0]<='9')) {
		*ip_lower=fr_ip_blur_parse_str_head_u8(str);
		i=(*ip_lower>99)?(3):((*ip_lower>9)?2:1);
		if(  str[i]=='-'  ) {
			*ip_upper=fr_ip_blur_parse_str_head_u8(&str[i+1]);
			if(*ip_upper<*ip_lower) {
				i=*ip_upper;
				*ip_upper=*ip_lower;
				*ip_lower=i;
			}
			return 0;
		}
		else {
		*ip_upper=*ip_lower;
		return 0;
		}
	}
	else
		return 2;
		
}

/* blur_ip_syntax : RE 
digit  =: [0-9]
num  =: (digit){1,3}
atom =: num | (num'-'num) | '*'
ip      =: atom '.' atom '.' atom '.' atom 
ips    =: (ip ' ')+
*/
// ret 0 success,otherwise syntax error
// "1-220.*.100.33"
static unsigned int fr_ip_blur_parse_ip
	(char * str,struct fr_ip_blur_list_node * blur_ptr,unsigned int * lenptr) {

	unsigned int i;
	unsigned int j;
	char ch;
	char dot_ct;

	if(str==NULL||blur_ptr==NULL||lenptr==NULL) {
		return 1;
	}

	i=0;
	j=0;
	dot_ct=0;
	while(1) {		// "1-220.*.100.33 "
		ch=str[i];
		if(fr_ip_blur_parse_char_check_bool(ch)) {
			i++;
			if(ch=='.') {
				dot_ct++;
				if(dot_ct==1) {
					if( 
						fr_ip_blur_parse_atom(&str[j],
						&(blur_ptr->atom0_upper_limit),
						&(blur_ptr->atom0_lower_limit))
						)
						return 2;
				}
				else if(dot_ct==2) {
					if( 
						fr_ip_blur_parse_atom(&str[j],
						&(blur_ptr->atom1_upper_limit),
						&(blur_ptr->atom1_lower_limit))
						)
						return 3;
				}
				else if(dot_ct==3) {
					if( 
						fr_ip_blur_parse_atom(&str[j],
						&(blur_ptr->atom2_upper_limit),
						&(blur_ptr->atom2_lower_limit))
						)
						return 4;
				}
				else	return 5;
				j=i;
			}
		}
		else {
			if(dot_ct==3) {
				if( 
					fr_ip_blur_parse_atom(&str[j],
					&(blur_ptr->atom3_upper_limit),
					&(blur_ptr->atom3_lower_limit))
					)
					return 4;
				blur_ptr->next=NULL;
				*lenptr=i;
				return 0;
			}
			else return 6;
		}
	}
	
	return 7;
	
}

/* blur_ip_syntax : RE 
digit  =: [0-9]
num  =: (digit){1,3}
atom =: num | (num'-'num) | '*'
ip      =: atom '.' atom '.' atom '.' atom 
ips    =: (ip ' ')+
*/
// ret 0 success,otherwise syntax error
// "1-220.*.100.33 1-220.*.100.33 1-220.*.100.33"
static unsigned int fr_ip_blur_parse_ips
	(char * str,struct fr_ip_blur_list_node * blur_ptr) {

	unsigned int len;
	
	if(str==NULL||blur_ptr==NULL) {
		return 1;
	}

	len=0;
	while(1) {
		if(fr_ip_blur_parse_ip(str=str+len,blur_ptr,&len)) {//fail
			return 1;
		}
		/* for debug
		printf("next:%d\n",blur_ptr->next);
		printf("len:%d\n",len);
		printf("atom0_lower_limit:%d\n",blur_ptr->atom0_lower_limit);
		printf("atom0_upper_limit:%d\n",blur_ptr->atom0_upper_limit);
		printf("atom1_lower_limit:%d\n",blur_ptr->atom1_lower_limit);
		printf("atom1_upper_limit:%d\n",blur_ptr->atom1_upper_limit);
		printf("atom2_lower_limit:%d\n",blur_ptr->atom2_lower_limit);
		printf("atom2_upper_limit:%d\n",blur_ptr->atom2_upper_limit);
		printf("atom3_lower_limit:%d\n",blur_ptr->atom3_lower_limit);
		printf("atom3_upper_limit:%d\n",blur_ptr->atom3_upper_limit);
		*/
		if(str[len]==NULL) {
			return 0;
		}
		len++;
		if(str[len]==NULL) {
			return 0;
		}
	}
	
}

static unsigned int fr_ip_hash_array_insert_ip_bystrings(
	struct fr_ip_hash_array * array_ptr,char * ip_str) { ///* ip string like:'12.*.2-200.32 1.23.4.5 '*/

	struct fr_ip_blur_list_node * blur_ptr;
	unsigned int ip;
	unsigned char * ptr;
	unsigned int len;
	
	if(array_ptr==NULL||ip_str==NULL)
		return 1;
	if(array_ptr->array_ptr==NULL)
		return 2;

	ptr=(unsigned char *)(&ip);
	len=0;
	blur_ptr=NULL;
	while(1) {
		if(blur_ptr==NULL)
			blur_ptr= (struct fr_ip_blur_list_node * )
				fr_ip_blur_list_node_malloc( sizeof(struct fr_ip_blur_list_node ) );
		if(blur_ptr==NULL)
			return 3;
		if(ip_str[len]==NULL) {
			fr_ip_blur_list_node_free(blur_ptr);
			return 0;
		}
		if(fr_ip_blur_parse_ip(ip_str=ip_str+len,blur_ptr,&len)) {//fail
			fr_ip_blur_list_node_free(blur_ptr);
			return 4;
		}
		//refresh ip_hash table
		if(
			(blur_ptr->atom0_lower_limit==blur_ptr->atom0_upper_limit)&&
			(blur_ptr->atom1_lower_limit==blur_ptr->atom1_upper_limit)&&
			(blur_ptr->atom2_lower_limit==blur_ptr->atom2_upper_limit)&&
			(blur_ptr->atom3_lower_limit==blur_ptr->atom3_upper_limit)
			) {
			*(ptr+0)=blur_ptr->atom0_lower_limit;
			*(ptr+1)=blur_ptr->atom1_lower_limit;
			*(ptr+2)=blur_ptr->atom2_lower_limit;
			*(ptr+3)=blur_ptr->atom3_lower_limit;
			if(fr_ip_hash_array_insert_ip(array_ptr,ip)) {//fail
				fr_ip_blur_list_node_free(blur_ptr);
				return 5;
			}
		}
		else {
			fr_ip_hash_array_delete_blurip_ptr(array_ptr,blur_ptr);
			if(array_ptr->blur_list_tailptr==NULL) {
				blur_ptr->next=NULL;
				array_ptr->blur_list_tailptr=blur_ptr;
				array_ptr->blur_list_headptr=blur_ptr;
				array_ptr->blur_ip_counter=1;
				blur_ptr=NULL;
			}
			else {
				blur_ptr->next=NULL;
				array_ptr->blur_list_tailptr->next=blur_ptr;
				array_ptr->blur_list_tailptr=blur_ptr;
				array_ptr->blur_ip_counter++;
				blur_ptr=NULL;
			}
		}
		
		if(ip_str[len]==NULL) {
			if(blur_ptr) fr_ip_blur_list_node_free(blur_ptr);
			return 0;
		}
		len++;
		if(ip_str[len]==NULL) {
			if(blur_ptr) fr_ip_blur_list_node_free(blur_ptr);
			return 0;
		}
	}

	return 7;	
}

static unsigned int fr_ip_hash_array_delete_ip_bystrings(
	struct fr_ip_hash_array * array_ptr,char * ip_str) {

	struct fr_ip_blur_list_node * blur_ptr;
	unsigned int ip;
	unsigned char * ptr;
	unsigned int len;
	
	if(array_ptr==NULL||ip_str==NULL)
		return 1;
	if(array_ptr->array_ptr==NULL)
		return 2;

	ptr=(unsigned char *)&ip;
	len=0;
	blur_ptr=NULL;
	while(1) {
		if(blur_ptr==NULL)
			blur_ptr= (struct fr_ip_blur_list_node * )
				fr_ip_blur_list_node_malloc( sizeof(struct fr_ip_blur_list_node ) );
		if(blur_ptr==NULL)
			return 3;
		if(ip_str[len]==NULL) {
			fr_ip_blur_list_node_free(blur_ptr);
			return 0;
		}
		if(fr_ip_blur_parse_ip(ip_str=ip_str+len,blur_ptr,&len)) {//fail
			fr_ip_blur_list_node_free(blur_ptr);
			return 4;
		}
		//refresh ip_hash table
		if(
			(blur_ptr->atom0_lower_limit==blur_ptr->atom0_upper_limit)&&
			(blur_ptr->atom1_lower_limit==blur_ptr->atom1_upper_limit)&&
			(blur_ptr->atom2_lower_limit==blur_ptr->atom2_upper_limit)&&
			(blur_ptr->atom3_lower_limit==blur_ptr->atom3_upper_limit)
			) {
			*(ptr+0)=blur_ptr->atom0_lower_limit;
			*(ptr+1)=blur_ptr->atom1_lower_limit;
			*(ptr+2)=blur_ptr->atom2_lower_limit;
			*(ptr+3)=blur_ptr->atom3_lower_limit;
			fr_ip_hash_array_delete_ip(array_ptr,ip);
		}
		else {
			fr_ip_hash_array_delete_blurip_ptr(array_ptr,blur_ptr);
		}
		
		if(ip_str[len]==NULL) {
			fr_ip_blur_list_node_free(blur_ptr);
			return 0;
		}
		len++;
		if(ip_str[len]==NULL) {
			fr_ip_blur_list_node_free(blur_ptr);
			return 0;
		}
	}

	return 7;
	
}


static unsigned int fr_ip_hash_array_find_ip_bystrings_bool(
	struct fr_ip_hash_array * array_ptr,char * ip_str) { ///* ip string like:'1.23.4.5 ' */

	struct fr_ip_blur_list_node * blur_ptr;
	unsigned int ip;
	unsigned char * ptr;
	unsigned int len;
	
	if(array_ptr==NULL||ip_str==NULL)
		return 0;
	if(array_ptr->array_ptr==NULL)
		return 0;

	ptr=(unsigned char *)(&ip);
	len=0;
	blur_ptr=NULL;
	while(1) {
		if(blur_ptr==NULL)
			blur_ptr= (struct fr_ip_blur_list_node * )
				fr_ip_blur_list_node_malloc( sizeof(struct fr_ip_blur_list_node ) );
		if(blur_ptr==NULL)
			return 0;
		if(ip_str[len]==NULL) {
			fr_ip_blur_list_node_free(blur_ptr);
			return 0;
		}
		if(fr_ip_blur_parse_ip(ip_str=ip_str+len,blur_ptr,&len)) {//fail
			fr_ip_blur_list_node_free(blur_ptr);
			return 0;
		}
		if(
			(blur_ptr->atom0_lower_limit==blur_ptr->atom0_upper_limit)&&
			(blur_ptr->atom1_lower_limit==blur_ptr->atom1_upper_limit)&&
			(blur_ptr->atom2_lower_limit==blur_ptr->atom2_upper_limit)&&
			(blur_ptr->atom3_lower_limit==blur_ptr->atom3_upper_limit)
			) {
			*(ptr+0)=blur_ptr->atom0_lower_limit;
			*(ptr+1)=blur_ptr->atom1_lower_limit;
			*(ptr+2)=blur_ptr->atom2_lower_limit;
			*(ptr+3)=blur_ptr->atom3_lower_limit;
			// :)
			fr_ip_blur_list_node_free(blur_ptr);
			return fr_ip_hash_array_find_bool(array_ptr,ip);
		}
		else {
			fr_ip_blur_list_node_free(blur_ptr);
			return 0;
		}
	}

	return 0;	
}



static void * 
fr_ip_double_hash_malloc(
	unsigned int modular,unsigned int (*hash_func)(unsigned int num,unsigned int initval),unsigned int rnd) {

	struct fr_ip_double_hash * dhptr;

	if(hash_func==NULL) return NULL;
	if(modular==0) return NULL;
	
	dhptr=(struct fr_ip_double_hash *)fr_malloc(sizeof(struct fr_ip_double_hash));
	if(dhptr==NULL) return NULL;
	dhptr->master_ptr=NULL;
	dhptr->mirror_ptr=NULL;

	dhptr->master_ptr=(struct fr_ip_hash_array *)fr_ip_hash_array_malloc(modular,hash_func,rnd);
	if(dhptr->master_ptr==NULL) {
		fr_free(dhptr);
		return NULL;
	}

	dhptr->mirror_ptr=(struct fr_ip_hash_array *)fr_ip_hash_array_malloc(modular,hash_func,rnd);
	if(dhptr->mirror_ptr==NULL) {
		fr_ip_hash_array_destroy(dhptr->master_ptr);
		fr_free(dhptr);
		return NULL;
	}

	if(dhptr) {
		rwlock_init(&dhptr->master_lock);
		rwlock_init(&dhptr->mirror_lock);
	}

	return dhptr;
	
}

//ret 0 :)
//else :(
// not lock yet
//asume that nobody is accessing the ptr->struct
static unsigned int 
fr_ip_double_hash_destroy(struct fr_ip_double_hash * ptr) {
	
	if(ptr==NULL) return 1;

	if(ptr->master_ptr!=NULL)
		fr_ip_hash_array_destroy(ptr->master_ptr);
	if(ptr->mirror_ptr!=NULL)
		fr_ip_hash_array_destroy(ptr->mirror_ptr);

	fr_free(ptr);

	return 0;

}

static unsigned int 
fr_ip_double_hash_mirror_insert_ip(struct fr_ip_double_hash * ptr,unsigned int ip) {

	unsigned int ret;

	if(ptr==NULL) return 1;
	//if(ptr->master_ptr==NULL||ptr->mirror_ptr==NULL) return 2;

	fr_write_lock(&ptr->mirror_lock);
	ret=fr_ip_hash_array_insert_ip(ptr->mirror_ptr,ip);
	fr_write_unlock(&ptr->mirror_lock);

	return ret;
}

static unsigned int 
fr_ip_double_hash_mirror_insert_blurip_ptr(
	struct fr_ip_double_hash * ptr,struct fr_ip_blur_list_node * blurip_ptr) {

	unsigned int ret;

	if(ptr==NULL||blurip_ptr==NULL) return 1;
	//if(ptr->master_ptr==NULL||ptr->mirror_ptr==NULL) return 2;

	fr_write_lock(&ptr->mirror_lock);
	ret=fr_ip_hash_array_insert_blurip_ptr(ptr->mirror_ptr,blurip_ptr);
	fr_write_unlock(&ptr->mirror_lock);

	return ret;
}

static unsigned int 
fr_ip_double_hash_mirror_insert_bystrings(struct fr_ip_double_hash * ptr,char * ip_str) {

	unsigned int ret;

	if(ptr==NULL||ip_str==NULL) return 1;
	//if(ptr->master_ptr==NULL||ptr->mirror_ptr==NULL) return 2;

	fr_write_lock(&ptr->mirror_lock);
	ret=fr_ip_hash_array_insert_ip_bystrings(ptr->mirror_ptr,ip_str);
	fr_write_unlock(&ptr->mirror_lock);

	return ret;
}


static unsigned int 
fr_ip_double_hash_mirror_delete_ip(struct fr_ip_double_hash * ptr,unsigned int ip) {

	unsigned int ret;

	if(ptr==NULL) return 1;
	//if(ptr->master_ptr==NULL||ptr->mirror_ptr==NULL) return 2;

	fr_write_lock(&ptr->mirror_lock);
	ret=fr_ip_hash_array_delete_ip(ptr->mirror_ptr,ip);
	fr_write_unlock(&ptr->mirror_lock);

	return ret;
}

static unsigned int 
fr_ip_double_hash_mirror_delete_blurip_ptr(
	struct fr_ip_double_hash * ptr,struct fr_ip_blur_list_node * blurip_ptr) {

	unsigned int ret;

	if(ptr==NULL||blurip_ptr==NULL) return 1;
	//if(ptr->master_ptr==NULL||ptr->mirror_ptr==NULL) return 2;

	fr_write_lock(&ptr->mirror_lock);
	ret=fr_ip_hash_array_delete_blurip_ptr(ptr->mirror_ptr,blurip_ptr);
	fr_write_unlock(&ptr->mirror_lock);

	return ret;
}

static unsigned int 
fr_ip_double_hash_mirror_delete_bystrings(struct fr_ip_double_hash * ptr,char * ip_str) {

	unsigned int ret;

	if(ptr==NULL||ip_str==NULL) return 1;
	//if(ptr->master_ptr==NULL||ptr->mirror_ptr==NULL) return 2;

	fr_write_lock(&ptr->mirror_lock);
	ret=fr_ip_hash_array_delete_ip_bystrings(ptr->mirror_ptr,ip_str);
	fr_write_unlock(&ptr->mirror_lock);

	return ret;
}


//ret : how many ip deleted actually
static unsigned int 
fr_ip_double_hash_mirror_delete_ip_randomly(struct fr_ip_double_hash * ptr,unsigned int num) {

	unsigned int ret;

	if(ptr==NULL) return 0;
	//if(ptr->master_ptr==NULL||ptr->mirror_ptr==NULL) return 0;

	
	fr_write_lock(&ptr->mirror_lock);
	ret=fr_ip_hash_array_delete_ip_randomly(ptr->mirror_ptr,num);	
	fr_write_unlock(&ptr->mirror_lock);

	return ret;
}

static unsigned int 
fr_ip_double_hash_mirror_delete_all(struct fr_ip_double_hash * ptr) {

	void * haptr;
	struct fr_ip_hash_list_node * next;
	unsigned int i;

	if(ptr==NULL) return 1;
	//if(ptr->master_ptr==NULL||ptr->mirror_ptr==NULL) return 2;

	fr_write_lock(&ptr->mirror_lock); // -->
//	if(ptr->mirror_ptr==NULL) return 2;
	ptr->mirror_ptr->ip_counter=0;
	ptr->mirror_ptr->worst_hash_index=0;
	ptr->mirror_ptr->worst_load_factor=0;
	for(i=0;i<ptr->mirror_ptr->modular;i++) {
		//release all mirror's nodes in this bucket
		haptr=*(ptr->mirror_ptr->array_ptr+i);
		while(haptr) {
			next=((struct fr_ip_hash_list_node *)haptr)->next;
			fr_ip_hash_list_node_free(haptr);
			haptr=(void *)next;
		}
		*(ptr->mirror_ptr->array_ptr+i)=NULL;
	}
	//release all mirror's blurip nodes
	haptr=(void *)(ptr->mirror_ptr->blur_list_headptr);
	while(haptr) {
		next=(struct fr_ip_hash_list_node * )(((struct fr_ip_blur_list_node *)(haptr))->next);
		fr_ip_blur_list_node_free(haptr);
		haptr=(void *)next;
	}
	ptr->mirror_ptr->blur_list_headptr=NULL;
	ptr->mirror_ptr->blur_list_tailptr=NULL;
	ptr->mirror_ptr->blur_ip_counter=0;	
	fr_write_unlock(&ptr->mirror_lock); // -->

	return 0;
}

static unsigned int 
fr_ip_double_hash_switch_mirror_update(struct fr_ip_double_hash * ptr) {

	void * haptr;
	struct fr_ip_hash_list_node * next;
	unsigned int i;
	unsigned int ret;

	if(ptr==NULL) return 1;
	//if(ptr->master_ptr==NULL||ptr->mirror_ptr==NULL) return 2;
	//if(ptr->master_ptr->array_ptr==NULL||ptr->mirror_ptr->array_ptr==NULL) return 3;
	
	//switch 
	//get write lock
	fr_write_lock(&ptr->mirror_lock);
	fr_write_lock_atom(&ptr->master_lock);
	haptr= (void *) ptr->master_ptr;
	ptr->master_ptr=ptr->mirror_ptr;
	ptr->mirror_ptr= (struct fr_ip_hash_array *) haptr;
	fr_write_unlock_atom(&ptr->master_lock);
	//release write lock

	//update mirror
	//get read lock
	fr_read_lock(&ptr->master_lock);
	ptr->mirror_ptr->ip_counter=0;
	ptr->mirror_ptr->worst_hash_index=0;
	ptr->mirror_ptr->worst_load_factor=0;
	for(i=0;i<ptr->master_ptr->modular;i++) {
		if( *(ptr->master_ptr->array_ptr+i) ) {
			//release all mirror's nodes in this bucket
			haptr=*(ptr->mirror_ptr->array_ptr+i);
			while(haptr) {
				next=((struct fr_ip_hash_list_node *)haptr)->next;
				fr_ip_hash_list_node_free(haptr);
				haptr=(void *)next;
			}
			*(ptr->mirror_ptr->array_ptr+i)=NULL;
			//copy master's nodes to mirror
			haptr=*(ptr->master_ptr->array_ptr+i);
			while(haptr) {
				ret=fr_ip_hash_array_insert_ip(ptr->mirror_ptr,((struct fr_ip_hash_list_node *)haptr)->ip_hash);
				if(ret) return ret+5;
				haptr=((struct fr_ip_hash_list_node *)haptr)->next;
			}
		}
		else {
			//release all mirror's nodes in this bucket
			haptr=*(ptr->mirror_ptr->array_ptr+i);
			while(haptr) {
				next=((struct fr_ip_hash_list_node *)haptr)->next;
				fr_ip_hash_list_node_free(haptr);
				haptr=(void *)next;
			}
			*(ptr->mirror_ptr->array_ptr+i)=NULL;
		}
	}
	//release all mirror's blurip nodes
	haptr=(void *)(ptr->mirror_ptr->blur_list_headptr);
	while(haptr) {
		next=(struct fr_ip_hash_list_node * )(((struct fr_ip_blur_list_node *)(haptr))->next);
		fr_ip_blur_list_node_free(haptr);
		haptr=(void *)next;
	}
	ptr->mirror_ptr->blur_list_headptr=NULL;
	ptr->mirror_ptr->blur_list_tailptr=NULL;
	ptr->mirror_ptr->blur_ip_counter=0;
	//copy master's nodes to mirror
	haptr=(void *)(ptr->master_ptr->blur_list_headptr);
	while(haptr) {
		ret=fr_ip_hash_array_insert_blurip_ptr(ptr->mirror_ptr,(struct fr_ip_blur_list_node *)haptr);
		if(ret) return ret+10;
		haptr=(void *)(((struct fr_ip_blur_list_node *)(haptr))->next);
	}
	//release read lock
	fr_read_unlock(&ptr->master_lock);
	fr_write_unlock(&ptr->mirror_lock);
	return 0;
}

static unsigned int 
fr_ip_double_hash_rebuild(
	struct fr_ip_double_hash * ptr,unsigned int modular,
	unsigned int (*hash_func)(unsigned int num,unsigned int initval),unsigned int rnd) {

	void * haptr;
	unsigned int i;
	unsigned int ret;

	if(ptr==NULL||hash_func==NULL) return 1;
	//if(ptr->master_ptr==NULL||ptr->mirror_ptr==NULL) return 2;
	if(modular==0) return 3;

	//update new mirror from master hash
	haptr=fr_ip_hash_array_malloc(modular,hash_func,rnd);
	if(haptr==NULL) return 1;
	fr_write_lock(&ptr->mirror_lock);  //-->
	fr_read_lock(&ptr->master_lock);   // -->
	fr_ip_hash_array_destroy(ptr->mirror_ptr);
	ptr->mirror_ptr=(struct fr_ip_hash_array *)haptr;
	//copy master's nodes to mirror
	for(i=0;i<ptr->master_ptr->modular;i++) {
		haptr=*(ptr->master_ptr->array_ptr+i);
		while(haptr) {
			ret=fr_ip_hash_array_insert_ip(ptr->mirror_ptr,((struct fr_ip_hash_list_node *)haptr)->ip_hash);
			if(ret) return ret+5;
			haptr=((struct fr_ip_hash_list_node *)haptr)->next;
		}
	}
	haptr=(void *)(ptr->master_ptr->blur_list_headptr);
	while(haptr) {
		ret=fr_ip_hash_array_insert_blurip_ptr(ptr->mirror_ptr,(struct fr_ip_blur_list_node *)haptr);
		if(ret) return ret+10;
		haptr=(void *)(((struct fr_ip_blur_list_node *)(haptr))->next);
	}
	fr_read_unlock(&ptr->master_lock);   // -->
	//switch 
	//get write lock
	fr_write_lock_atom(&ptr->master_lock); //-->
	haptr= (void *) ptr->master_ptr;
	ptr->master_ptr=ptr->mirror_ptr;
	ptr->mirror_ptr= (struct fr_ip_hash_array *) haptr;
	fr_write_unlock_atom(&ptr->master_lock); //-->
	//release write lock

	//update mirror from master 
	haptr=fr_ip_hash_array_malloc(modular,hash_func,rnd);
	if(haptr==NULL) return 2;
	fr_ip_hash_array_destroy(ptr->mirror_ptr);
	ptr->mirror_ptr=(struct fr_ip_hash_array *)haptr;
	fr_read_lock(&ptr->master_lock);   // -->
	for(i=0;i<ptr->master_ptr->modular;i++) {
		//copy master's nodes to mirror
		haptr=*(ptr->master_ptr->array_ptr+i);
		while(haptr) {
			ret=fr_ip_hash_array_insert_ip(ptr->mirror_ptr,((struct fr_ip_hash_list_node *)haptr)->ip_hash);
			if(ret) return ret+15;
			haptr=((struct fr_ip_hash_list_node *)haptr)->next;
		}
	}
	haptr=(void *)(ptr->master_ptr->blur_list_headptr);
	while(haptr) {
		ret=fr_ip_hash_array_insert_blurip_ptr(ptr->mirror_ptr,(struct fr_ip_blur_list_node *)haptr);
		if(ret) return ret+20;
		haptr=(void *)(((struct fr_ip_blur_list_node *)(haptr))->next);
	}
	fr_read_unlock(&ptr->master_lock);   // -->
	fr_write_unlock(&ptr->mirror_lock);  // -->
	return 0;

}

static unsigned int 
fr_ip_double_hash_find_bool(
	struct fr_ip_double_hash * ptr,unsigned int ip) {

	unsigned int ret;

	if(ptr==NULL) return 0;
	//if(ptr->master_ptr==NULL||ptr->mirror_ptr==NULL) return 0;

	fr_read_lock(&ptr->master_lock);   // -->
	ret=fr_ip_hash_array_find_bool(ptr->master_ptr,ip);
	fr_read_unlock(&ptr->master_lock);   // -->

	return ret;
}

static unsigned int 
fr_ip_double_hash_find_bystrings_bool(
	struct fr_ip_double_hash * ptr,char * ip_str) {

	unsigned int ret;
	
	if(ptr==NULL) return 0;
	//if(ptr->master_ptr==NULL||ptr->mirror_ptr==NULL) return 0;

	fr_read_lock(&ptr->master_lock);   // -->
	ret=fr_ip_hash_array_find_ip_bystrings_bool(ptr->master_ptr,ip_str);
	fr_read_unlock(&ptr->master_lock);   // -->

	return ret;
}


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

static int fr_ip_mem_major = FR_IP_MEMDEV_MAJOR;
static int fr_ip_mem_share;
static struct fr_ip_mem_dev *fr_ip_mem_devp; 
static struct cdev fr_ip_cdev; 
static struct fr_ip_ioctl_para_t fr_ip_ioctl_para;

static struct fr_ip_double_hash * double_hash_ptr=NULL;
static struct fr_ip_double_hash * double_hash_white_ptr=NULL;
static spinlock_t frdev_ioctl_spinlock; 

void fr_ip_print_blurip_ptr(struct fr_ip_blur_list_node * blptr) {

	if(blptr==NULL) {
		printk("print_blurip_ptr error: input is null\n");
	}

	if(blptr->atom0_lower_limit==blptr->atom0_upper_limit) 
		printk("%d",blptr->atom0_lower_limit);
	else if((blptr->atom0_lower_limit==0)&&(blptr->atom0_upper_limit==255)) 
		printk("*");
	else if((blptr->atom0_lower_limit==255)&&(blptr->atom0_upper_limit==0)) 
		printk("*");
	else if(blptr->atom0_lower_limit<blptr->atom0_upper_limit) 
		printk("%d-%d",blptr->atom0_lower_limit,blptr->atom0_upper_limit);
	else 
		printk("%d-%d",blptr->atom0_upper_limit,blptr->atom0_lower_limit);

	printk(".");

	if(blptr->atom1_lower_limit==blptr->atom1_upper_limit) 
		printk("%d",blptr->atom1_lower_limit);
	else if((blptr->atom1_lower_limit==0)&&(blptr->atom1_upper_limit==255)) 
		printk("*");
	else if((blptr->atom1_lower_limit==255)&&(blptr->atom1_upper_limit==0)) 
		printk("*");
	else if(blptr->atom1_lower_limit<blptr->atom1_upper_limit) 
		printk("%d-%d",blptr->atom1_lower_limit,blptr->atom1_upper_limit);
	else 
		printk("%d-%d",blptr->atom1_upper_limit,blptr->atom1_lower_limit);

	printk(".");

	if(blptr->atom2_lower_limit==blptr->atom2_upper_limit) 
		printk("%d",blptr->atom2_lower_limit);
	else if((blptr->atom2_lower_limit==0)&&(blptr->atom2_upper_limit==255)) 
		printk("*");
	else if((blptr->atom2_lower_limit==255)&&(blptr->atom2_upper_limit==0)) 
		printk("*");
	else if(blptr->atom2_lower_limit<blptr->atom2_upper_limit) 
		printk("%d-%d",blptr->atom2_lower_limit,blptr->atom2_upper_limit);
	else 
		printk("%d-%d",blptr->atom2_upper_limit,blptr->atom2_lower_limit);

	printk(".");

	if(blptr->atom3_lower_limit==blptr->atom3_upper_limit) 
		printk("%d",blptr->atom3_lower_limit);
	else if((blptr->atom3_lower_limit==0)&&(blptr->atom3_upper_limit==255)) 
		printk("*");
	else if((blptr->atom3_lower_limit==255)&&(blptr->atom3_upper_limit==0)) 
		printk("*");
	else if(blptr->atom3_lower_limit<blptr->atom3_upper_limit) 
		printk("%d-%d",blptr->atom3_lower_limit,blptr->atom3_upper_limit);
	else 
		printk("%d-%d",blptr->atom3_upper_limit,blptr->atom3_lower_limit);
}

void fr_ip_print_ip(unsigned int ip) {
	unsigned char * ptr;
	ptr=(unsigned char *) &ip;
	printk("%d.%d.%d.%d",*(ptr+0),*(ptr+1),*(ptr+2),*(ptr+3));
}

void fr_ip_double_hash_dump( struct fr_ip_double_hash * double_hash_ptr) {
	
	struct fr_ip_hash_list_node * hlptr;
	struct fr_ip_blur_list_node * blptr;
	unsigned int i;
	unsigned int j;
	unsigned int sum;
	unsigned int sum0;

	if(double_hash_ptr==NULL) return ;

	fr_read_lock(&double_hash_ptr->mirror_lock);   // -->
	fr_read_lock(&double_hash_ptr->master_lock);   // -->

	printk("frdev_dump_struct:ptr-> %x $",double_hash_ptr);
	printk("	 master 	mirror$");
	printk("ptr: 0x%-6x 	0x%-6x $",double_hash_ptr->master_ptr,double_hash_ptr->mirror_ptr);
	printk("mod: %-6d		%-6d $",double_hash_ptr->master_ptr->modular,double_hash_ptr->mirror_ptr->modular);
	printk("haf: 0x%-6x 	0x%-6x $",double_hash_ptr->master_ptr->hash_func,double_hash_ptr->mirror_ptr->hash_func);
	printk("rnd: %-6d		%-6d $",double_hash_ptr->master_ptr->hash_rnd,double_hash_ptr->mirror_ptr->hash_rnd);
	printk("ipc: %-6d		%-6d $",double_hash_ptr->master_ptr->ip_counter,double_hash_ptr->mirror_ptr->ip_counter);
	printk("bip: %-6d		%-6d $",double_hash_ptr->master_ptr->blur_ip_counter,double_hash_ptr->mirror_ptr->blur_ip_counter);
	printk("wlf: %-6d		%-6d $",double_hash_ptr->master_ptr->worst_load_factor,double_hash_ptr->mirror_ptr->worst_load_factor);
	printk("whi: %-6d		%-6d $",double_hash_ptr->master_ptr->worst_hash_index,double_hash_ptr->mirror_ptr->worst_hash_index);
	printk("apt: 0x%-6x 	0x%-6x $",double_hash_ptr->master_ptr->array_ptr,double_hash_ptr->mirror_ptr->array_ptr);
	printk("blh: 0x%-6x 	0x%-6x $",double_hash_ptr->master_ptr->blur_list_headptr,double_hash_ptr->mirror_ptr->blur_list_headptr);
	printk("blt: 0x%-6x 	0x%-6x \n",double_hash_ptr->master_ptr->blur_list_tailptr,double_hash_ptr->mirror_ptr->blur_list_tailptr);

	printk("frdev_dump_numbers:ptr-> %x $",double_hash_ptr);

	fr_read_unlock(&double_hash_ptr->mirror_lock);   // -->
	
	sum=0;
	sum0=0;
	for(j=0;j<double_hash_ptr->master_ptr->modular;j++) {
		hlptr=(struct fr_ip_hash_list_node *)(*(double_hash_ptr->master_ptr->array_ptr+j));
		i=0;
		while(hlptr) {
			i++;
			hlptr=hlptr->next;
		}
		printk("%-3d $",i);
		sum=sum+i;
		if(i==0)
			sum0++;
	}
	printk("$ sum:%d on sum0:%d \n",sum,double_hash_ptr->master_ptr->modular-sum0);

	printk("frdev_dump_ip:ptr-> %x $",double_hash_ptr);
	blptr=double_hash_ptr->master_ptr->blur_list_headptr;
	while(blptr) {
		fr_ip_print_blurip_ptr(blptr);
		printk(" $");
		blptr=blptr->next;
	}
	for(j=0;j<double_hash_ptr->master_ptr->modular;j++) {
		hlptr=(struct fr_ip_hash_list_node *)(*(double_hash_ptr->master_ptr->array_ptr+j));
		while(hlptr) {
			fr_ip_print_ip(hlptr->ip_hash);
			printk(" $");
			hlptr=hlptr->next;
		}
	}
	printk(" \n");
	
	fr_read_unlock(&double_hash_ptr->master_lock);   // -->
	
}

static void fr_ip_dev_ioctl_routine(unsigned long arg) {

	unsigned int ret;
	unsigned int modular;
	unsigned int rnd;
	unsigned int size;
	char * str;

	/* ret status code through the input ptr :) */
	printk("FR_IP_MEMDEV_IOCSETDATA: \n fr_ip_ioctl_para.type:%d\n fr_ip_ioctl_para.ptr:%d \n fr_ip_ioctl_para.size:%d \n fr_ip_ioctl_para.ret:%d \n ",
			fr_ip_ioctl_para.type,fr_ip_ioctl_para.ptr,fr_ip_ioctl_para.size,fr_ip_ioctl_para.ret);

	if(fr_ip_ioctl_para.type<FR_IP_IOCTL_TYPE_WHITE_FIND) {
		if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_MIRROR_INSERT_BYSTRINGS) {
			str=fr_malloc(fr_ip_ioctl_para.size);
			if(str==NULL) {
				ret=1;
				goto RET;
			}
			copy_from_user(str,fr_ip_ioctl_para.ptr,fr_ip_ioctl_para.size);
			ret=fr_ip_double_hash_mirror_insert_bystrings(double_hash_ptr,str);
			fr_free(str);
			goto RET;
		}
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_SWITCH_MIRROR_UPDATE) {
			ret=fr_ip_double_hash_switch_mirror_update(double_hash_ptr);
			goto RET;
		}	
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_FIND_BYSTRINGS) {
			str=fr_malloc(fr_ip_ioctl_para.size);
			if(str==NULL) {
				ret=3;
				goto RET;
			}
			copy_from_user(str,fr_ip_ioctl_para.ptr,fr_ip_ioctl_para.size);
			ret=fr_ip_double_hash_find_bystrings_bool(double_hash_ptr,str);
			fr_free(str);
			goto RET;		
		}
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_MIRROR_DELETE_BYSTRINGS) {
			str=fr_malloc(fr_ip_ioctl_para.size);
			if(str==NULL) {
				ret=3;
				goto RET;
			}
			copy_from_user(str,fr_ip_ioctl_para.ptr,fr_ip_ioctl_para.size);
			ret=fr_ip_double_hash_mirror_delete_bystrings(double_hash_ptr,str);
			fr_free(str);
			goto RET;		
		}
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_MIRROR_DELETE_ALL) {
			ret=fr_ip_double_hash_mirror_delete_all(double_hash_ptr);
			goto RET;
		}
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_REBUILD) {
			// modular rnd
			copy_from_user(&modular,(unsigned int *)(fr_ip_ioctl_para.ptr),sizeof(unsigned int));
			copy_from_user(&rnd,(unsigned int *)(fr_ip_ioctl_para.ptr)+1,sizeof(unsigned int));
			ret=fr_ip_double_hash_rebuild(double_hash_ptr,modular,double_hash_ptr->master_ptr->hash_func,rnd);
			goto RET;
		}//FR_IP_IOCTL_TYPE_DUMP
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_DUMP) {
			fr_ip_double_hash_dump(double_hash_ptr);
			ret=0;
			goto RET;
		}
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_MIRROR_INSERT_IP_BINS) {
			str=fr_malloc(fr_ip_ioctl_para.size);
			if(str==NULL) {
				ret=3;
				goto RET;
			}
			copy_from_user(str,fr_ip_ioctl_para.ptr,fr_ip_ioctl_para.size);
			size=fr_ip_ioctl_para.size/sizeof(unsigned int);
			while(size&&(ret==0)) {
				size--;
				ret=fr_ip_double_hash_mirror_insert_ip(double_hash_ptr,*((unsigned int *)str+size));
			}
			if(ret)
				ret=size+1;
			fr_free(str);
			goto RET;		
		}
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_MIRROR_DELETE_IP_BINS) {
			str=fr_malloc(fr_ip_ioctl_para.size);
			if(str==NULL) {
				ret=3;
				goto RET;
			}
			copy_from_user(str,fr_ip_ioctl_para.ptr,fr_ip_ioctl_para.size);
			size=fr_ip_ioctl_para.size/sizeof(unsigned int);
			while(size&&(ret==0)) {
				size--;
				ret=fr_ip_double_hash_mirror_delete_ip(double_hash_ptr,*((unsigned int *)str+size));
			}
			if(ret)
				ret=size+1;
			fr_free(str);
			goto RET;		
		}
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_MIRROR_DELETE_IP_RANDOMLY) {
			ret=fr_ip_double_hash_mirror_delete_ip_randomly(double_hash_ptr,fr_ip_ioctl_para.size);
			goto RET;
		}
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_MIRROR_DELETE_IP) {
			ret=fr_ip_double_hash_mirror_delete_ip(double_hash_ptr,fr_ip_ioctl_para.size);
			goto RET;
		}
		else {
			ret=3198;
			goto RET;
		}
	}
	else {
		if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_WHITE_MIRROR_INSERT_BYSTRINGS) {
			str=fr_malloc(fr_ip_ioctl_para.size);
			if(str==NULL) {
				ret=1;
				goto RET;
			}
			copy_from_user(str,fr_ip_ioctl_para.ptr,fr_ip_ioctl_para.size);
			ret=fr_ip_double_hash_mirror_insert_bystrings(double_hash_white_ptr,str);
			fr_free(str);
			goto RET;
		}
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_WHITE_SWITCH_MIRROR_UPDATE) {
			ret=fr_ip_double_hash_switch_mirror_update(double_hash_white_ptr);
			goto RET;
		}	
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_WHITE_FIND_BYSTRINGS) {
			str=fr_malloc(fr_ip_ioctl_para.size);
			if(str==NULL) {
				ret=3;
				goto RET;
			}
			copy_from_user(str,fr_ip_ioctl_para.ptr,fr_ip_ioctl_para.size);
			ret=fr_ip_double_hash_find_bystrings_bool(double_hash_white_ptr,str);
			fr_free(str);
			goto RET;		
		}
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_WHITE_MIRROR_DELETE_BYSTRINGS) {
			str=fr_malloc(fr_ip_ioctl_para.size);
			if(str==NULL) {
				ret=3;
				goto RET;
			}
			copy_from_user(str,fr_ip_ioctl_para.ptr,fr_ip_ioctl_para.size);
			ret=fr_ip_double_hash_mirror_delete_bystrings(double_hash_white_ptr,str);
			fr_free(str);
			goto RET;		
		}
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_WHITE_MIRROR_DELETE_ALL) {
			ret=fr_ip_double_hash_mirror_delete_all(double_hash_white_ptr);
			goto RET;
		}
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_WHITE_REBUILD) {
			// modular rnd
			copy_from_user(&modular,(unsigned int *)(fr_ip_ioctl_para.ptr),sizeof(unsigned int));
			copy_from_user(&rnd,(unsigned int *)(fr_ip_ioctl_para.ptr)+1,sizeof(unsigned int));
			ret=fr_ip_double_hash_rebuild(double_hash_white_ptr,modular,double_hash_white_ptr->master_ptr->hash_func,rnd);
			goto RET;
		}//FR_IP_IOCTL_TYPE_WHITE_DUMP
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_WHITE_DUMP) {
			fr_ip_double_hash_dump(double_hash_white_ptr);
			ret=0;
			goto RET;
		}
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_WHITE_MIRROR_INSERT_IP_BINS) {
			str=fr_malloc(fr_ip_ioctl_para.size);
			if(str==NULL) {
				ret=3;
				goto RET;
			}
			copy_from_user(str,fr_ip_ioctl_para.ptr,fr_ip_ioctl_para.size);
			size=fr_ip_ioctl_para.size/sizeof(unsigned int);
			while(size&&(ret==0)) {
				size--;
				ret=fr_ip_double_hash_mirror_insert_ip(double_hash_white_ptr,*((unsigned int *)str+size));
			}
			if(ret)
				ret=size+1;
			fr_free(str);
			goto RET;		
		}
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_WHITE_MIRROR_DELETE_IP_BINS) {
			str=fr_malloc(fr_ip_ioctl_para.size);
			if(str==NULL) {
				ret=3;
				goto RET;
			}
			copy_from_user(str,fr_ip_ioctl_para.ptr,fr_ip_ioctl_para.size);
			size=fr_ip_ioctl_para.size/sizeof(unsigned int);
			while(size&&(ret==0)) {
				size--;
				ret=fr_ip_double_hash_mirror_delete_ip(double_hash_white_ptr,*((unsigned int *)str+size));
			}
			if(ret)
				ret=size+1;
			fr_free(str);
			goto RET;		
		}
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_WHITE_MIRROR_DELETE_IP_RANDOMLY) {
			ret=fr_ip_double_hash_mirror_delete_ip_randomly(double_hash_white_ptr,fr_ip_ioctl_para.size);
			goto RET;
		}
		else if(fr_ip_ioctl_para.type==FR_IP_IOCTL_TYPE_WHITE_MIRROR_DELETE_IP) {
			ret=fr_ip_double_hash_mirror_delete_ip(double_hash_white_ptr,fr_ip_ioctl_para.size);
			goto RET;
		}
		else {
			ret=3198;
			goto RET;
		}
	}

	RET:
	copy_to_user(&(((struct fr_ip_ioctl_para_t *)arg)->ret),&ret,sizeof(unsigned int));

}

static int fr_ip_mem_open(struct inode *inode, struct file *filp)
{
    struct fr_ip_mem_dev *dev;
    int num = MINOR(inode->i_rdev);
	
    if (num >= FR_IP_MEMDEV_NR_DEVS) 
            return -ENODEV;
    dev = &fr_ip_mem_devp[num];
    filp->private_data = dev;
    
    return 0; 
}

static int fr_ip_mem_release(struct inode *inode, struct file *filp)
{
  return 0;
}

static int fr_ip_memdev_ioctl(struct inode *inode, struct file *filp,
                 unsigned int cmd, unsigned long arg)
{
    int err = 0;
    int ret = 0;
    int ioarg = 0;
	unsigned char rand;

	ret=0;
	while(1) {
		if(spin_trylock(&frdev_ioctl_spinlock)) {
			ret=0;
			break;
		}
		else {
			ret++;
			if(ret>=10) {
				printk("frdev_dump_ioctl_get_spinlock_fail :( \n");
				return 3;
			}
			get_random_bytes(&rand,1);
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(rand%11+10);
		}
	}

	if (_IOC_TYPE(cmd) != FR_IP_MEMDEV_IOC_MAGIC) 
        {ret= -EINVAL;goto END;}
    if (_IOC_NR(cmd) > FR_IP_MEMDEV_IOC_MAXNR) 
        {ret= -EINVAL;goto END;}

    if (_IOC_DIR(cmd) & _IOC_READ)
        err = !access_ok(VERIFY_WRITE, (void *)arg, _IOC_SIZE(cmd));
    else if (_IOC_DIR(cmd) & _IOC_WRITE)
        err = !access_ok(VERIFY_READ, (void *)arg, _IOC_SIZE(cmd));
	
    if (err) 
		{ret= -EFAULT;goto END;}

    switch(cmd) {
      case FR_IP_MEMDEV_IOCPRINT:
        break;
      case FR_IP_MEMDEV_IOCGETDATA: 
        ioarg = 1101;
        ret = __put_user(fr_ip_mem_share, (int *)arg);
        break;
      case FR_IP_MEMDEV_IOCSETDATA: 
        copy_from_user(&fr_ip_ioctl_para,arg,sizeof(struct fr_ip_ioctl_para_t));
		/*copy_from_user(buf,fr_ip_ioctl_para.ptr,fr_ip_ioctl_para.size);*/
		fr_ip_dev_ioctl_routine(arg);
		printk("<--- In Kernel FR_IP_MEMDEV_IOCSETDATA para.type:%d --->\n\n",fr_ip_ioctl_para.type);
        break;
      default:  
		{ret= -EINVAL;goto END;}        
    }
	
END:
	spin_unlock(&frdev_ioctl_spinlock);
    return ret;

}


static const struct file_operations fr_ip_mem_fops =
{
  .owner = THIS_MODULE,
  .open = fr_ip_mem_open,
  .release = fr_ip_mem_release,
  .ioctl = fr_ip_memdev_ioctl,
};

static unsigned int double_hash_modular=1024;
static unsigned int double_hash_rnd=3198;
module_param(double_hash_modular, uint, 0600);
module_param(double_hash_rnd, uint, 0600);

static unsigned int double_hash_white_modular=1024;
static unsigned int double_hash_white_rnd=3198;
module_param(double_hash_white_modular, uint, 0600);
module_param(double_hash_white_rnd, uint, 0600);


#define NIPQUAD(addr) \
  ((unsigned char *)&addr)[0], \
  ((unsigned char *)&addr)[1], \
  ((unsigned char *)&addr)[2], \
  ((unsigned char *)&addr)[3]

static int fr_ip_counter=0;

static unsigned int fr_nf_hook_sample(
	unsigned int hooknum,struct sk_buff * skb,const struct net_device *in,
	const struct net_device *out,int (*okfn) (struct sk_buff *))
{
   __be32 sip,dip;

   if(skb){
   		struct sk_buff *sb = NULL;
   		sb = skb;
   		struct iphdr *iph;
   		iph  = ip_hdr(sb);
   		sip = iph->saddr;
   		dip = iph->daddr;
   		printk("frip:packet sip: %d.%d.%d.%d dst: %d.%d.%d.%d ", NIPQUAD(sip), NIPQUAD(dip));
   }
   fr_ip_counter++;
   
   printk("counter:%d ,jiffies:%d \n",fr_ip_counter,jiffies);

   if(fr_ip_double_hash_find_bool(double_hash_white_ptr,sip)) return NF_ACCEPT;
   else if(fr_ip_double_hash_find_bool(double_hash_ptr,sip)) return NF_DROP;
   else  return NF_ACCEPT;
   
}

 struct nf_hook_ops fr_nf_hook_sample_ops = {
   .list =  {NULL,NULL},
   .hook = fr_nf_hook_sample,
   .pf = PF_INET,
   .hooknum = NF_INET_PRE_ROUTING,
   .priority = NF_IP_PRI_FILTER+2
 };


static int fr_ip_dev_init(void)
{
  int result;
  int i;
  dev_t devno = MKDEV(fr_ip_mem_major, 0);

  spin_lock_init(&frdev_ioctl_spinlock);
  printk("frdev: double_hash_modular:%d double_hash_rnd:%d \n",double_hash_modular,double_hash_rnd);

  fr_ip_blur_list_node_cache = kmem_cache_create("frdev_blur_ip", sizeof(struct fr_ip_blur_list_node),
			0, SLAB_HWCACHE_ALIGN, NULL); /* no ctor/dtor */
  fr_ip_hash_list_node_cache = kmem_cache_create("frdev_ip", sizeof(struct fr_ip_hash_list_node),
			0, SLAB_HWCACHE_ALIGN, NULL); /* no ctor/dtor */
  double_hash_ptr	   =fr_ip_double_hash_malloc(double_hash_modular,fr_jhash_1word,double_hash_rnd);
  double_hash_white_ptr=fr_ip_double_hash_malloc(double_hash_white_modular,fr_jhash_1word,double_hash_white_rnd);
  
  if((fr_ip_blur_list_node_cache==NULL)||(fr_ip_hash_list_node_cache==NULL)||
  	 (double_hash_ptr==NULL)||(double_hash_white_ptr==NULL) ) {
  	if(fr_ip_blur_list_node_cache) {
		kmem_cache_destroy(fr_ip_blur_list_node_cache);
		fr_ip_blur_list_node_cache=NULL;
  	}
	if(fr_ip_hash_list_node_cache) {
		kmem_cache_destroy(fr_ip_hash_list_node_cache);
		fr_ip_hash_list_node_cache=NULL;
  	}
	if(double_hash_ptr) {
		fr_ip_double_hash_destroy(double_hash_ptr);
		double_hash_ptr=NULL;
	}
	if(double_hash_white_ptr) {
		fr_ip_double_hash_destroy(double_hash_white_ptr);
		double_hash_white_ptr=NULL;
	}
	printk("frdev:double hash table init failed\n");
  	return -1;
  }
  
  if (fr_ip_mem_major)
    result = register_chrdev_region(devno, 2, "frdev");
  else   {
    result = alloc_chrdev_region(&devno, 0, 2, "frdev");
    fr_ip_mem_major = MAJOR(devno);
  }  
  if (result < 0) {
  	if(fr_ip_blur_list_node_cache) {
		kmem_cache_destroy(fr_ip_blur_list_node_cache);
		fr_ip_blur_list_node_cache=NULL;
  	}
	if(fr_ip_hash_list_node_cache) {
		kmem_cache_destroy(fr_ip_hash_list_node_cache);
		fr_ip_hash_list_node_cache=NULL;
  	}
	if(double_hash_ptr) {
		fr_ip_double_hash_destroy(double_hash_ptr);
		double_hash_ptr=NULL;
	}
	if(double_hash_white_ptr) {
		fr_ip_double_hash_destroy(double_hash_white_ptr);
		double_hash_white_ptr=NULL;
	}
	printk("frdev:kernel device init failed\n");
    return result;
  }
  cdev_init(&fr_ip_cdev, &fr_ip_mem_fops);
  fr_ip_cdev.owner = THIS_MODULE;
  fr_ip_cdev.ops = &fr_ip_mem_fops;
  
  cdev_add(&fr_ip_cdev, MKDEV(fr_ip_mem_major, 0), FR_IP_MEMDEV_NR_DEVS);
  fr_ip_mem_devp = kmalloc(FR_IP_MEMDEV_NR_DEVS * sizeof(struct fr_ip_mem_dev), GFP_KERNEL);
  if (!fr_ip_mem_devp) 
  {
    result =  - ENOMEM;
    goto fail_malloc;
  }
  memset(fr_ip_mem_devp, 0, sizeof(struct fr_ip_mem_dev));

  for (i=0; i < FR_IP_MEMDEV_NR_DEVS; i++) 
  {
        fr_ip_mem_devp[i].size = FR_IP_MEMDEV_SIZE;
        fr_ip_mem_devp[i].data = kmalloc(FR_IP_MEMDEV_SIZE, GFP_KERNEL);
        memset(fr_ip_mem_devp[i].data, 0, FR_IP_MEMDEV_SIZE);
  }
  nf_register_hook(&fr_nf_hook_sample_ops);
  return 0;
  fail_malloc: 
  if(fr_ip_blur_list_node_cache) {
		kmem_cache_destroy(fr_ip_blur_list_node_cache);
		fr_ip_blur_list_node_cache=NULL;
  }
  if(fr_ip_hash_list_node_cache) {
		kmem_cache_destroy(fr_ip_hash_list_node_cache);
		fr_ip_hash_list_node_cache=NULL;
  }
  if(double_hash_ptr) {
		fr_ip_double_hash_destroy(double_hash_ptr);
		double_hash_ptr=NULL;
  }
  if(double_hash_white_ptr) {
		fr_ip_double_hash_destroy(double_hash_white_ptr);
		double_hash_white_ptr=NULL;
	}
  unregister_chrdev_region(devno, 1);
  printk("frdev:devmem malloc failed\n");
  return result;
}

static void fr_ip_dev_exit(void)
{
	nf_unregister_hook(&fr_nf_hook_sample_ops);
    cdev_del(&fr_ip_cdev);  
    kfree(fr_ip_mem_devp);    
    unregister_chrdev_region(MKDEV(fr_ip_mem_major, 0), 2); 

    if(double_hash_ptr) {
		fr_ip_double_hash_destroy(double_hash_ptr);
		double_hash_ptr=NULL;
	}
	if(double_hash_white_ptr) {
		fr_ip_double_hash_destroy(double_hash_white_ptr);
		double_hash_white_ptr=NULL;
	}
    if(fr_ip_blur_list_node_cache) {
		kmem_cache_destroy(fr_ip_blur_list_node_cache);
		fr_ip_blur_list_node_cache=NULL;
  	}
	if(fr_ip_hash_list_node_cache) {
		kmem_cache_destroy(fr_ip_hash_list_node_cache);
		fr_ip_hash_list_node_cache=NULL;
  	}
	
	
}

module_init(fr_ip_dev_init);
module_exit(fr_ip_dev_exit);

