#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"

#include "ip.h"

#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

extern ustack_t *instance;

pthread_mutex_t mospf_lock;

void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);

	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		init_list_head(&iface->nbr_list);
	}

	init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);

void mospf_run()
{
	pthread_t hello, lsu, nbr;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
}

void *sending_mospf_hello_thread(void *param) //ywl
{
	fprintf(stdout, "TODO: send mOSPF Hello message periodically.\n");
	/*
	while(1)循环，sleep hello时间间隔，循环内
	加锁
	1.循环遍历iface_list
	2.分配hello包地址
	3.填写ETH hdr, ip hdr，mospf hdr, hello body
	4.使用iface_send_packet 发送
	解锁
	*/


	u8 mac_daddr[ETH_ALEN] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x05};
    int packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE;

	while (1){
		sleep(MOSPF_DEFAULT_HELLOINT);
		pthread_mutex_lock(&mospf_lock);
		iface_info_t *iface_p;
		list_for_each_entry(iface_p, &instance->iface_list, list){
			char *hello_packet = (char *)malloc(packet_len);

            // set ether_header
			struct ether_header *eth = (struct ether_header *)hello_packet;
			memcpy(eth->ether_dhost, mac_daddr, ETH_ALEN);
			memcpy(eth->ether_shost, iface_p->mac, ETH_ALEN);
			eth->ether_type = htons(ETH_P_IP);

            // set ip_header
			struct iphdr *ip_h = packet_to_ip_hdr(hello_packet);
			ip_init_hdr(ip_h, iface_p->ip, MOSPF_ALLSPFRouters, packet_len - ETHER_HDR_SIZE, IPPROTO_MOSPF);

            // set mospf_header
			struct mospf_hdr *mospf_h = (struct mospf_hdr *)(hello_packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
			mospf_init_hdr(mospf_h, MOSPF_TYPE_HELLO, MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, instance->router_id, instance->area_id);

            // set hello(mospf body)
			struct mospf_hello *hello = (struct mospf_hello *)(hello_packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);
			mospf_init_hello(hello, iface_p->mask);
			mospf_h->checksum = mospf_checksum(mospf_h);
			iface_send_packet(iface_p, hello_packet, packet_len);
		}
		pthread_mutex_unlock(&mospf_lock);
	}

	return NULL;
}

void *checking_nbr_thread(void *param) //ywl
{
	fprintf(stdout, "TODO: neighbor list timeout operation.\n");
	/*
	while循环
	加锁
	遍历instance的eth_list
		遍历每个网口的邻居列表
		假设 alive时间即将超过3倍，则删除这一项邻居，并且free
		标记已被change，广播LSU
	解锁
	*/

	int changed = 0;
	iface_info_t *iface_p;
    mospf_nbr_t *mospf_p, *mospf_q;
	while(1){
		sleep(1);
		pthread_mutex_lock(&mospf_lock);
        changed = 0;
		list_for_each_entry(iface_p, &instance->iface_list, list) {
			list_for_each_entry_safe(mospf_p, mospf_q, &iface_p->nbr_list, list) {
				if ((mospf_p->alive)++ > 3 * MOSPF_DEFAULT_HELLOINT) { //3 * 5 seconds
					list_delete_entry(&mospf_p->list);
					(iface_p->num_nbr)--;
					free(mospf_p);
                    changed = 1;
				}
			}
		}
        if(changed)
            broadcast_lsu();
		pthread_mutex_unlock(&mospf_lock);
	}
	
	return NULL;
}

//each interface handle the rx hello packet.
void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	//fprintf(stdout, "TODO: handle mOSPgit F Hello message.\n");
	pthread_mutex_lock(&mospf_lock);
	int in_nbr_list = 0;
	
	//1.depart packet
	struct iphdr * ip_h = packet_to_ip_hdr(packet);
	struct mospf_hdr * mos_h = (struct mospf_hdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
	struct  mospf_hello * mos_hello = (struct mospf_hello *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);
	u32 hello_rid = ntohl(mos_h->rid); //  

	//2.check for iface's nbr:  hello source node alrdy in nbr_list? 
	mospf_nbr_t * mos_nbr_p;
	list_for_each_entry(mos_nbr_p, &iface->nbr_list, list){
		if(mos_nbr_p->nbr_id == hello_rid){
			in_nbr_list = 1;  //find this hello alrdy in nbr list
			break;
		}
	}

	if(!in_nbr_list){ //new node in nbr_list, add entry
		mos_nbr_p = (mospf_nbr_t *)malloc(sizeof(mospf_nbr_t));
		mos_nbr_p -> nbr_id = hello_rid;
		mos_nbr_p -> nbr_ip = ntohl(ip_h -> saddr);
		mos_nbr_p -> nbr_mask = ntohl(mos_hello -> mask);
		list_add_tail(&mos_nbr_p->list, &iface->nbr_list);
		iface->num_nbr ++;
	}
	//update or set nbr's alive time
	mos_nbr_p -> alive = 0;

	pthread_mutex_unlock(&mospf_lock);
}


//sending lsu packet peroidlly
//每个节点发送，相当于对于整个图的每个邻居都构造一个包并发送
void *sending_mospf_lsu_thread(void *param)  //ywl
{
	//fprintf(stdout, "TODO: send mOSPF LSU message periodically.\n");
	while(1){
		sleep(MOSPF_DEFAULT_LSUINT);  //每隔一段时间发送lsu

		pthread_mutex_lock(&mospf_lock);
		/*broadcast lsu

		1.统计全图总nbr num
		2.分配lsu packet内存，分别是eth hdr|ip hdr|MOSPF hdr|mospf lsu|mospf lsa数组
		3.定义宏lsu packet：对于lsa结构体数组的每一个，通过遍历iface_list的nbr_list来赋值（要考虑host端口情况,num_nbr==0）
		4.构造并且发送packet：
			两层循环,遍历每个interface的的每个nbr
			malloc分配新的包
			将之前的宏packet memcpy过去，用来填充lsa部分
			(lsa之前的部分)构造ip hdr, mospf hdr, init mospf lsu
			mospf checksum
			ip_send_packet(每个网口都给每个他的邻居发送一个LSU包)
			//发送完需要free下每个包？

		5.	instance->sequence_num ++
			free 宏packet
		*/
		int i = 0;
		int num_adv = 0;
		iface_info_t *iface_p;

		// count the nbr node; "num == 0" means that there's a host
		list_for_each_entry(iface_p, &(instance->iface_list), list){
			num_adv = (iface_p->num_nbr == 0)? num_adv + 1 : num_adv + iface_p->num_nbr;
		}

		int pac_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + MOSPF_LSA_SIZE * num_adv;
		char *packet = (char *)malloc(pac_len);
		struct mospf_lsa * lsa_start = (struct mospf_lsa *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE);

		mospf_nbr_t *mospf_nbr_p;
		struct mospf_lsa *mospf_lsa_p;
		list_for_each_entry(iface_p, &(instance->iface_list), list) {
			if(iface_p->num_nbr == 0) { // host node
				mospf_lsa_p = &lsa_start[i++];
				mospf_lsa_p->subnet = htonl(iface_p->ip & iface_p->mask);
				mospf_lsa_p->mask   = htonl(iface_p->mask);
				mospf_lsa_p->rid    = 0;
				continue;
			}
			list_for_each_entry(mospf_nbr_p, &(iface_p->nbr_list), list) {
				mospf_lsa_p = &lsa_start[i++];
				mospf_lsa_p->subnet = ntohl(mospf_nbr_p->nbr_ip & mospf_nbr_p->nbr_mask);
				mospf_lsa_p->mask   = ntohl(mospf_nbr_p->nbr_mask);
				mospf_lsa_p->rid    = ntohl(mospf_nbr_p->nbr_id);
			}
		}
		// send packet
		list_for_each_entry(iface_p, &(instance->iface_list), list) {
			list_for_each_entry(mospf_nbr_p, &(iface_p->nbr_list), list) {
				char *packet_t = (char *)malloc(pac_len);
				memcpy(packet_t, packet, pac_len);

				// set ip_header
				struct iphdr *iph = (struct iphdr *)(packet_t + ETHER_HDR_SIZE);
				ip_init_hdr(iph, iface_p->ip, mospf_nbr_p->nbr_ip, pac_len - ETHER_HDR_SIZE, 90);

				// set imospf_header
				struct mospf_hdr * mospf_h = (struct mospf_hdr *)(packet_t + IP_BASE_HDR_SIZE + ETHER_HDR_SIZE);
				mospf_init_hdr(mospf_h, MOSPF_TYPE_LSU, pac_len - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE, instance->router_id, instance->area_id);
				
				// set lsu
				struct mospf_lsu *mos_lsu = (struct mospf_lsu *)((char *)mospf_h + MOSPF_HDR_SIZE);
				mospf_init_lsu(mos_lsu, num_adv);

				mospf_h->checksum = mospf_checksum(mospf_h);
				ip_send_packet(packet_t, pac_len);
			}
				
		}
		instance->sequence_num ++;
		free(packet);

		pthread_mutex_unlock(&mospf_lock);
		}
	return NULL;
}


void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)  
{
	//fprintf(stdout, "TODO: handle mOSPF LSU message.\n");
	/*
	如果之前未收到该节点的链路状态信息，或者该信息的序列号更大，
		则更新链路状态数据库
	TTL减1
	如果TTL值大于0
		则向除该端口以外的端口转发该消息
	*/
	//1.分解packet
	struct iphdr * ip_h = packet_to_ip_hdr(packet);
	struct mospf_hdr * mos_h = (struct mospf_hdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
	struct mospf_lsu * mos_lsu = (struct mospf_lsu *)((char *)mos_h + MOSPF_HDR_SIZE);
	struct mospf_lsa * mos_lsa = (struct mospf_lsa *)((char *)mos_lsu + MOSPF_LSU_SIZE);

	u32 mospf_rid = ntohl(mos_h -> rid);
	if(mospf_rid == instance-> router_id){ //recv lsu message from router itself(sending to host) 
		return;
	}

	//找到该lsu 的rid是否已经在db里出现,以及是否序列号更大
	//db在 init_ustack() --> mospf_init() --> init_mospf_db()中初始化，定义在mospf_database.c
	int in_db = 0, to_update_seq = 0;
	mospf_db_entry_t * mos_db_line;
	u16 lsu_seq = (ntohs)(mos_lsu->seq);
	int mos_nadv = (ntohl)(mos_lsu->nadv);

	list_for_each_entry(mos_db_line, &(mospf_db), list){
		if(mos_db_line -> rid == mospf_rid){
			in_db = 1;
			if(mos_db_line -> seq < lsu_seq ){
				to_update_seq = 1;
				free(mos_db_line -> array); //丢弃该rid的旧项
			}
			break;
		}
	}
	
	if(!in_db){//建立新的项for后续插入db
		mos_db_line = (mospf_db_entry_t *)malloc(sizeof(mospf_db_entry_t));
		init_list_head(&mos_db_line->list );
		mos_db_line->rid = mospf_rid;
		mos_db_line->seq = lsu_seq;
		mos_db_line->nadv = lsu_nadv;
	}

	if(!in_db || to_update_seq){ //已经建立新的项or删除旧项的array，构造array(拷贝lsu->db),加入db
		mos_db_line->array = (struct mospf_lsa*)malloc(nadv * sizeof(mospf_lsa));
		
		for(int i=0; i<nadv; i++){
			mos_db_line->array[i].subnet = ntohl(mos_lsa[i].subnet);
			mos_db_line->array[i].mask = ntohl(mos_lsa[i].mask);
			mos_db_line->array[i].rid = ntohl(mos_lsa[i].rid);
		}

		//插入db的list
		list_add_tail(&(mos_db_line->list), &mospf_db);
	}

	//打印该路由器节点的database
	mospf_db_entry_t *mospf_p;
	list_for_each_entry(mospf_p, &mospf_db, list){
		fprintf(stdout, "RID : "IP_FMT"\n", HOST_IP_FMT_STR(mospf_p->rid)); 
		for(int i = 0;i < mospf_p->nadv; i++){
			fprintf(stdout, IP_FMT"\t"IP_FMT"\t"IP_FMT"\n", 
			  HOST_IP_FMT_STR(mospf_p->array[i].subnet), 
			  HOST_IP_FMT_STR(mospf_p->array[i].mask), 
			  HOST_IP_FMT_STR(mospf_p->array[i].rid) );
		}
	}

	mos_lsu->ttl --;
    if(mos_lsu->ttl > 0) { // 继续向别的端口转发
    	iface_info_t * iface_t;
    	mospf_nbr_t * mos_nbr;
    	list_for_each_entry(iface, &(instance->iface_list), list){
    		if(iface_t->index == iface->index) //跳过原端口
    			continue;

            list_for_each_entry(mos_nbr, &(iface_t->nbr_list), list){
            	char * forward_packet = (char *)malloc(len);
            	memcpy(forward_packet, packet, len);

				//设置ip hdr和mospf checksum
				struct iphdr * ip_h = packet_to_ip_hdr(forward_packet);
                struct mospf_hdr * mos_h = (struct mospf_hdr *)(forward_packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
                mospf->checksum = mospf_checksum(mos_h);

                ip_init_hdr(ip_h, iface_t->ip, mos_nbr->nbr_ip, len - ETHER_HDR_SIZE, IPPROTO_MOSPF);
                ip_send_packet(forward_packet, len);
            }
    	}
    }

    //计算路由表函数  //第二部分

    return;

}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return ;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum");
		return ;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return ;
	}

	// log(DEBUG, "received mospf packet, type: %d", mospf->type);

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO:
			handle_mospf_hello(iface, packet, len);
			break;
		case MOSPF_TYPE_LSU:
			handle_mospf_lsu(iface, packet, len);
			break;
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}
