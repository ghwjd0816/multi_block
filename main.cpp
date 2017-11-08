#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<netinet/in.h>
#include<linux/types.h>
#include<linux/netfilter.h>
#include<libnet.h>
#include<errno.h>

#include<libnetfilter_queue/libnetfilter_queue.h>

#define SIZE_OF_TCP 20
#define SIZE_OF_IPV4 20
#define NUM_OF_METHOD 6
#define METHOD_MAX_LENGTH 7
#define IPP_TCP 6
#define SIZE_OF_HOST_LIST 1000000

char http_method[NUM_OF_METHOD][METHOD_MAX_LENGTH+1] = 
				{"GET","POST","HEAD","PUT","DELETE","OPTIONS"};
int http_method_size[NUM_OF_METHOD] = {3,4,4,3,6,7};

struct host_hash{
	char domain[100];
	int hash;
}blockhost_list[SIZE_OF_HOST_LIST];

void usage()
{
	puts("------------------------------");
	printf("[*]iptables setting\n");
	printf("[+]iptables -F\n");
	system("iptables -F");
	printf("[+]iptables -A OUTPUT -j NFQUEUE --queue-num 0\n");
	system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
	printf("[+]iptables -A INPUT -j NFQUEUE --queue-num 0\n");
	system("iptables -A INPUT -j NFQUEUE --queue-num 0");
	puts("------------------------------");
}

void database()
{
	puts("[*]Make database");
	puts("[+]Open file top-1m-hashed-sorted.txt");
	FILE *db = fopen("top-1m-hashed-sorted.txt","r");
	puts("[*]Parsing database");

	char domain[100],hash[100];
	for(int i=0;i<1000000;i++)
	{
		fscanf(db,"%s %s",domain,hash);
		strcpy(blockhost_list[i].domain,domain);
		blockhost_list[i].hash = atoi(hash);
	}
	puts("[+]Successfully Parsed Database");
	puts("------------------------------");
}

unsigned int RSHash(char*str,int length)
{
	unsigned int b = 378551;
	unsigned int a = 63689;
	unsigned int hash = 0;
	for(int i=0;i<length;i++)
	{
		hash = hash * a + str[i];
		a = a * b;
	}
	  
	return (hash & 0x7FFFFFFF);
}

void dump(char*buf, int len)
{
	for(int i=0;i<len;i++)
	{
		printf("%c",*buf++);
	}
}

int find(int n,int low,int high)
{
	// Update to Hash Search
	int mid = (low+high)/2;
	while(low<=high)
	{
		mid = (low+high)/2;
		if(blockhost_list[mid].hash == n)return mid;
		if(blockhost_list[mid].hash < n) low = mid+1;
		else high = mid -1;
	}
	return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
							struct nfq_data *nfa, void *data)
{
	u_int32_t id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	u_int32_t ret;
	unsigned char* pl = 0;
	struct libnet_ipv4_hdr*ip_hdr = 0;
	struct libnet_tcp_hdr*tcp_hdr = 0;

	ph = nfq_get_msg_packet_hdr(nfa);
	if(ph) id = ntohl(ph->packet_id);

	ret = nfq_get_payload(nfa, &pl);
	if(ret < 0) return nfq_set_verdict(qh,id,NF_ACCEPT,0,NULL);
	
	ip_hdr = (struct libnet_ipv4_hdr*)pl;
	if(ip_hdr->ip_p == IPP_TCP && ret >= SIZE_OF_IPV4 + SIZE_OF_TCP )
	{
		tcp_hdr = (struct libnet_tcp_hdr*)((char*)ip_hdr + SIZE_OF_IPV4);
		int tcp_size = tcp_hdr->th_off * 4;
		char *payload = (char*)((char*)tcp_hdr+tcp_size);
		u_int32_t len = ret - SIZE_OF_IPV4 - tcp_size;
		
		for(int i=0;i<NUM_OF_METHOD;i++)
		{
			if(!memcmp(payload, http_method[i],http_method_size[i]))
			{
				char * tmp = strstr(payload, "Host: "); // replace strstr
				if(!tmp)break;	
				char *cmp = tmp+6;
				int size_www = 0;
				while(*(cmp-1)!='.')
				{
					cmp = cmp+1;
					size_www ++ ;
				}
				char *hashcheck = cmp;
				int size = 0;
				while(*cmp!='\r')
				{
					cmp = cmp+1;
					size++;
				}
				int tmphash = RSHash(hashcheck, size);

				int index=find(tmphash,0,SIZE_OF_HOST_LIST-1);
				if(!index)break;
				if(strncmp(hashcheck, blockhost_list[index].domain,size))break;
				printf("[+]Blocking...%s\n",blockhost_list[index].domain);
				//dump(payload,len);
				return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
			}
		}
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char *argv[])
{
	usage();
	database();

	struct nfq_handle *handle;
	struct nfq_q_handle *q_handle;
	struct nfnl_handle *n_handle;
	int fd;
	int rv;
	char buf[4096];
	
	printf("[*]Opening library handle\n");
	handle = nfq_open();
	if(handle == NULL)
	{
		printf("[-]Error during nfq_open()\n");
		exit(1);
	}

	printf("[*]Unbinding existing nf_queue handler for AF_INET (if any)\n");
	if(nfq_unbind_pf(handle, AF_INET)<0)
	{
		printf("[-]Error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("[*]Binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if(nfq_bind_pf(handle,AF_INET)<0)
	{
		printf("[-]Error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("[*]Binding this socket to queue '0'\n");
	q_handle = nfq_create_queue(handle, 0, &cb, NULL);
	if(q_handle == NULL)
	{
		printf("[-]Error during nfq_create_queue()\n");
		exit(1);
	}

	printf("[*]Setting copy_packet mode\n");
	puts("------------------------------");
	if(nfq_set_mode(q_handle, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		printf("[-]Can't set packet_copy mod\n");
		exit(1);
	}
	fd = nfq_fd(handle);
	while(true)
	{
		if((rv = recv(fd, buf, sizeof(buf),0)) >=0 )
		{
			//printf("[+]Packet received\n");
			nfq_handle_packet(handle, buf, rv);
			continue;
		}

		if(rv < 0 && errno == ENOBUFS)
		{
			printf("[-]Losing packets!\n");
			continue;
		}

		printf("[-]Recv failed");
		
		break;
	}

	printf("[*]Unbinding from queue 0\n");
	nfq_destroy_queue(q_handle);

	printf("[*]Closing library handle\n");
	nfq_close(handle);

	printf("[*]Reset iptable\n");
	system("iptables -F");

	return 0;
}
