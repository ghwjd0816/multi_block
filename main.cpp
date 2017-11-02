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

char blockhost[30];
char http_method[NUM_OF_METHOD][METHOD_MAX_LENGTH+1] = 
				{"GET","POST","HEAD","PUT","DELETE","OPTIONS"};
int http_method_size[NUM_OF_METHOD] = {3,4,4,3,6,7};


void usage()
{
	printf("[*]iptables -F\n");
	printf("[*]iptables -A OUTPUT -j NFQUEUE --queue-num 0\n");
	printf("[*]iptables -A INPUT -j NFQUEUE --queue-num 0\n");
	printf("[*]usage : ./netfilter_block www.domain.com\n");
}

void dump(char*buf, int len)
{
	for(int i=0;i<len;i++)
	{
		printf("%c",*buf++);
	}
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
		char *payload = (char*)((char*)tcp_hdr+SIZE_OF_TCP);
		u_int32_t len = ret - SIZE_OF_IPV4 - SIZE_OF_TCP;
		
		for(int i=0;i<NUM_OF_METHOD;i++)
		{
			if(!memcmp(payload, http_method[i],http_method_size[i]))
			{
				char *host;
				char * tmp = strstr(payload, "Host: ");
				if(!tmp)break;	
				tmp+=6;
				host = strtok(tmp, "\r");
				if(strncmp(blockhost, host, strlen(blockhost)))break;
				
				printf("[+]Blocking...%s\n",blockhost);
				//dump(payload,len);
				return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
			}
		}
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char *argv[])
{
	if(argc!=2)
	{
		usage();
		exit(1);
	}
	strcpy(blockhost, argv[1]);

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

	return 0;
}
