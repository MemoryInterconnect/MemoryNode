#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <endian.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "ox_common.h"

char mem_storage[MEM_SIZE];

/**
 * @brief Print omnixtend header
 */
void print_ox_header(struct ox_packet_struct * ox_p) {
	printf("Dest. MAC = %012lx\n", (be64toh(ox_p->eth_hdr.dst_mac_addr))>>16);
	printf("Src. MAC = %012lx\n", (be64toh(ox_p->eth_hdr.src_mac_addr))>>16);
	printf("Eth Type = %04hx\n", ox_p->eth_hdr.eth_type);
	printf("\n<<TLoE header>>\n");
	printf("vc: %u\n", ox_p->tloe_hdr.vc);
	printf("msg_type: %u\n", ox_p->tloe_hdr.msg_type);
	printf("seq_num: %x\n", ox_p->tloe_hdr.seq_num);
	printf("seq_num_ack: %x\n", ox_p->tloe_hdr.seq_num_ack);
	printf("ack: %u\n", ox_p->tloe_hdr.ack);
	printf("channel: %u\n", ox_p->tloe_hdr.chan);
	printf("credit: %u\n", ox_p->tloe_hdr.credit);

	printf("\n");
}

/**
 * @brief Print flits
 */
void print_flits(struct ox_packet_struct *ox_p) {

	int i;
	uint64_t flit;
	printf("flit cnt: %d\n", ox_p->flit_cnt);

	for (i = 0; i < ox_p->flit_cnt; i++) {
		flit = ox_p->flits[i];
		printf("flit[%d]: 0x%lx\n", i, flit);
	}

	printf("\n");
}

/**
 * @brief Print tileLink message header
 */
void print_tl_msg_header(struct tl_msg_header_chan_AD *tl_header) {
	printf("<<tl_msg>>\n");
	printf("chan = %u \n", tl_header->chan);
	printf("opcode = %u \n", tl_header->opcode);
	printf("param = %u \n", tl_header->param);
	printf("size = %u \n", tl_header->size);
	printf("domain = %u \n", tl_header->domain);
	printf("err = %u \n", tl_header->err);
	printf("source = %u \n", tl_header->source);
}

/**
 * @brief Print payload in Hex format
 */
void print_payload(char *data, int size) {
	int i, j;

    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0) {
            printf("\t"); 
            for (j = i - 16; j < i; j++) {
                if (data[j] >= 32 && data[j] < 128)
                    printf("%c", (unsigned char)data[j]);
                else
                    printf(".");
            }
            printf("\n");
        }

	if ( (i % 8) == 0 && (i % 16) != 0 ) printf(" ");
        printf(" %02X", (unsigned char) data[i]);		// print DATA

        if (i == size - 1) {
            for (j = 0; j < (15 - (i % 16)); j++)
                printf("   ");

            printf("\t");

            for (j = (i - (i % 16)); j <= i; j++) {
                if (data[j] >= 32 && data[j] < 128)
                    printf("%c", (unsigned char) data[j]);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}

/**
 * @brief Write data to memory
 * @param 
 * @todo 
 */
void write_data(uint64_t tl_addr, uint32_t data_size, void * data) {
	uint64_t mem_offset = 0;

	mem_offset = (tl_addr - OX_START_ADDR) % MEM_SIZE;
	memcpy(mem_storage + mem_offset, data, data_size);
}

/**
 * @brief Read data from memory
 */
void read_data(uint64_t tl_addr, uint32_t data_size, void * data) {
	uint64_t mem_offset = 0;

	mem_offset = (tl_addr - OX_START_ADDR) % MEM_SIZE;
	memcpy(data, mem_storage + mem_offset, data_size);
}

/**
 * @brief Handling packet typed "NORMAL"
 */
int handle_normal_packet(int sockfd, int connection_id, struct ox_packet_struct * recv_ox_p)
{
	int i;
	uint64_t mask;
	uint64_t be64_temp;
	uint64_t tl_addr;
	void * data;
	uint32_t data_size;
	uint64_t send_flits[256]; //256*8 = 2kb
	char send_buffer[RECV_BUFFER_SIZE];
	int send_buffer_size = 0;

	struct ox_packet_struct send_ox_p;
	struct tl_msg_header_chan_AD tl_msg_header;
	struct tl_msg_header_chan_AD tl_msg_ack;
	
	mask = recv_ox_p->tl_msg_mask;

	if ( mask ) {
	// Retrieve the TileLink header based on the mask 
	for (i = 0; i < sizeof(uint64_t)*8; i++) {		//TODO reduce the iteration

		//if There is no more bit==1 in mask, then exit.
		if ( mask == 0 ) break;

		if ( (mask & 1) == 1) {

			//convert TL message header as struct
			//be64_temp = be64toh(recv_ox_p->flits[i]);
			be64_temp = recv_ox_p->flits[i];
			memcpy(&(tl_msg_header), &be64_temp, sizeof(uint64_t));

			switch (tl_msg_header.chan) {
			case CHANNEL_A:
				//Initialize send ox struct
				bzero(&send_ox_p, sizeof(struct ox_packet_struct));
				send_ox_p.flits = send_flits;
				build_ethernet_header(recv_ox_p, &send_ox_p);				// build Ethernet Header

				switch (tl_msg_header.opcode) {
				case A_PUTFULLDATA_OPCODE:	//Handle write operation for 2^n byte size data
					build_tLoE_frame_header(connection_id, recv_ox_p, &send_ox_p);          // build TLoE frame header
					send_ox_p.tloe_hdr.chan = 1; //CHAN A

					// 1. get TL bus address, data pointer and size
					tl_addr = be64toh(recv_ox_p->flits[i+1]);
					data_size = 1<<tl_msg_header.size;
					data = &(recv_ox_p->flits[i+2]);
					send_ox_p.tloe_hdr.credit = tl_msg_header.size-3; //flit(8B) count
//printf("data_size=%d tl_msg_header.size=%d send_ox_p.tloe_hdr.credit=%d\n", data_size, tl_msg_header.size, send_ox_p.tloe_hdr.credit);

					// 2. copy data to mem storage - No converting to host-endian
					write_data(tl_addr, data_size, data);

					// 3. create response tl_msg based on received tl_msg
					memcpy(&tl_msg_ack, &tl_msg_header, sizeof(struct tl_msg_header_chan_AD));
					tl_msg_ack.err = 0;
					tl_msg_ack.opcode = 0; //AccessAck
					tl_msg_ack.chan = 4; //channel D

					// 4. append response tl_msg to send_ox_p's flits(converted to big endian)
					be64_temp = htobe64(*(uint64_t*)&(tl_msg_ack));
					send_ox_p.flits[send_ox_p.flit_cnt] = be64_temp;
					send_ox_p.tl_msg_mask |= 1<<send_ox_p.flit_cnt;
					send_ox_p.flit_cnt += 1;

					// 5. build OX packet with ox_struct and flits
					ox_struct_to_packet(&send_ox_p, send_buffer, &send_buffer_size);

#if 0
                                        PRINT_LINE("----------------   SEND   ----------------\n");
                                        print_payload(send_buffer, send_buffer_size);
                                        printf("------------------------------------------\n\n");
#endif
                                        // 6. Send AccessAck packet
                                        send(sockfd, send_buffer, send_buffer_size, 0);
					break;

				case A_GET_OPCODE: // return ack using Channel D (AccessAckData)
					build_tLoE_frame_header(connection_id, recv_ox_p, &send_ox_p);          // build TLoE frame header
					send_ox_p.tloe_hdr.chan = 1; //CHAN A

					// 1. get TL bus address, data pointer and size
					tl_addr = be64toh(recv_ox_p->flits[i+1]);
					data_size = 1<<tl_msg_header.size;

					// 2. create response tl_msg based on received tl_msg
					memcpy(&tl_msg_ack, &tl_msg_header, sizeof(struct tl_msg_header_chan_AD));
					tl_msg_ack.err = 0;
					tl_msg_ack.opcode = 1; //AccessAckData
					tl_msg_ack.chan = 4; //channel D

					// 3. Add response tl_msg to send_ox_p as a flit(converted to big endian)
					be64_temp = htobe64(*(uint64_t*)&(tl_msg_ack));
					send_ox_p.flits[send_ox_p.flit_cnt] = be64_temp;
					send_ox_p.tl_msg_mask |= 1<<send_ox_p.flit_cnt;
					send_ox_p.flit_cnt += 1;
					send_ox_p.tloe_hdr.credit = 0; 

					// 4. copy data from mem storage to flits
					read_data(tl_addr, data_size, &(send_ox_p.flits[send_ox_p.flit_cnt]));
PRINT_LINE("tl_addr=%lx data_size=%d data=%lx\n", tl_addr, data_size, send_ox_p.flits[send_ox_p.flit_cnt]);
					send_ox_p.flit_cnt += (data_size+7)/sizeof(uint64_t);


					// 5. build OX packet with ox_struct and flits
					ox_struct_to_packet(&send_ox_p, send_buffer, &send_buffer_size);
#if 0
                    printf("----------------   SEND   ----------------\n");
                    print_payload(send_buffer, send_buffer_size);
                    printf("------------------------------------------\n\n");
#endif
 
					// 6. Send AccessAckData packet
					send(sockfd, send_buffer, send_buffer_size, 0);
					break;
				case A_PUTPARTIALDATA_OPCODE:
					//TBD
				default:
					PRINT_LINE("OP_CODE=%d is not supported.\n", tl_msg_header.opcode);
					return 0;
				}
				//TBD
		
				break;
			case CHANNEL_C: // Channel C
				//TBD
			case CHANNEL_E: // Channel E
				//TBD
			case CHANNEL_B: 
			case CHANNEL_D: // Channel B, D is ignored
			default:
				PRINT_LINE("TL channel %d is not supported.\n", tl_msg_header.chan);
				break;
			}

		}
		//next mask bit
		mask >>= 1;
	}
	} else { //There is no flits in the packet, return just ack response
		send_ack(sockfd, connection_id, recv_ox_p);
	}

	return 0;
}

/**
 * @brief Get channel number from OX packet header
 */
int get_ox_msg_type(struct ox_packet_struct * ox_p)
{
	if ( !ox_p ) return -1;
//	printf("msg_type: %u\n", ox_p->tloe_hdr.msg_type);
	return ox_p->tloe_hdr.msg_type;
}

/**
 * @brief main function
 */
int main(int argc, char ** argv)
{
	int sockfd = 0;
	int recv_size = 0;
	char recv_buffer[RECV_BUFFER_SIZE];
	struct sockaddr_ll saddr;
	struct ox_packet_struct ox_p;
	int connection_id = 0;
#if SIM
	int msg_type = 0;
#endif

	if (argc <=1) {
		printf("Usage: sudo %s [dev name], (ex sudo %s ens1)\n", argv[0], argv[0]);
		return 0;
	}

	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sockfd == -1) {
		perror("Socket creation error.\n");
		return sockfd;
	}

	bzero(&saddr, sizeof(struct sockaddr_ll));
	saddr.sll_family = AF_PACKET;
	saddr.sll_protocol = htons(ETH_P_ALL);
	saddr.sll_ifindex = if_nametoindex(argv[1]);

	if ( saddr.sll_ifindex == 0 ) {
		perror("Socket bind error\n");
		goto close;
	}

	if (bind(sockfd, (struct sockaddr*) &saddr, sizeof(saddr)) < 0) {
		perror("Socket bind error\n");
		goto close;
	}

	while(1) {
		recv_size = recv(sockfd, recv_buffer, RECV_BUFFER_SIZE, 0);

		// Checking whether the packet is omnixtend one
		if ( recv_size > 0 ) {
			struct ethhdr *etherHeader = (struct ethhdr *) recv_buffer;
			if (etherHeader->h_proto == OX_ETHERTYPE || etherHeader->h_proto == OX_ETHERTYPE_LOW)
				printf("(DEBUG) Ethe_type (AAAA) packet received.\n");
			else
				continue;
		}
#if 0
		printf("---------------- RECEIVED ----------------\n");
		print_payload(recv_buffer, recv_size);
		printf("------------------------------------------\n\n");
#endif
			
		// Reconstruct packet into a struct
		// TODO : to-be modified
		//packet_to_ox_struct(recv_buffer, recv_size, &ox_p);
		packet_to_ox_struct(recv_buffer, recv_size - 2, &ox_p);

#if SIM
		// Check Omnixtend message type from message_type field (OX 1.1)
		msg_type = get_ox_msg_type(&ox_p);

		// TODO: Check credit or channel??

		switch (msg_type) {
		case NORMAL:	// Normal packet
			connection_id = get_connection(&ox_p);

			if ( connection_id < 0 ) { // Connection not found
				break;
			}
//		printf("---------------- RECEIVED ----------------\n");
//		print_payload(recv_buffer, recv_size);
//		printf("------------------------------------------\n\n");
			handle_normal_packet(sockfd, connection_id, &ox_p);

			break;
		case ACK_ONLY: // Ack Only
			//TBD
			break; 
		case OPEN_CONN:	// Open_Connection
			connection_id = create_new_connection(&ox_p);
			if ( connection_id < 0 ) { // Connection creation fail
				printf("Connection Error! - No empty slot\n");
				goto close;
			}

			send_ack(sockfd, connection_id, &ox_p);
			break;
		case CLOSE_CONN:	// Close_Connection
			connection_id = get_connection(&ox_p);

			if ( connection_id < 0 ) { // Connection not found
				printf("Connection Error! - This connection is not found in list.\n");
				break;
			}

			send_close_connection(sockfd, connection_id, &ox_p);

			delete_connection(connection_id);
//			goto close;	//exit when connection closed. for development. remove this later.

			break;
		default: // Invalid msg_type. just ignore them
			;
		}
#else
		connection_id = 0;
		handle_normal_packet(sockfd, connection_id, &ox_p);
#endif
	}
close:
	close(sockfd);

	return 0;
}

