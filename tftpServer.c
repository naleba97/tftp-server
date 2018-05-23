#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/stat.h>

#define PORT_NUM "69"
#define RAND_PORT "9450"
#define PACKET_SIZE 516
#define MODE_LEN 32
#define FILENAME_LEN 256

typedef enum {
	UNDEFINED,
	FILE_NOT_FOUND,
	ACCESS_DENIED,
	DISK_FULL,
	ILLEGAL_OP,
	UNKNOWN_TID,
	FILE_ALREADY_EXISTS,
	NO_SUCH_USER
} error_t;

typedef enum{
	RRQ,
	WRQ,
	DATA,
	ACK,
	ERROR
} packet_t;


void sigchld_handler(int s)
{
	 // waitpid() might overwrite errno, so we save and restore it:
	 int saved_errno = errno;
	 while(waitpid(-1, NULL, WNOHANG) > 0);
	 errno = saved_errno;
}

void printPortName(struct sockaddr_storage *p){
	if(p->ss_family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)(p);
		printf("Connected to port: %d\n", htons(ipv4->sin_port));
	}
	else{
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)(p);
		printf("Connected to port: %d\n", htons(ipv6->sin6_port));
	}
}

int doesFileExist(const char *filename){
	struct stat st;
	int result = stat(filename, &st);
	return result == 0;
}

void getAckPacket(char *ackPacket, uint16_t *packetNum){
	memset(ackPacket, 0, PACKET_SIZE);
	ackPacket[0] = 0;
	ackPacket[1] = 4;
	uint16_t* numPtr = ackPacket;
	numPtr[1] = htons(*packetNum);
	//printf("%d %d, %d\n", ackPacket[2], ackPacket[3], numPtr[1]);
	//(*packetNum)++;
}

int getDataPacket(char *dataPacket, FILE *fileptr, long int fileSize, uint16_t *packetNum){
	memset(dataPacket, 0, PACKET_SIZE);
	dataPacket[0] = 0;
	dataPacket[1] = 3;
	uint16_t *numPtr = dataPacket;
	numPtr[1] = htons(*packetNum);
	
	int numBytes = fread(dataPacket+4, sizeof(char), 512, fileptr);
	return numBytes;
}

int getErrorPacket(char *errorPacket, error_t code){
	memset(errorPacket, 0, PACKET_SIZE);
	errorPacket[0] = 0;
	errorPacket[1] = 5;
	uint16_t *numPtr = errorPacket;
	switch(code){
		case UNDEFINED:
			numPtr[1] = htons(0);
			strcat(errorPacket+4, "Not defined, see error message (if any).");
			break;
		case FILE_NOT_FOUND:
			numPtr[1] = htons(1);
			strcat(errorPacket+4, "File not found.");
			break;
		case ACCESS_DENIED:
			numPtr[1] = htons(2);
			strcat(errorPacket+4, "Access violation.");
			break;
		case DISK_FULL:
			numPtr[1] = htons(3);
			strcat(errorPacket+4, "Disk full or allocation exceeded.");
			break;
		case ILLEGAL_OP:
			numPtr[1] = htons(4);
			strcat(errorPacket+4, "Illegal TFTP operation.");
			break;
		case UNKNOWN_TID:
			numPtr[1] = htons(5);
			strcat(errorPacket+4, "Unknown transfer ID.");
			break;
		case FILE_ALREADY_EXISTS:
			numPtr[1] = htons(6);
			strcat(errorPacket+4, "File already exists.");
			break;
		case NO_SUCH_USER:
			numPtr[1] = htons(7);
			strcat(errorPacket+4, "No such user.");
			break;
	}
	return 4 + strlen(errorPacket+4);
}

void parseRequest(const char *request, char *mode, char *filename){
	memset(mode, 0, MODE_LEN);
	memset(filename, 0, FILENAME_LEN);
	int j;
	int idx = 0;
	for(j = 2; request[j] != 0; j++){
		filename[idx] = request[j];
		idx++;
	}
	idx = 0;
	for(j++; request[j] != 0; j++){
		mode[idx] = request[j];
		idx++;
	}
}

packet_t processPacket(const char *packet){
	switch(packet[1]){
		case 1:
			return RRQ;
		case 2:
			return WRQ;
		case 3:
			return DATA;
		case 4:
			return ACK;
	}
	return ERROR;
}

int main(int argc, char *argv[]){

	int status;
	int dataSz; //used to store the num of bytes of a packet
	struct addrinfo hints, *res, *p;
	int sockfd, new_fd;
	struct sockaddr_storage their_addr;
	struct sigaction sa;
	char buffer[PACKET_SIZE]; //clear this after each request
	char mode[MODE_LEN]; //clear this after each request
	char filename[FILENAME_LEN]; //clear this after each request
	uint16_t packetNum = 0;
	int yes = 1;

	if(argc > 2){
		fprintf(stderr, "usage: ./tftpServer [directory]");
		return 1;
	}

	memset(&hints, 0, sizeof(hints)); // clear the struct
	hints.ai_family = AF_UNSPEC; //IPv4 or IPv6, doesn't matter
	hints.ai_socktype = SOCK_DGRAM; // UDP stream sockets
	hints.ai_flags = AI_PASSIVE; // fill in localhost IP address

	if((status = getaddrinfo(NULL, PORT_NUM, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo error (tftp port): %s\n", gai_strerror(status));
		return 2;
	}


	for(p = res; p != NULL; p = p->ai_next){
		if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
			fprintf(stderr, "get file descriptor with socket() error (sockfd): %s\n", gai_strerror(errno));
			continue;
		}

		setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

		if(bind(sockfd, p->ai_addr, p->ai_addrlen) == -1){
			close(sockfd);
			perror("binding socket to port failed (sockfd):");
			continue;
		}
		break;		
	}

	if(p == NULL) {
		fprintf(stderr, "unable to bind socket to port \"tftp\"");
		return 3;
	}

	int addr_len = sizeof(their_addr);
	while(1){

		printf("Waiting for client connection...\n");
		int numBytes;
		if((numBytes = recvfrom(sockfd, buffer, PACKET_SIZE, 0, 
			(struct sockaddr *)&their_addr, &addr_len)) == -1){
			fprintf(stderr, "fatal error: recv() failed\n");
			return 4;
		}

		sa.sa_handler = sigchld_handler; // reap all dead processes
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_RESTART;
		if (sigaction(SIGCHLD, &sa, NULL) == -1) {
			perror("sigaction");
			exit(1);
		}

		if(!fork()){
			close(sockfd);
			//printPortName(&their_addr);
			//printf("Num bytes Received: %d\n", numBytes);

			packet_t packetStatus = processPacket(buffer);
			if(packetStatus == ERROR){
				fprintf(stderr, "packet received has an erroneous opcode.\n");
				return 5;
			}

			if((new_fd = socket(their_addr.ss_family, SOCK_DGRAM, 0)) == -1){
				fprintf(stderr, "get file descriptor with socket() error (new_fd): %s\n", gai_strerror(errno));
				exit(1);
			}

			if(packetStatus == RRQ){
				packetNum = 1;
				parseRequest(buffer, mode, filename);

				if(!doesFileExist(filename)){
					dataSz = getErrorPacket(buffer, FILE_NOT_FOUND);
					if((numBytes = sendto(sockfd, buffer, dataSz, 0, 
						(struct sockaddr *)&their_addr, addr_len)) == -1){
						fprintf(stderr, "did not send error packet (1) successfully\n");
					}
					exit(1);
				}

				FILE *fileptr;
				printf("Reading from %s...\n", filename);
				fileptr = fopen(filename, "rb");

				fseek(fileptr, 0, SEEK_END);
				long int fileSize = ftell(fileptr); //filesize is in bytes
				fseek(fileptr, 0, SEEK_SET);
				do{
					dataSz = getDataPacket(buffer, fileptr, fileSize, &packetNum);
					do{
						printf("Sending data size of packet %d: %d\n", packetNum, dataSz+4);
						if((numBytes = sendto(sockfd, buffer, dataSz+4, 0, 
							(struct sockaddr *)&their_addr, addr_len)) == -1){
							fprintf(stderr, "did not send data packet successfully");
						}
						if((numBytes = recvfrom(sockfd, buffer, PACKET_SIZE, 0,
							(struct sockaddr *)&their_addr, &addr_len)) == -1){
							fprintf(stderr, "did not receive data ack packet successfully");
						}
					} while (ntohs(((uint16_t *)(buffer))[1]) != packetNum);

					packetNum++;
				} while (dataSz == 512);

				fclose(fileptr);
			}
			if(packetStatus == WRQ){
				parseRequest(buffer, mode, filename);

				FILE *fileptr;
				printf("Writing to %s...\n", filename);
				fileptr = fopen(filename, "wb"); 

				getAckPacket(buffer, &packetNum);
				if((numBytes = sendto(new_fd, buffer, 4, 0,
					(struct sockaddr *)&their_addr, addr_len)) == -1){
					fprintf(stderr, "fatal error: sending write request acknowledge failed\n");
					return 6;
				}
				do{
					if((numBytes = recvfrom(new_fd, buffer, PACKET_SIZE, 0,
						(struct sockaddr *)&their_addr, &addr_len)) == -1){
						fprintf(stderr, "data packet failed to be received\n");
					}
					fwrite(buffer+4, sizeof(char), numBytes-4, fileptr);

					packetNum = ntohs(((uint16_t *)(buffer))[1]);
					getAckPacket(buffer, &packetNum);
					if(sendto(new_fd, buffer, 4, 0, 
						(struct sockaddr *)&their_addr, addr_len) == -1){
						fprintf(stderr, "data packet acknolwedgement failed to be sent\n");
					}
					printf("Receiving data size of packet %d: %d\n", packetNum, numBytes);
				} while (numBytes == 516);

				fclose(fileptr);
			}
			exit(1);
		}
	}
	freeaddrinfo(res);
}
