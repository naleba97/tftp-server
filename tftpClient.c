#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>

#define PORT_NUM "69"
#define PACKET_SIZE 516
#define COMMAND_SIZE 256
#define HOSTNAME_LEN 100
#define DEFAULT_MODE "OCTET"

//localhost = naleba97-Inspiron-15-7569
//command = ./tftpClient naleba97-Inspiron-15-7569 -w test.txt

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

int checkForErrors(const char* buffer){
	if(buffer[1] == 5){
		fprintf(stderr, "TFTP Error Code (%d): %s\n", ntohs(((uint16_t *)(buffer))[1]), buffer+4);
		return 1;
	}
	return 0;
}

int doesFileExist(const char *filename){
	struct stat st;
	int result = stat(filename, &st);
	return result == 0;
}

int getChoice(){
	char choice = '\0';
	while(choice != 'y' && choice != 'n'){
		scanf("%c", &choice);
	}
	if(choice == 'y')
		return 1;
	else
		return 0;
}

void getInput(char *input, int* argcInput, char** argvInput){
	input = (char *)malloc(sizeof(char) * COMMAND_SIZE);
	fgets(input, COMMAND_SIZE, stdin);
	char* pch = strtok(input, " ");
	while(pch != NULL){
		argcInput++;
		pch = strtok(NULL, " ");
	}
}

void getAckPacket(char *ackPacket, uint16_t *packetNum){
	memset(ackPacket, 0, PACKET_SIZE);
	ackPacket[0] = 0;
	ackPacket[1] = 4;
	uint16_t* numPtr = ackPacket;
	numPtr[1] = htons(*packetNum);
}

int getReadPacket(char *readPacket, const char *filename){
	memset(readPacket, 0, PACKET_SIZE);
	readPacket[0] = 0;
	readPacket[1] = 1;
	strcat(readPacket+2, filename);
	strcat(readPacket+2+strlen(filename)+1, DEFAULT_MODE);
	return 2 + strlen(filename) + 1 + strlen(DEFAULT_MODE) + 1;
}

//for now, the mode will default to OCTET
int getWritePacket(char *writePacket, const char *filename){
	memset(writePacket, 0, PACKET_SIZE);
	writePacket[0] = 0;
	writePacket[1] = 2;
	strcat(writePacket+2, filename);
	strcat(writePacket+2+strlen(filename)+1, DEFAULT_MODE);
	return 2 + strlen(filename) + 1 + strlen(DEFAULT_MODE) + 1;
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

int main(int argc, char *argv[]){
	int status;
	struct addrinfo hints, *res, *p;
	int sockfd;
	struct sockaddr_storage their_addr;
	char buffer[PACKET_SIZE];
	int yes = 1;
	uint16_t packetNum = 1;

	//timeval struct used for timeouts
	struct timeval timeout;
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	if(argc > 4){
		fprintf(stderr, "usage: ./tftpClient [hostname] [-r -w] [filename]");
		return 1;
	}

	memset(&hints, 0, sizeof(hints)); // clear the struct
	hints.ai_family = AF_UNSPEC; //IPv4 or IPv6, doesn't matter
	hints.ai_socktype = SOCK_DGRAM; // UDP stream sockets
	hints.ai_flags = AI_PASSIVE; // fill in localhost IP address

	if((status = getaddrinfo(argv[1], PORT_NUM, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo error (tftp port): %s\n", gai_strerror(status));
		return 2;
	}

	for(p = res; p != NULL; p = p->ai_next){
		if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
			fprintf(stderr, "get file descriptor with socket() error: %s\n", gai_strerror(sockfd));
			continue;
		}

		setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
		setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
		setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

		break;
	}

	if(p == NULL) {
		fprintf(stderr, "unable to bind socket to port \"tftp\"");
		return 3;
	}

	int arg, flag; //flag = 0 --> read, flag = 1 --> write
	if((arg = (getopt(argc, argv, "rw"))) != -1) {
		switch(arg){
			case 'r':
				flag = 0;
				break;
			case 'w':
				flag = 1;
				break;
			default:
				fprintf(stderr, "invalid argument: read -r, write -w\n");
				return 4;
				break;
		}
	}
	else{
		fprintf(stderr, "please specify valid argument: read -r, write -w\n");
		return 4;
	}


	FILE* fileptr;
	

	if(!flag){ // read
		printf("read\n");
		if(doesFileExist(argv[3])){
			fprintf(stderr, "file already exists: are you sure you want to overwrite %s? (y/n)\n", argv[3]);
			if(!getChoice()) return 5;
		}

		printf("Sending read request...\n");
		int packetLen = getReadPacket(buffer, argv[3]);

		int numBytes;
		if((numBytes = sendto(sockfd, buffer, packetLen, 0, p->ai_addr, p->ai_addrlen)) == -1){
			fprintf(stderr, "failed to send read request packet\n");
			return 6;
		}

		int addr_len = sizeof(their_addr); 

		fileptr = fopen(argv[3], "wb");


		do{
			if((numBytes = recvfrom(sockfd, buffer, PACKET_SIZE, 0,
				(struct sockaddr *)&their_addr, &addr_len)) == -1){
				fprintf(stderr, "data packet failed to be received\n");
			}

			if(checkForErrors(buffer)){
				return 9001;
			}

			fwrite(buffer+4, sizeof(char), numBytes-4, fileptr);

			packetNum = ntohs(((uint16_t *)(buffer))[1]);
			getAckPacket(buffer, &packetNum);
			if(sendto(sockfd, buffer, 4, 0, 
				(struct sockaddr *)&their_addr, addr_len) == -1){
				fprintf(stderr, "data packet acknolwedgement failed to be sent\n");
			}
			printf("Receiving data size of packet %d: %d\n", packetNum, numBytes);
		} while (numBytes == 516);

		fclose(fileptr);

	}
	else{ // write

		if(!doesFileExist(argv[3])){
			fprintf(stderr, "file %s does not exist\n", argv[3]);
			return 5;
		}

		printf("Sending write request...\n");
		int packetLen = getWritePacket(buffer, argv[3]);

		int numBytes;
		if((numBytes = sendto(sockfd, buffer, packetLen, 0, p->ai_addr, p->ai_addrlen)) == -1){
			fprintf(stderr, "failed to send write request packet\n");
			return 6;
		}

		int addr_len = sizeof(their_addr); 
		while(buffer[1] != 4){
			if((numBytes = recvfrom(sockfd, buffer, PACKET_SIZE, 0, 
				(struct sockaddr *)&their_addr, &addr_len)) == -1){
				fprintf(stderr, "did not receive write acknowledgement\n");
				return 7;
			}
		}
		printPortName(&their_addr);
		printf("Acknowledgement received.\n", numBytes);

		fileptr = fopen(argv[3], "rb");
		fseek(fileptr, 0, SEEK_END);
		long int fileSize = ftell(fileptr); //filesize is in bytes
		fseek(fileptr, 0, SEEK_SET);
		int dataSz;
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
	}
	

	// while(1){
		// printf("tftp> ");
		// char *input;
		// int *argcInput;
		// char **argvInput;
		// getInput(input, argcInput, argvInput);
		// processCommand();
		// freeCommand(input, argcInput, argvInput);
	// }

}