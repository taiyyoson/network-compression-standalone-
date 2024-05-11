//Taiyo Williamson, 20688536
//standalone application to detect network compression


//header files
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <errno.h>
#include "cJSON.h"

//global constants
#define ITEMS 12
#define BUFFER_MAX 2048
#define RST_COUNT 2
#define DIFF_THRESHOLD 100
#define INTER_TIME 15

//struct to hold json line items
typedef struct {
    char *key;
    char *value;
} jsonLine;


void send_UDP (jsonLine *items); //sending UDP packet trains, exact same as pt 1
static unsigned short compute_checksum(unsigned short *addr, unsigned int count);//computing IP and TCP checksums
unsigned short csum (unsigned short *buf, int nwords);
unsigned short compute_tcp_checksum(struct ip *pIph, unsigned short *ipPayload);
void make_SYN_packet (int sockfd, int packet_size, char *ADDR, int PORT); //making HEAD and TAIL SYN packet, and then sending to server closed ports
cJSON *JSONObj(char *input[]); //same as pt 1, initializing json parser
void *recv_RST (void *arg); //receiving RST packets, and calculating the difference, ran in a separate thread

int main (int argc, char *argv[]) {
    /*
    1. Create raw socket for TCP SYN packet
    2. Fill the buffer with the IP header
    3. Fill the TCP header and then put it into the buffer at buffer pointer + ip header len 
    4. Send the SYN packet
    5. Repeat for UDP but using UDP header instead of TCP
    6. Listen for RST packets and then use that to calculate the time difference
    */
    
    //FIRST, parse json file and store in struct like in pt 1 client.c
    if (argc < 2) {
        printf("missing JSON file in cmd line arg!\n");
        return EXIT_FAILURE;
    }
    //array of structs, representing config.json
    cJSON *json = JSONObj(argv);
  
    // access the JSON data 
    cJSON *server_ip_addr = cJSON_GetObjectItemCaseSensitive(json, "server_ip_addr"); 
    //printf("%s\n", server_ip_addr->valuestring);
    cJSON *UDP_src_port = cJSON_GetObjectItemCaseSensitive(json, "UDP_src_port"); 
    cJSON *UDP_dest_port = cJSON_GetObjectItemCaseSensitive(json, "UDP_dest_port"); 
    cJSON *TCP_dest_port_headSYN = cJSON_GetObjectItemCaseSensitive(json, "TCP_dest_port_headSYN"); 
    cJSON *TCP_dest_port_tailSYN = cJSON_GetObjectItemCaseSensitive(json, "TCP_dest_port_tailSYN"); 
    cJSON *TCP_port_preProb = cJSON_GetObjectItemCaseSensitive(json, "TCP_port_preProb"); 
    cJSON *TCP_port_postProb = cJSON_GetObjectItemCaseSensitive(json, "TCP_port_postProb"); 
    cJSON *UDP_packet_size = cJSON_GetObjectItemCaseSensitive(json, "UDP_packet_size"); 
    cJSON *inter_time = cJSON_GetObjectItemCaseSensitive(json, "inter_time"); 
    cJSON *UDP_train_size = cJSON_GetObjectItemCaseSensitive(json, "UDP_train_size"); 
    cJSON *UDP_TTL = cJSON_GetObjectItemCaseSensitive(json, "UDP_TTL"); 
    cJSON *server_wait_time = cJSON_GetObjectItemCaseSensitive(json, "server_wait_time");

    jsonLine config[ITEMS] = {
      {"server_ip_addr", server_ip_addr->valuestring},
      {"UDP_src_port", UDP_src_port->valuestring},
      {"UDP_dest_port", UDP_dest_port->valuestring},
      {"TCP_dest_port_headSYN", TCP_dest_port_headSYN->valuestring},
      {"TCP_dest_port_tailSYN", TCP_dest_port_tailSYN->valuestring},
      {"TCP_port_preProb", TCP_port_preProb->valuestring},
      {"TCP_port_postProb", TCP_port_postProb->valuestring},
      {"UDP_packet_size", UDP_packet_size->valuestring},
      {"inter_time", inter_time->valuestring},
      {"UDP_train_size", UDP_train_size->valuestring},
      {"UDP_TTL", UDP_TTL->valuestring},
      {"server_wait_time", server_wait_time->valuestring}
    };


    //LAST, create and start thread to call recv_RST for listening for RST packets
        // Create thread 1
        //recv_RST() func
    pthread_t thread;
    int res = 0;
    if ((pthread_create(&thread, NULL, recv_RST, (void *)&res)) != 0) {
        printf("error with creating thread\n");
    }
    printf("Made thread!\n");
            //creates socket using IPPROTO_IP, not IPPROTO_TCP
            //QUESTIONS: figure out if you need to bind socket, what to put in struct sockaddr_in, etc
                //do we need to listen?? or just receive? figure this out
                //we do need to account for timeout, if no RSTs are received
            //start listening for RST packets
                //after receive first packet, record time, then record time again after you receive the second RST packet
            //recv_RST will be a void func, but will TAKE an int ptr, store 1 if network compression, 0 if none, -1 if error
        //remember, call pthread_join for this func after sending tail SYN packet, if before, infinite loop 




    //SECOND, open socket for SYN head and tail packets (you will pass this into make_head and make_tail func), remember this is a raw socket
    int sockfd;
    if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
	    printf("ERROR opening socket\n");
        exit(0);
    }
    printf("Socket created!\n");
        //need to enable header included so YOU make the header for the packet
            /* allow process to build IP header
                    int one = 1;
                    const int *val = &one;
                    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));*/
    int incl_val = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &incl_val, sizeof(incl_val)) < 0) {
        printf("error setting IP header building to process\n");
    }


    //IMPORTANT: INTIALIZE ALL VARIABLES/PARAMETERS HERE SO FUNCTION CALLS ARE ONE AFTER ANOTHER (for seamless, little delay)
    int pack_size = atoi(config[7].value);
    int port_HEADSYN = atoi(config[3].value);
    int port_TAILSYN = atoi (config[4].value);
    char *s_addr = config[0].value;
    

        //make_HEAD_SYN()  
            //this function will take many parameters, but guaranteed one is the socket
            //two phases: making packet, and sending it

    make_SYN_packet(sockfd, pack_size, s_addr, port_HEADSYN);

            //making the SYN packet, needs a couple things:
                //create buffer (must malloc) that will hold size of iphdr struct + tcphdr struct + packet size (we'll set default to something random like 50, or could jus use UDP_packet size)
                //create new ip header struct, point to beginning of buffer
                //create new tcp header struct, point to after ip header in the buffer still  
                    //must typecast
                    //Char *buffer = (char*)malloc(ip header length + tcp header length + packet length);
                    //struct ipheader *ipheader = (struct ipheader*)buffer;    
                    //*struct tcpheader *tcpheader = (struct tcpheader*)(buffer + sizeof(struct ipheader))
                //FILL all these header fields in, will take some time, use extra function if you want
                    //will need extra functions, like calculating checksum
                //create new sockaddr struct, needed to send packet
                    //fill in like usual, like in pt 1

            //sending the SYN packet
                //send it! add some error handling, then immediately exit func to start the UDP train



    //THIRD, sending UDP packet trains
        //remember, you can reuse code from pt 1, since not using raw sockets for UDP packets
        //set default TTL value tho
    send_UDP(config); 



    //FOURTH, reuse raw socket from second, but make new packe
        //make_TAIL_SYN()
            //literally identical to func for head syn, but different port
            //inefficient to make whole new function that does the same thing, but easy to identify/separate
    
    make_SYN_packet(sockfd, pack_size, s_addr, port_TAILSYN);


    //call pthread_join for the RST packet listener
    //LAST LAST, print output for network compression detection
    pthread_join(thread, NULL);

    if (res == 1) 
        printf("\nNetwork compression DETECTED!\n");
    else if (res == 0)
        printf("\nNetwork compression NOT DETECTED!\n");
    else
        printf("\nFailed to detect due to insufficient information!\n");



    //and then, DONE WITH PT 2   
    cJSON_Delete(json);
    close(sockfd);
    return EXIT_SUCCESS; 
}

cJSON *JSONObj(char *input[]) {
    // open the file 
    FILE *fp = fopen(input[1], "r"); 
    if (fp == NULL) { 
        printf("Error: Unable to open the file.\n"); 
        exit(EXIT_FAILURE); 
    } 
  
    // read the file contents into a string 
    char buffer[1024]; 
    int len = fread(buffer, 1, sizeof(buffer), fp); 
    fclose(fp);

    // parse the JSON data 
    cJSON *json = cJSON_Parse(buffer); 
    if (json == NULL) { 
        const char *error_ptr = cJSON_GetErrorPtr(); 
        if (error_ptr != NULL) { 
            printf("Error: %s\n", error_ptr); 
        } 
        cJSON_Delete(json); 
        exit(EXIT_FAILURE);
    } 

    return json;
}

void make_SYN_packet(int sockfd, int packet_size, char *ADDR, int PORT) {
    //making the packet
    //using UDP packet size, doesn't really matter, but for contiuency
    char *buffer = (char *) malloc(packet_size + sizeof(struct tcphdr) + sizeof(struct ip));
    //assigning ip and tcp header fields in the buffer
    struct ip *iph = (struct ip*) buffer;
    struct tcphdr *tcph = (struct tcphdr*) (buffer + sizeof(struct ip));

    //iph
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof (struct ip) + sizeof(struct tcphdr) + packet_size;
    iph->ip_id = htons(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_sum = 0; //assign to 0 first
    iph->ip_src.s_addr = INADDR_ANY;
    iph->ip_dst.s_addr = inet_addr(ADDR);

    iph->ip_sum = csum((unsigned short *) buffer, iph->ip_len >> 1);

    //tcphdr
    tcph->th_sport = htons(1234);
    tcph->th_dport = htons(PORT);
    tcph->th_seq = random();
    tcph->th_ack = 0;
    tcph->th_x2 = 0;
    tcph->th_off = 0;
    tcph->th_flags = TH_SYN;
    tcph->th_win = htons(65535);
    tcph->th_sum = 0; //assign to 0 first
    tcph->th_urp = 0;

    tcph->th_sum = compute_tcp_checksum(iph, (unsigned short *)tcph);


    //fill in server info
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);
    if (!(inet_pton(AF_INET, ADDR, &(sin.sin_addr)) > 0)) {
        printf("standalone.c 262: ERROR assigning address to socket\n");
        exit(EXIT_FAILURE);
    }


    //sending the packet
    int res = sendto (sockfd, buffer, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    if (res < 0) {
        printf("standalone.c 270: error sending SYN packet\n");
    }
    else 
        printf("Sent SYN packet!\n");
}

//2 diff checksum functions, do the same thing
//i will be using csum
unsigned short csum (unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}
static unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
  register unsigned long sum = 0;
  while (count > 1) {
    sum += * addr++;
    count -= 2;
  }
  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&htons(0xFF00));
  }
  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  //one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}

//tcp checksum function, uses pseudo IP header
/* set tcp checksum: given IP header and tcp segment */
unsigned short compute_tcp_checksum(struct ip *pIph, unsigned short *ipPayload) {
    register unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->ip_len) - (pIph->ip_hl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    //the source ip
    sum += ((pIph->ip_src.s_addr)>>16)&0xFFFF;
    sum += ((pIph->ip_src.s_addr))&0xFFFF;
    //the dest ip
    sum += ((pIph->ip_dst.s_addr)>>16)&0xFFFF;
    sum += ((pIph->ip_dst.s_addr))&0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcpLen);
 
    //add the IP payload
    //initialize checksum to 0
    tcphdrp->th_sum = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload)&htons(0xFF00));
    }
      //Fold 32-bit sum to 16 bits: add carrier to result
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      sum = ~sum;
    //set computation result
    return (unsigned short) sum;
}


void send_UDP (jsonLine *items) { 
    //create socket
    int sockfd;
    if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
        printf("Error making UDP socket\n");
        exit(EXIT_FAILURE);
    }

    //set DF bit
    int dfval = IP_PMTUDISC_DO; //linux df bit
    if (setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &dfval, sizeof(dfval)) < 0) { //if linux, use IP_MTU_DISCOVER & IP_PMTUDISC_DO
        printf("error with setting don't fragment bit\n");
        exit(EXIT_FAILURE);
    }

    //fill server info
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(atoi(items[2].value));
    if (!(inet_pton(AF_INET, items[0].value, &(sin.sin_addr)) > 0)) {
        printf("client.c 209: ERROR assigning address to socket\n");
        exit(EXIT_FAILURE);
    }

    printf("Set server info!\n");

    //initialize necessary variables
    int packet_size = atoi(items[7].value);
    int train_size = atoi(items[9].value);
    int inter_time = atoi(items[8].value) * 1000;
    //fill buffer with 1000 0s
    char low_entropy_BUFFER[packet_size];
    memset(low_entropy_BUFFER, 0, packet_size);
    //first time, set timer with inter_time
            //while timer isn't == inter_time (or packet count != 6000), run while loop
            //to make and send UDP packets with all 0s buffer 
    int server_wait_time = atoi(items[11].value);

    //basic timer
        printf("Sending low entropy payload!\n");
        int pak_count = 0;
        do {
            //send UDP packet (6000 times haha)
            //setting packet ID
            low_entropy_BUFFER[0] = pak_count & 0xFF;
            low_entropy_BUFFER[1] = pak_count & 0xFF;
            if (sendto(sockfd, low_entropy_BUFFER, packet_size, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) 
                printf("packet failed to send\n");
            pak_count++;
        } while (pak_count <= train_size);
        printf("Low entropy payload sent!\n");


    //second time, restart before timer and new difference timer
        //make random packet_data using random_file in ../dir
        char high_entropy_BUFFER[packet_size];
        FILE *fp;
        if ((fp = fopen("random_file", "rb")) == NULL) {
            printf("error opening file\n");
            exit(EXIT_FAILURE);
        }
        fread(high_entropy_BUFFER, sizeof(char), packet_size, fp);
        fclose(fp);
        
        printf("Sending high entropy payload\n"); 
        pak_count = 0;
        do {
            //setting packet ID
            high_entropy_BUFFER[0] = pak_count & 0xFF;
            high_entropy_BUFFER[1] = pak_count & 0xFF;
            //send UDP packet (6000 times again)
            if (sendto(sockfd, high_entropy_BUFFER, packet_size, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) 
                printf("packet failed to send\n");
            pak_count++;
        } while (pak_count <= train_size);
        printf("High entropy payload sent!\n");
    close(sockfd);
}

void *recv_RST (void *arg) {
    int sockfd;
    //typecasting our result var, this points to our result in main that we use to detect network compression
    int *ans = (int *)arg;
    //creating socket
    if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
        printf("error creating socket\n");
        exit(EXIT_FAILURE);
    }
    printf("created socket for RSTs!\n");

    //so we can access header fields
    int optval = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        printf("setsockopt failed\n");
        exit(EXIT_FAILURE);
    }
    printf("setsockopt RST HDRINCL worked\n");

    struct timeval timeout;
    timeout.tv_sec = INTER_TIME;
    timeout.tv_usec = 0;
    //creates timeout for RST packets, if longer than INTER_TIME (15 seconds), timeout, move on
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) { //basically an inactivity timer
        printf("error with setting timeout\n");
        exit(EXIT_FAILURE);
    }

    //filling in server info
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET; 
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = 0;

    //bind, isn't necessary but nice practice
    if (bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("Bind failed\n");
        exit(EXIT_FAILURE);
    }
    printf("bind worked (do we need it?)\n");

    //incrementing these while listening for RST packets
    int rst_num = 0, timer = 0;
    long double sec = 0;

    char buffer[BUFFER_MAX];
    struct sockaddr_in sender_addr;
    clock_t before = clock();
    socklen_t sender_addr_len = sizeof(sender_addr);
    
    for (int i=0; i < RST_COUNT; i++) {
        int rec_RST = recvfrom(sockfd, buffer, BUFFER_MAX, 0, (struct sockaddr *)&sender_addr, &sender_addr_len);
        if (rec_RST <= 0) {
            printf("could not receive RST packet\n");
            continue;
        }
        else if (rec_RST > 0) {
            //parse through the packet, access tcph is what we want
            struct ip *iph = (struct ip *)buffer;
            struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ip));

            //is this packet a RST packet? if so, increase the count, we should be getting two
            if ((tcph->th_flags) == TH_RST) {
                printf("\nreceived RST packet\n");
                rst_num++;
                if (timer == 0) {
                    before = clock();
                    timer++;
                }
            }
        }
    }


    //chaning output res
    if (rst_num < RST_COUNT) {
        *ans = -1;
        printf("Didn't receive enough RST packets\n");
    }
    else if (sec >= DIFF_THRESHOLD) {
        *ans = 0;
        printf("Received RST packets, but res = 0\n");
    }
    else {
        *ans = 1;
        printf("Received RST packets, res = 1\n");
    }

    close(sockfd);
    return NULL;
}


