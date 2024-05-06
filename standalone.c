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
#include <jansson.h>
#include <pthread.h>
#define ITEMS 11
#define BUFFER_MAX 2048
#define RST_COUNT 2
#define INTER_TIME 15
#define SYN_WAIT_TIME 15
#define DIFF_THRESHOLD 100

typedef struct {
    char *key;
    const char *value;
} jsonLine;


void send_UDP (jsonLine *items);
static unsigned short compute_checksum(unsigned short *addr, unsigned int count);
unsigned short csum (unsigned short *buf, int nwords);
unsigned short compute_tcp_checksum(struct ip *pIph, unsigned short *ipPayload);
void make_SYN_packet (int sockfd, int packet_size, char *ADDR, int PORT);
json_t *json_init(char *input[]);
void recv_RST (void *res);

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
        printf("missing JSON file in cmd line arg!");
        return EXIT_FAILURE;
    }
    json_t *root = json_init(argv);
    jsonLine config[ITEMS] = {
      {"server_ip_addr", json_string_value(json_object_get(root, "server_ip_addr"))},
      {"UDP_src_port", json_string_value(json_object_get(root, "UDP_src_port"))},
      {"UDP_dest_port", json_string_value(json_object_get(root, "UDP_dest_port"))},
      {"TCP_dest_port_headSYN", json_string_value(json_object_get(root, "TCP_dest_port_headSYN"))},
      {"TCP_dest_port_tailSYN", json_string_value(json_object_get(root, "TCP_dest_port_tailSYN"))},
      {"TCP_port_preProb", json_string_value(json_object_get(root, "TCP_port_preProb"))},
      {"TCP_port_postProb", json_string_value(json_object_get(root, "TCP_port_postProb"))},
      {"UDP_packet_size", json_string_value(json_object_get(root, "UDP_packet_size"))},
      {"inter_time", json_string_value(json_object_get(root, "inter_time"))},
      {"UDP_train_size", json_string_value(json_object_get(root, "UDP_train_size"))},
      {"UDP_TTL", json_string_value(json_object_get(root, "UDP_TTL"))}
    };


    //LAST, create and start thread to call recv_RST for listening for RST packets
        // Create thread 1
        //recv_RST() func
    pthread_t thread;
    int res = 0;
    if ((pthread_create(&thread, NULL, recv_RST, (void *)&res)) != 0) {
        printf("error with creating thread\n");
    }
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
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
	    printf("ERROR opening socket");
        exit(0);
    }
        //need to enable header included so YOU make the header for the packet
            /* allow process to build IP header 
                    int one = 1;
                    const int *val = &one;
                    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));*/
    int incl_val = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &incl_val, sizeof(incl_val)) < 0) {
        printf("error setting IP header building to process");
    }
    //IMPORTANT: INTIALIZE ALL VARIABLES/PARAMETERS HERE SO FUNCTION CALLS ARE ONE AFTER ANOTHER (for seamless, little delay)
    int pack_size = atoi(config[7].value);
    int port_HEADSYN = atoi(config[3].value);
    int port_TAILSYN = atoi (config[4].value);
    char *s_addr;
    strcpy(s_addr, config[0].value);
    

        //make_HEAD_SYN()  
            //this function will take many parameters, but guaranteed one is the socket
            //two phases: making packet, and sending it
    
    //IMPLEMENT TCP CHECKSUM FUNC
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
    json_decref(root);
    close(sockfd);
    return EXIT_SUCCESS; 
}

json_t *json_init (char *input[]) {
    int json_test = 1;
    //this is to test that .json parses correctly
    FILE *fp = fopen(input[1], "r"); 
    if (!fp) {
        printf("No JSON file was given.");
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *json_buffer = malloc(file_size);
    fread(json_buffer, 1, file_size, fp);
    fclose(fp);

    json_error_t error;
    json_t *root = json_loads(json_buffer, 0, &error);
    free(json_buffer);
    if (!root) {
        fprintf(stderr, "Failed to parse JSON: %s\n", error.text);
        return NULL;
    }
    
    return root;
}

void make_SYN_packet(int sockfd, int packet_size, char *ADDR, int PORT) {
    //making the packet
    //using UDP packet size, doesn't really matter, but for contiuency
    char *buffer = (char *) malloc(packet_size + sizeof(struct tcphdr) + sizeof(struct ip));
    struct ip *iph = (struct ip*) buffer;
    struct tcphdr *tcph = (struct tcphdr*) (buffer + sizeof(struct ip));

    //iph
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof (struct ip) + sizeof(struct tcphdr) + packet_size;
    iph->ip_id = htonl(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = INADDR_ANY;
    iph->ip_dst.s_addr = inet_addr(ADDR);

    iph->ip_sum = csum((unsigned short *) buffer, iph->ip_len >> 1);

    //study this up later
    //tcphdr
    tcph->th_sport = htons(1234);
    tcph->th_dport = htons(PORT);
    tcph->th_seq = random();
    tcph->th_ack = 0;
    tcph->th_x2 = 0;
    tcph->th_off = 0;
    tcph->th_flags = TH_SYN;
    tcph->th_win = htonl(65535);
    tcph->th_sum = 0; //find tcp checksum function
    tcph->th_urp = 0;

    //this is iffy? if code doesn't work, check this FIRST lmao
    tcph->th_sum = compute_tcp_checksum(iph, (unsigned short *)tcph);


    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(ADDR);
    sin.sin_port = htons(PORT);


    //sending the packet
    int res = sendto (sockfd, buffer, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin) < 0);
    if (res < 0) {
        printf("error sending SYN packet\n");
    }
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
    if (sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) == -1) {
        printf("Error making UDP socket");
        return;
    }

    //set DF bit
    int dfval = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAG, &dfval, sizeof(dfval)) < 0) {
        printf("error with setting don't fragment bit");
    }

    //set TTL bit to default (255)
    int ttlval = atoi(items[10].value);
    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttlval, sizeof(ttlval)) < 0) 
        printf("error with setting TTL value");

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(atoi(items[2].value));
    sin.sin_addr.s_addr = inet_addr(items[0].value);


    //create buffer
    int packet_size = atoi(items[7].value);
    int train_size = atoi(items[9].value);
    int inter_time = atoi(items[8].value);
    char low_entropy_BUFFER[packet_size];
    memset(low_entropy_BUFFER, 0, packet_size);
    //first time, set timer with inter_time
            //while timer isn't == 0 (or packet count != 6000), run while loop
            //to make and send UDP packets with all 0s buffer 
    //basic timer
        int sec = 0, pak_count = 0, true_count = 0;
        clock_t before = clock();
        do {
            clock_t difference = clock() - before;
            sec = difference / CLOCKS_PER_SEC;
            //send UDP packet (6000 times haha)
            low_entropy_BUFFER[0] = pak_count & 0xFF;
            low_entropy_BUFFER[1] = pak_count & 0xFF;
            if (sendto(sockfd, low_entropy_BUFFER, packet_size, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) 
                printf("packet failed to send");
            else 
                true_count++;
            pak_count++;
        } while ((sec <= inter_time) && (pak_count <= train_size)); //items[8] is variable that holds inter_time
        printf("true_count: %d and pak_count: %d. Client/server lost %d packets from the low entropy payload", true_count, pak_count, pak_count - true_count);
    
    //second time, restart before timer and new difference timer
        //make random packet_data using random_file in ../dir
        char high_entropy_BUFFER[packet_size];
        FILE *fp;
        if ((fp = fopen("../random_file", "rb")) == NULL) {
            printf("error opening file");
        }
        fread(high_entropy_BUFFER, sizeof(char), packet_size, fp);
        fclose(fp);
        

        sec = 0, pak_count = 0, true_count = 0;
        before = clock();
        do {
            clock_t difference = clock() - before;
            sec = difference / CLOCKS_PER_SEC;
            high_entropy_BUFFER[0] = pak_count & 0xFF;
            high_entropy_BUFFER[1] = pak_count & 0xFF;
            //send UDP packet (6000 times again)
            if (sendto(sockfd, high_entropy_BUFFER, packet_size, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) 
                printf("packet failed to send");
            else 
                true_count++;
            pak_count++;
        } while ((sec <= inter_time) && (pak_count <= train_size));
        printf("true_count: %d and pak_count: %d. Client/server lost %d packets from the high entropy payload", true_count, pak_count, pak_count - true_count);
    
    close(sockfd);
}

void recv_RST (void *res) {
    sleep(SYN_WAIT_TIME);
    int sockfd;
    //typecasting our result var
    int *ans = (int *)res;
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) == -1) {
        printf("error creating socket");
        exit(EXIT_FAILURE);
    }

    //so we can access header fields
    int optval = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        printf("setsockopt failed");
        exit(EXIT_FAILURE);
    }


    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET; 
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = 0;

    if (bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    int rst_num = 0;
    float sec = 0;
    
    //while loop with 2 conditions: RST packet count is == 2, and timeout with inter_time
    //sec is used to calculate inter time, but it also is the time that will determine network compression
    clock_t before = clock();
    while (rst_num < RST_COUNT && sec <= INTER_TIME) {
        char buffer[BUFFER_MAX];
        struct sockaddr_in sender_addr;
        socklen_t sender_addr_len = sizeof(sender_addr);

        if ((recvfrom(sockfd, buffer, BUFFER_MAX, 0, (struct sockaddr *)&sender_addr, &sender_addr_len)) < 0) {
            printf("\ncould not receive RST packet");
            continue;
        }

        struct ip *iph = (struct ip *)buffer;
        struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ip));

        if (!(strcmp(tcph->th_flags, TH_RST))) {
            printf("\nreceived RST packet\n");
            rst_num++;
        }

        clock_t difference = clock() - before;
        sec = difference / CLOCKS_PER_SEC;
    }

    if (rst_num > RST_COUNT || rst_num < RST_COUNT)
        *ans = -1;
    else if (sec >= DIFF_THRESHOLD)
        *ans = 0;
    else
        *ans = 1;

    close(sockfd);
}

