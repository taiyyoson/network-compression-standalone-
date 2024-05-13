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
typedef struct 
{
    char *key;
    char *value;
} jsonLine;

//functions made, proper descriptions given at actual function bodies
void send_UDP (jsonLine *items); //sending UDP packet trains, exact same as pt 1
static unsigned short compute_checksum(unsigned short *addr, unsigned int count);//computing IP and TCP checksums
unsigned short csum (unsigned short *buf, int nwords);
unsigned short compute_tcp_checksum(struct ip *pIph, unsigned short *ipPayload);
void make_SYN_packet (int sockfd, int packet_size, char *ADDR, int PORT); //making HEAD and TAIL SYN packet, and then sending to server closed ports
cJSON *JSONObj(char *input[]); //same as pt 1, initializing json parser
void *recv_RST (void *arg); //receiving RST packets, and calculating the difference, ran in a separate thread

/***
 * main makes the function cals, sends SYN packets and UDP payloads, and listens for RST packets on separate thread
 * argc is the number of arguments given on the cmd line
 * argv is an array of strings allocated for each argument on the cmd line
*/
int main (int argc, char *argv[]) 
{
    //my vague notes/game plan
    /*
    1. Create raw socket for TCP SYN packet
    2. Fill the buffer with the IP header
    3. Fill the TCP header and then put it into the buffer at buffer pointer + ip header len 
    4. Send the SYN packet
    5. Repeat for UDP but using UDP header instead of TCP
    6. Listen for RST packets and then use that to calculate the time difference
    */
    
    //checking there is a config.json
    if (argc < 2) 
    {
        printf("missing JSON file in cmd line arg!\n");
        return EXIT_FAILURE;
    }
    //root to make JSON calls
    cJSON *json = JSONObj(argv);
  
    // access the JSON data 
    cJSON *server_ip_addr = cJSON_GetObjectItemCaseSensitive(json, "server_ip_addr"); 
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

    //create struct array mimicking config.json 
    jsonLine config[ITEMS] = 
    {
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


    //create and start thread to call recv_RST for listening for RST packets right away
        // Create thread 1
        //void *res is the data i need to determine if there's network compression or not 
    pthread_t thread;
    int res = 0;
    if ((pthread_create(&thread, NULL, recv_RST, (void *)&res)) != 0) //basic error handling
    {
        printf("error with creating thread\n");
    }
    //update statement
    printf("Made thread!\n");




    //open socket for SYN head and tail packets (you will pass this into make_head and make_tail func), remember this is a raw socket
    //used for both SYN packets, not just one
    int sockfd;
    if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) 
    {
	    printf("ERROR opening socket\n"); // basic error handling
        exit(0);
    }
    printf("Socket created!\n");
    
    //need to enable header included so I make the header for the packet, not the kernel
    int incl_val = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &incl_val, sizeof(incl_val)) < 0) 
    {
        printf("error setting IP header building to process\n");
    }


    //IMPORTANT: INTIALIZE ALL VARIABLES/PARAMETERS HERE SO FUNCTION CALLS ARE ONE AFTER ANOTHER (for seamless, little delay)
    int pack_size = atoi(config[7].value);
    int port_HEADSYN = atoi(config[3].value);
    int port_TAILSYN = atoi (config[4].value);
    char *s_addr = config[0].value;
    

    //making HEAD SYN packet
    make_SYN_packet(sockfd, pack_size, s_addr, port_HEADSYN);




   
   //Sending UDP trains,reusing code from pt 1 mostly
    send_UDP(config); 



    //making TAIL SYN packet (diff port)    
    make_SYN_packet(sockfd, pack_size, s_addr, port_TAILSYN);


    //call pthread_join for the RST packet listener
    pthread_join(thread, NULL);

    //output from the thread, passed it as a pointer
    if (res == 1) 
        printf("\nNetwork compression DETECTED!\n");
    else if (res == 0)
        printf("\nNetwork compression NOT DETECTED!\n");
    else
        printf("\nFailed to detect due to insufficient information!\n");



    //and then, DONE WITH PT 2   
    cJSON_Delete(json); //dereference memory
    close(sockfd);
    return EXIT_SUCCESS; 
}



/***
 * JSONObj simply creates the JSON object needed to make calls to my config.json file. 
 * input is the command line argument argv, used to identify filename config.json
 * returns a root of type cJSON, which can be used to access config.json
*/
cJSON *JSONObj(char *input[]) 
{
    // open the file 
    FILE *fp = fopen(input[1], "r"); 
    if (fp == NULL) //basic error handling
    { 
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

/***
 * make_SYN_packet takes a created socket and makes the TCP packet from scratch. then sends it like a regular UDP packet
 * sockfd is the socket
 * packet_size is the packet_size i want it to be, but doesn't really matter, so using packet_size from config json (1000B)
 * ADDR is the char array that holds the server IP address
 * PORT is the destination port (closed one)
*/
void make_SYN_packet(int sockfd, int packet_size, char *ADDR, int PORT) {
    //making the packet
    char *buffer = (char *) malloc(packet_size + sizeof(struct tcphdr) + sizeof(struct ip)); //buffer holds payload PLUS headers
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
    //testing
    //printf("IP checksum: %hu\nTCP checksum: %hu\n", iph->ip_sum, tcph->th_sum);


    //fill in server info
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);
    //printing outgoing dest port
    printf("SENDING SYN PACKET TO PORT %d\n", PORT);
    if (!(inet_pton(AF_INET, ADDR, &(sin.sin_addr)) > 0)) 
    {
        printf("standalone.c 262: ERROR assigning address to socket\n");
        exit(EXIT_FAILURE);
    }


    //sending the packet
    int res = sendto (sockfd, buffer, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    if (res < 0) //error handling
        printf("standalone.c 270: error sending SYN packet\n");
    else 
        printf("Sent SYN packet!\n");
}

//2 diff checksum functions, do the same thing, got these from the internet
//i will be using csum

/***
 * csum & compute_checksum both calculate the ip checksum
 * buf is the buffer to be used
 * nwords is the length of the ip header
 * returns the checksum
*/
unsigned short csum (unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}
/***
 * addr is the IP address
 * count is the length of the ip header
*/
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
/***
 * compute_tcp_checksum computes the tcp checksum (lol)
 * pIph is the pseudo IP header
 * ipPayload is the tcp segment
 * returns checksum
*/
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






/***
 * send_UDP handles the whole probing phase. It creates a socket and immediately sends the low entropy payload,
 *  then sends the high entropy payload
 * items is a jsonLine array consisting of all infro from config.json
*/
void send_UDP (jsonLine *items) 
{ 
    //create socket
    int sockfd;
    if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) 
    {
        printf("Error making UDP socket\n");
        exit(EXIT_FAILURE);
    }

    //set TTL bit to default (255)
    int ttlval = atoi(items[10].value);
    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttlval, sizeof(ttlval)) < 0) 
    {
        printf("error with setting TTL value\n");
        exit(EXIT_FAILURE);
    }

    //set DF bit
    int dfval = IP_PMTUDISC_DO; //linux df bit
    if (setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &dfval, sizeof(dfval)) < 0)   //if linux, use IP_MTU_DISCOVER & IP_PMTUDISC_DO
    { //if linux, use IP_MTU_DISCOVER & IP_PMTUDISC_DO
        printf("error with setting don't fragment bit\n");                            //if MacOS, use IP_DONTFRAG & 1
        exit(EXIT_FAILURE);
    }

    //fill server info
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(atoi(items[2].value));
    if (!(inet_pton(AF_INET, items[0].value, &(sin.sin_addr)) > 0)) //basic error handling
    {
        printf("standalone.c 400: ERROR assigning address to socket\n");
        exit(EXIT_FAILURE);
    }

    //update statement
    printf("Set server info!\n");

    //initialize necessary variables
    int packet_size = atoi(items[7].value);
    int train_size = atoi(items[9].value);
    int inter_time = atoi(items[8].value) * 1000;
    //fill buffer with 1000 0s
    char low_entropy_BUFFER[packet_size];
    memset(low_entropy_BUFFER, 0, packet_size);


    //LOW ENTROPY PAYLOAD
        printf("Sending low entropy payload!\n");
        int pak_count = 0;
        do 
        {
            //send UDP packet (6000 times haha)
            //setting packet ID
            low_entropy_BUFFER[0] = pak_count & 0xFF;
            low_entropy_BUFFER[1] = pak_count & 0xFF;
            if (sendto(sockfd, low_entropy_BUFFER, packet_size, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) 
                printf("packet failed to send\n");
            pak_count++;
        } while (pak_count <= train_size);
        printf("Low entropy payload sent!\n");


    //HIGH ENTROPY PAYLODA
        //make random packet_data using random_file in ../dir
        char high_entropy_BUFFER[packet_size];
        FILE *fp;
        if ((fp = fopen("random_file", "rb")) == NULL) 
        {
            printf("error opening file\n");
            exit(EXIT_FAILURE);
        }
        fread(high_entropy_BUFFER, sizeof(char), packet_size, fp);
        fclose(fp);
        
        printf("Sending high entropy payload\n"); 
        pak_count = 0;
        do 
        {
            //setting packet ID
            high_entropy_BUFFER[0] = pak_count & 0xFF;
            high_entropy_BUFFER[1] = pak_count & 0xFF;
            //send UDP packet (6000 times again)
            if (sendto(sockfd, high_entropy_BUFFER, packet_size, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) 
                printf("packet failed to send\n");
            pak_count++;
        } while (pak_count <= train_size);
        printf("High entropy payload sent!\n");
    //close socket
    close(sockfd);
}

/***
 * recv_RST is running on a separate thread from the beginning to minimize delay while listening for response RST packets,
 *  should get response RST packets cuz sending SYN packets to closed ports
 * arg is the void* res i passed when creating the thread
 * return NULL, signal end of thread
*/
void *recv_RST (void *arg) {
    int sockfd;
    //typecasting our result var, this points to our result in main that we use to detect network compression
    int *ans = (int *)arg;
    //creating socket
    if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) //basic error handling
    {
        printf("error creating socket\n");
        exit(EXIT_FAILURE);
    }
    printf("created socket for RSTs!\n");

    //so we can access header fields
    int optval = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) //basic error handling
    {
        printf("setsockopt failed\n");
        exit(EXIT_FAILURE);
    }
    //update statement
    printf("setsockopt RST HDRINCL worked\n");

    struct timeval timeout;
    timeout.tv_sec = INTER_TIME*2;
    timeout.tv_usec = 0;
    //creates timeout for RST packets, if longer than INTER_TIME (15 seconds) * 2, timeout, move on
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) //basically an inactivity timer
    { 
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
    if (bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) < 0) 
    {
        perror("Bind failed\n");
        exit(EXIT_FAILURE);
    }
    //update statement
    printf("bind worked (do we need it?)\n");

    //incrementing these while listening for RST packets
    int rst_num = 0, timer = 0;
    long double sec = 0;
    //initialization
    char buffer[BUFFER_MAX];
    struct sockaddr_in sender_addr;
    clock_t before = clock();
    socklen_t sender_addr_len = sizeof(sender_addr);
    
    //for loop to listten for only TWO RST packets
    for (int i=0; i < RST_COUNT; i++) 
    {
        //each recvfrom call waits for 30 seconds (cuz i set the timeout)
        int rec_RST = recvfrom(sockfd, buffer, BUFFER_MAX, 0, (struct sockaddr *)&sender_addr, &sender_addr_len);
        if (rec_RST <= 0) //couldn't get packet
        {
            printf("could not receive RST packet\n");
            continue;
        }
        else if (rec_RST > 0) //did get packet, check it's an RST packet
        {
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
            else
                i--; //decrement, we don't want anything but RST packets
        }
    }
    //stop timer
    clock_t after = clock() - before;
    sec = (after * 1000 / CLOCKS_PER_SEC);


    //changing output res
    if (rst_num < RST_COUNT) 
    {
        *ans = -1;
        printf("Didn't receive enough RST packets\n");
    }
    else if (sec >= DIFF_THRESHOLD) 
    { //DIFF_THRESHOLD set to 100 (ms)
        *ans = 0;
        printf("Received RST packets, but res = 0\n");
    }
    else 
    {
        *ans = 1;
        printf("Received RST packets, res = 1\n");
    }

    close(sockfd);
    return NULL;
}


