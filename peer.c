/*
This file is part of TinyP2PC

Github: https://github.com/brandonvessel/TinyP2PC

THIS LICENSE MUST REMAIN AT THE TOP OF THIS FILE

TinyP2PC is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

TinyP2PC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TinyP2PC.  If not, see <https://www.gnu.org/licenses/>.
*/
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <netdb.h>

// encryption
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

// standard
#include "message.h"
#include "encrypting.h"

#include <strings.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>


/// CONFIG ///

// port of another peer
short bootstrap_peer_port = 8833;

// the ip of our own port
short self_peer_port = 8833;

// max peer count. change this in the global arrays if you want this changed
int32_t max_peers = 100;

// peer update interval for peer updates and pinging in seconds
int32_t update_interval = 500;

// modulus for the update random padding
int32_t update_interval_modulus_delta = 2;

// the length of the message
#define MAX_MESSAGE_LENGTH 236

// the length of the payload
#define MAX_PAYLOAD_LENGTH 240

// only defined if we want to allow console control of the peer. if you are testing anything at all, this is probably enabled
#define CONSOLE

// only defined if we need to print generic things to the user
#define DPRINT

// only defined if we want to print pings
//#define PPRINT

// only defined if we want to print peer list checks
//#define CPRINT

// only defined if we want to print error messages
//#define EPRINT

// only defined if we want to see error checking for sending packets
//#define SENDCHECK

// define to debug announce processing
//#define APROCESS

// define to debug peer updates
//#define PUPDATE

// define to debug message processing
//#define MPRINT

// define to debug encryption and message authentication
//#define AUTHPRINT

// define to debug command processing
#define COMPRINT

// define to enable sending messages on this node
//#define PRIVATEKEY

// public key for RSA encryption/decryption
char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Me+NX3ndWqDstrKR2Tj\n"\
"KDEEMFD7wWVt0DtzVO5qCR+/NUZwtiOsRMZCSFu94M9q0Sts5ic2ciAbVar1wkAN\n"\
"x7x3xq2/JDccKiv6u79ov7fjmL881wxVNdeO0MMVZPNReYPH+otABXvNDi+Q+y9T\n"\
"2UGqM7GSwWrqsAxJNuFzWqf8cen0Aj+/2qO/B1flTTr0sFhxYwEytWMa8tiCzmUT\n"\
"ERFzv50x4qPqdznrL1I+vc0G77NoielKTRD/qIGH4xvvwgfx6HktvdUgtDNyVzQT\n"\
"M/IvAEicZkTiVSwA2wxGtID2f74V6Q+LumoKpBbEki4mdrcaWxH5+fts6GhI8iv2\n"\
"QwIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

// private key for RSA encryption/decryption. Exists only when defined
#ifdef PRIVATEKEY
char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEpQIBAAKCAQEA1Me+NX3ndWqDstrKR2TjKDEEMFD7wWVt0DtzVO5qCR+/NUZw\n"\
"tiOsRMZCSFu94M9q0Sts5ic2ciAbVar1wkANx7x3xq2/JDccKiv6u79ov7fjmL88\n"\
"1wxVNdeO0MMVZPNReYPH+otABXvNDi+Q+y9T2UGqM7GSwWrqsAxJNuFzWqf8cen0\n"\
"Aj+/2qO/B1flTTr0sFhxYwEytWMa8tiCzmUTERFzv50x4qPqdznrL1I+vc0G77No\n"\
"ielKTRD/qIGH4xvvwgfx6HktvdUgtDNyVzQTM/IvAEicZkTiVSwA2wxGtID2f74V\n"\
"6Q+LumoKpBbEki4mdrcaWxH5+fts6GhI8iv2QwIDAQABAoIBAGryalwgiDGv87n1\n"\
"1i3EO5h76osOaTtva556AyHxI0KqvkRcv1IM5A09SRttYSaZmirAFOApXWhHUvXg\n"\
"E94qq8J0rA8kTSo6uOFJcaDkOBYEq1Se6kl8XWfOjG3JX/t5gL3+yojXbLpU22AB\n"\
"8HEP/Kj6JD4PRqAIySTrR/FZp80sLqvvbqqDoj0eicLsZFY1Kvp9mn11ChbUlavF\n"\
"m/4++YVqcIF1EWZSYHHR9AOBabUGl8Elwv9a+ykL3qB7qq130uJY1cPElBf1uH8a\n"\
"zeE2mG+2LeW7v63SrjFhYlqPqHNB8xW2I24Zxv5wGJH7iMbhXJzMwegaqFDPUjEg\n"\
"qy8bwQECgYEA+xcxhcJuBiWt5w6xRFbuF57ofRWPaBe8fIY8FrX/8/hUo8ScsDf8\n"\
"Bt7f/ZxD1fYD7LarP63YbSfb+H0bQ5wI6o4jLNhACqRXfavAzIZOG1iKd5afdKua\n"\
"Mkhxm5BIdcnYVEJJ1YIh/z/NYh3gU5shTDH9K7p3PUmxZ8Lz9O334yMCgYEA2PDK\n"\
"kK2phjijWRBCmNv9Nbr694r4DxniVS5RkSbjtXXnsoLO3qbtWLqPKl5yQDFyhQIO\n"\
"/2GRgz31tOk6mKNx5QLPSbTHVE5LDhbwkqKjLk2g/zlWy5Nay1/jfpje1pU2prgc\n"\
"+2MwKMgmSZGm3GHhBi1miUcR67IwMdh+Blz+4mECgYEAxf8pFwAVwJUvx7cHRAuE\n"\
"nm25iQFaX0vwXwV/Fq2X0uus2qMsp6zN+SEA4jy6JVtlBuGYspNEyfaXeCA3Qp4l\n"\
"Tcidpjw0a+/h6gBo/R6fMuMj9V96CAdVhXco1vH0oaV0CCVpkYqXgm7uZwOGJId8\n"\
"v1ff+v6EDnkxAtBxjV+ljJ8CgYEAgB/mYwBN6Pm2b7mMu57hs0QVSPIIg1K0O765\n"\
"adLgFaHnD6T17MYF06uLNmjFbWhGzItktCu5txt27Dv64X9WmvzH1C4ys3XyGgYu\n"\
"W0w2t/gdJ9+DhYQn0Yl2YKSEp5NEzb5bT5VLMirTggvF0s70CaPytQ0GZn+8uxOz\n"\
"iqqN1sECgYEAyzshl2OTmFYqsKJR8LS91vKiJuACfvKWZ6Vp3nDitx2HMkirThWZ\n"\
"q4cqyT7Qv065z2wrgZm+Y1xZIKxXZKIZ0ZpW/7do3nPTH/HVVfWswb5e/N9GNm6+\n"\
"01ymmDJIAcJQjlov9n50qZXCFn5En97T0PC5GF5vesKnqXFh5w1P/kU=\n"\
"-----END RSA PRIVATE KEY-----\n";
#endif

//////////////

// message header translator
/*
p ping request
q ping response
m message
r peer list update request
n peer list update response
a announce request
*/

// peer status values
#define pstatus_DEAD 0
#define pstatus_ALIVE 30

// boolean values
#define TRUE 1
#define FALSE 0
#define True 1
#define False 0


// the socket instance
int32_t sock;

// address of the first peer
struct sockaddr_in tracker_addr;
// address of ourself
struct sockaddr_in self_addr;
// peer list
struct sockaddr_in peer_list[100]; // max peers

// boolean array of whether peers are alive or not
char peer_status[100]; // max peers

// number of peers
int32_t peer_num = 1;

// the last-seen message number
int32_t last_seen_message_num = 0;

// pthread lock for the num_lock
pthread_mutex_t peer_num_lock;

// pthread lock for the stdout
pthread_mutex_t stdout_lock;

// pthread lock for the peer list
pthread_mutex_t peer_list_lock;

// pthread lock for the peer status array
pthread_mutex_t peer_status_lock;


void parse_args(int32_t argc, char **argv);

// threaded functions

#ifdef CONSOLE
void * read_input(void *ptr);
#endif

void * update_peers(void *ptr);
void * peer_finder(void *ptr);

// normal functions

#ifdef PRIVATEKEY
void send_message(char *msg);
#endif

void relay_message(packet *pkt);
void receive_packet(char **argv);
void process_message(struct sockaddr_in *sender_addr, packet *pkt, int32_t bytes_received, char **argv);
char confirm_message(packet *pkt);
void process_command(char * buf, int32_t len);

void send_ping_request(int32_t peer_index);
void reply_to_ping_request(struct sockaddr_in *sender_addr);
void ping_update(struct sockaddr_in *sender_addr);

void send_peer_update_request(int32_t peer_index);
void reply_to_peer_update_request(struct sockaddr_in *sender_addr);
void peer_list_update(struct sockaddr_in *sender_addr, packet *pkt, int32_t bytes_received);

void join_net(int32_t argc, char **argv);
void send_announce(struct sockaddr_in *destination_addr);
void new_peer_joined(struct sockaddr_in *sender_addr);

int32_t in_peer_list(char *msg);


// main function
int32_t main(int32_t argc, char **argv)
{
    // create a socket for processing inputs
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
    {
        #ifdef EPRINT
		fprintf(stderr, "%s\n", "error - error creating socket.");
        #endif
		abort();
	}

    // parse arguments
    // this function really shouldn't exist,
    // but for some reason it makes the whole thing work. don't ask me why
	parse_args(argc, argv);

    // completely ignore the parse_args function and just set our own stuff anyway
    self_addr.sin_family = AF_INET; 
    self_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    self_addr.sin_port = htons(self_peer_port);

    // bind listening socket to port
	if (bind(sock, (struct sockaddr *)&self_addr, sizeof(self_addr)))
    {
        #ifdef EPRINT
		fprintf(stderr, "%s\n", "error - error binding.");
        #endif
		abort();
	}

    // initialize peer status
    for(int32_t i=0; i < max_peers; i++)
    {
        peer_status[i] = pstatus_DEAD;
    }

    #ifdef CONSOLE
	// create a thread to read user input
	pthread_t input_thread;
	pthread_create(&input_thread, NULL, read_input, NULL);
	pthread_detach(input_thread);
    #endif

    // create a thread to update peer list occasionally
	pthread_t update_thread;
	pthread_create(&update_thread, NULL, update_peers, NULL);
	pthread_detach(update_thread);

    // create a thread to find peers
	pthread_t peer_finder_thread;
	pthread_create(&peer_finder_thread, NULL, peer_finder, NULL);
	pthread_detach(peer_finder_thread);

    // join the net
    join_net(argc, argv);


    pthread_mutex_lock(&peer_status_lock);
    peer_status[0] = pstatus_ALIVE;
    pthread_mutex_unlock(&peer_status_lock);


    // start receive packet loop for processing packets
	receive_packet(argv);
}


// parses arguments
void parse_args(int32_t argc, char **argv)
{
    if (argc > 3)
    {
        #ifdef EPRINT
		fprintf(stderr, "%s\n", "error - Argument number not correct");
        #endif
        abort();
	}

    /// arguments and config
    if(argc < 4)
    {
        // the string for the tracker ip
        char tracker_ip[20];

        // copy the origin peer ip into the string for it
        memcpy(tracker_ip, argv[1], (strlen(argv[1]) + 1 > sizeof(tracker_ip)) ? sizeof(tracker_ip) : strlen(argv[1]));
        
        // the port of the origin peer
        short tracker_port = bootstrap_peer_port;

        // the ip of our own port
        short self_port = self_peer_port;

        self_addr.sin_family = AF_INET;
        self_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        self_addr.sin_port = htons(self_port);

        tracker_addr.sin_port = htons(tracker_port);

        peer_list[0].sin_family = AF_INET; 
        peer_list[0].sin_port = htons(tracker_port);
    }
    else
    {
        #ifdef DPRINT
        pthread_mutex_lock(&stdout_lock);
		printf("No arguments provided, starting in bootstrap mode\n");
        pthread_mutex_unlock(&stdout_lock);
        #endif
    }
    
}

#ifdef CONSOLE
//read input from the user forever
void * read_input(void *ptr)
{
	char line[256];
	char *p;
	while (1)
    {
		// read input
		memset(line, 0, sizeof(line));
		p = fgets(line, sizeof(line), stdin);
		// flush input stream to clear out long message
		if (p == NULL)
        {
            #ifdef EPRINT
			pthread_mutex_lock(&stdout_lock);
			fprintf(stderr, "%s\n", "error - cannot read input");
			pthread_mutex_unlock(&stdout_lock);
            #endif
			continue;
		}
		if (line[strlen(line) - 1] != '\n')
        {
			// flush input stream to clear out long mssage
			scanf ("%*[^\n]"); 
			(void) getchar ();
		}
		line[strlen(line) - 1] = '\0';

		// parse input
		if (line[0] != '-')
        {
            #ifdef EPRINT
			pthread_mutex_lock(&stdout_lock);
			fprintf(stderr, "%s\n", "error - input format is not correct.");
			pthread_mutex_unlock(&stdout_lock);
            #endif
			continue;
		}

		switch (line[1])
        {
			case 'm':
                #ifdef PRIVATEKEY
				send_message(line + 3);
                #endif
				break;
			default:
                #ifdef EPRINT
				pthread_mutex_lock(&stdout_lock);
				fprintf(stderr, "%s\n", "error - request type unknown.");
				pthread_mutex_unlock(&stdout_lock);
                #endif
				break;
		}
	}
  return NULL;
}
#endif


// handles incoming packets
void receive_packet(char **argv)
{
    // address of the packet sender
	struct sockaddr_in sender_addr;

    // length of an address
	socklen_t addrlen = 10;

    // the packet that is received by the socket
	packet pkt;

    // the the return value of the packet receiving function recvfrom()
	int32_t bytes_received;

    #ifdef DPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("Listening for packets\n");
    pthread_mutex_unlock(&stdout_lock);
    #endif

	while (1)
    {
		bytes_received = recvfrom(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&sender_addr, &addrlen);
		if (0 < bytes_received)
        {
            switch (pkt.header.type)
            {
                // ping request
                case 'p':
                    reply_to_ping_request(&sender_addr);
                    break;
                // ping response
                case 'q':
                    ping_update(&sender_addr);
                    break;
                // receive message
                case 'm':
                    process_message(&sender_addr, &pkt, bytes_received, argv);
                    break;
                // peer list update request
                case 'r':
                    reply_to_peer_update_request(&sender_addr);
                    break;
                // peer list update response
                case 'n':
                    peer_list_update(&sender_addr, &pkt, bytes_received);
                    break;
                // new peer join announcement
                case 'a':
                    new_peer_joined(&sender_addr);
                    break;
                default:
                    #ifdef EPRINT
                    pthread_mutex_lock(&stdout_lock);
                    fprintf(stderr, "%s %c\n", "error - received packet type unknown. recieved type", pkt.header.type);
                    pthread_mutex_unlock(&stdout_lock);
                    #endif
                    break;
            }
		}
        else
        {
            // bad packet
            #ifdef EPRINT
			pthread_mutex_lock(&stdout_lock);
			fprintf(stderr, "%s\n", "error - error receiving a packet, ignoring.");
			pthread_mutex_unlock(&stdout_lock);
            #endif
			continue;
        }
	}
}


// sends a join message
void join_net(int32_t argc, char **argv)
{
    struct sockaddr_in server;
    server.sin_family = AF_INET;            
    server.sin_port = htons(bootstrap_peer_port);   // port
    server.sin_addr.s_addr = inet_addr(argv[1]);    // ip

    send_announce(&server);
}


// add a new peer to the peer list
void new_peer_joined(struct sockaddr_in *sender_addr)
{
    #ifdef DPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("Announce <- %s\n", inet_ntoa(sender_addr->sin_addr));
    pthread_mutex_unlock(&stdout_lock);
    #endif

    pthread_mutex_lock(&peer_num_lock);
    int32_t pnum = peer_num;
    pthread_mutex_unlock(&peer_num_lock);

    // max peers check
    if(max_peers != pnum)
    {
        #ifdef APROCESS
        pthread_mutex_lock(&stdout_lock);
        printf(" We have room for more peers. Adding...\n");
        pthread_mutex_unlock(&stdout_lock);
        #endif

        int32_t i=0;
        char alive = pstatus_DEAD;

        // find the first empty slot
        while(i < max_peers)
        {
            // get peer status from list
            pthread_mutex_lock(&peer_status_lock);
            alive = peer_status[i];
            pthread_mutex_unlock(&peer_status_lock);
            
            // break if peer alive
            if(alive == pstatus_DEAD)
            {
                break;
            }
            i++;
        }

        #ifdef APROCESS
        pthread_mutex_lock(&stdout_lock);
        printf(" Empty spot at peer_list index: %i\n", i);
        pthread_mutex_unlock(&stdout_lock);
        #endif
        

        // ip strings
        #ifdef APROCESS
        char peer_list_ip[INET_ADDRSTRLEN];
        #endif
        char new_peer_ip[INET_ADDRSTRLEN];

        // addr to ip
        inet_ntop(AF_INET, &(sender_addr->sin_addr), new_peer_ip, INET_ADDRSTRLEN);

        char *sender_ip = inet_ntoa(sender_addr->sin_addr);

        // check if peer is in list
        if(in_peer_list(sender_ip) == False)
        {
            // set the status for the peer
            pthread_mutex_lock(&peer_status_lock);
            peer_status[i] = pstatus_ALIVE;
            pthread_mutex_unlock(&peer_status_lock);

            // ip to addr
            inet_pton(AF_INET, new_peer_ip, &(peer_list[i].sin_addr));

            // set sin port
            peer_list[i].sin_port = htons(self_peer_port);

            // set sin family
            peer_list[i].sin_family = AF_INET;

            #ifdef APROCESS
            pthread_mutex_lock(&stdout_lock);
            inet_ntop(AF_INET, &(peer_list[i].sin_addr), peer_list_ip, INET_ADDRSTRLEN);
            printf(" Peer %s successfully added\n", peer_list_ip);
            pthread_mutex_unlock(&stdout_lock);
            #endif

            // say hello back
            
            pthread_mutex_lock(&peer_list_lock);

            // send packet to tracker
            send_announce(&peer_list[i]);

            pthread_mutex_lock(&peer_num_lock);
            peer_num++;
            pthread_mutex_unlock(&peer_num_lock);

            pthread_mutex_unlock(&peer_list_lock);
        }
        else
        {
            #ifdef APROCESS
            pthread_mutex_lock(&stdout_lock);
            printf(" Peer %s already in peer list. Ignoring\n", inet_ntoa(sender_addr->sin_addr));
            //printf("new_ip: %s", new_ip);
            pthread_mutex_unlock(&stdout_lock);
            #endif
        }
        
        
    }
    else
    {
        #ifdef APROCESS
        pthread_mutex_lock(&stdout_lock);
		printf(" Max peers reached\n");
		pthread_mutex_unlock(&stdout_lock);
        #endif
    }
    
}


// sends a message to a peer
void relay_message(packet *pkt)
{   
	int32_t i;
	int32_t status;
    char ppstatus;
    #ifdef DPRINT
    char mpeer_ip[INET_ADDRSTRLEN];
    #endif
	
	for (i = 0; i < max_peers; i++)
    {
        // see if able to send to peer
        pthread_mutex_lock(&peer_status_lock);
        ppstatus = peer_status[i];
        pthread_mutex_unlock(&peer_status_lock);

        // if this peer is not dead, send message
        if(ppstatus != pstatus_DEAD)
        {
            // send packet
            pthread_mutex_lock(&peer_list_lock);
            status = sendto(sock, pkt, sizeof(pkt->header) + pkt->header.payload_length, 0, (struct sockaddr *)&(peer_list[i]), sizeof(struct sockaddr_in));
            pthread_mutex_unlock(&peer_list_lock);

            // check error of packet sending
            #ifdef EPRINT
            if (status == -1)
            {
                pthread_mutex_lock(&stdout_lock);
                fprintf(stderr, "%s %d\n", "error - error sending packet to peer", i);
                pthread_mutex_unlock(&stdout_lock);
            }
            #endif

            // send packet to every peer
            #ifdef DPRINT
            // addr to ip
            inet_ntop(AF_INET, &(peer_list[i].sin_addr), mpeer_ip, INET_ADDRSTRLEN);

            pthread_mutex_lock(&stdout_lock);
            printf("Message -> %s\n", mpeer_ip);
            pthread_mutex_unlock(&stdout_lock);
            #endif
        }
	}
}


// processes a recieved message packet
void process_message(struct sockaddr_in *sender_addr, packet *pkt, int32_t bytes_received, char **argv)
{
    #ifdef AUTHPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("Message recieved\n");
    pthread_mutex_unlock(&stdout_lock);
    #endif

    //for(int i=0; i < sizeof(pkt->payload); i++)
    //{
    //    pthread_mutex_lock(&stdout_lock);
    //    printf("%i Raw:%d\n", i, pkt->payload[i]);
    //    pthread_mutex_unlock(&stdout_lock);
    //}

    // confirm payload length is in acceptable range
    if((pkt->header.payload_length > (240 + 256)) || (pkt->header.payload_length < 0))
    {
        return;
    }

    // confirm message length is in acceptable range
    if((pkt->header.message_length > MAX_MESSAGE_LENGTH) || (pkt->header.message_length < 0))
    {
        return;
    }

    #ifdef DPRINT
    char mpeer_ip[INET_ADDRSTRLEN];
    #endif

    char result;

    result = confirm_message(pkt);

    #ifdef AUTHPRINT
    pthread_mutex_lock(&stdout_lock);
    if(result == True)
    {
        printf("Result of confirm: True\n");
    }
    else
    {
        printf("Result of confirm: False\n");
    }
    pthread_mutex_unlock(&stdout_lock);
    #endif


    // only relay and acknowledge message if verified authenticity and new
    if(result == True)
    {
        // if we are here, the message has been confirmed to be legit and never seen before
        // the actual message
        char message[pkt->header.message_length];

        // copy message from payload into message string
        memcpy(message, pkt->payload, pkt->header.message_length);

        // send packet to every peer
        #ifdef DPRINT
        // addr to ip
        inet_ntop(AF_INET, &(sender_addr->sin_addr), mpeer_ip, INET_ADDRSTRLEN);

        pthread_mutex_lock(&stdout_lock);
        printf("Message <- %s\n", mpeer_ip);
        pthread_mutex_unlock(&stdout_lock);
        #endif
        
        // process the command
        process_command(message, pkt->header.message_length);

        relay_message(pkt);
    }
}


#ifdef PRIVATEKEY
// sends a message to a peer
void send_message(char *msg)
{
    #ifdef MPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("Inside send_message\n");
    pthread_mutex_unlock(&stdout_lock);
    #endif

    #ifdef EPRINT
	if (msg[0] == '\0')
    {
		pthread_mutex_lock(&stdout_lock);
		fprintf(stderr, "%s\n", "error - no message content.");
		pthread_mutex_unlock(&stdout_lock);
	}
    #endif

	// format packet
	packet pkt;
	pkt.header.type = 'm';
	pkt.header.message_length = strlen(msg) + 1;
    pkt.header.payload_length = 240 + 256;

    // new string for adding message num
    char payload_string[240];

    // zero payload string
    for(int i=0; i < 240; i++)
    {
        payload_string[i] = '\0';
    }

    #ifdef MPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("1\n");
    pthread_mutex_unlock(&stdout_lock);
    #endif

    // copy message into payload string
    memcpy(payload_string, msg, pkt.header.message_length);

    #ifdef MPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("Payload String: %s\nLength: %i\n", payload_string, pkt.header.message_length);
    pthread_mutex_unlock(&stdout_lock);
    #endif
 
    #ifdef MPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("2\n");
    pthread_mutex_unlock(&stdout_lock);
    #endif

    // copy num into payload string
    last_seen_message_num++;
    memcpy(&payload_string[236], &last_seen_message_num, sizeof(last_seen_message_num));
    last_seen_message_num--;

    #ifdef MPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("3\n");
    pthread_mutex_unlock(&stdout_lock);
    #endif

    // copy the raw message into the packet payload
	memcpy(pkt.payload, payload_string, 240);

    #ifdef MPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("Payload String: %s\nLength: %i\n", pkt.payload, pkt.header.message_length);
    pthread_mutex_unlock(&stdout_lock);
    #endif

    // encrypted message
    char encrypted_message[256];
    //char * encrypted_message;

    #ifdef MPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("4\n");
    pthread_mutex_unlock(&stdout_lock);
    #endif

    // encrypt message
    private_encrypt(payload_string, 240, privateKey, encrypted_message);

    // copy encrypted message into encrypted section of packet
    memcpy(pkt.encrypted, encrypted_message, sizeof(encrypted_message));

    #ifdef MPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("Entering relay function\n");
    pthread_mutex_unlock(&stdout_lock);
    #endif
    
    // relay the message to all peers
	relay_message(&pkt);
}
#endif


// reply to a ping packet request
void reply_to_ping_request(struct sockaddr_in *sender_addr)
{
    // fork the thread allowing it to continue independently
    // the pid of the fork
    //int32_t fork_id;
    //fork_id = fork();
    //if (fork_id > 0 || fork_id == -1)
    //    // return original process
    //    return;

    // reply to a ping request
	// format packet
	packet pkt;
	pkt.header.type = 'q';
	pkt.header.payload_length = 0;

	// send ping reply
	int32_t status = sendto(sock, &pkt, sizeof(pkt.header), 0, (struct sockaddr *)sender_addr, sizeof(struct sockaddr_in));
    
    #ifdef PPRINT
    printf("Replying to ping from %s\n", inet_ntoa(sender_addr->sin_addr));
    #endif
    #ifdef EPRINT
	if (status == -1)
    {
		pthread_mutex_lock(&stdout_lock);
		fprintf(stderr, "%s\n", "error - error replying to ping message, possibility of being opt-out.");
		pthread_mutex_unlock(&stdout_lock);
	}
    #endif
}


// reply from peer ping
void ping_update(struct sockaddr_in *sender_addr)
{
    // ip of the sender address
    char sender_ip[INET_ADDRSTRLEN];

    // test peer ip
    char test_peer_ip[INET_ADDRSTRLEN];

    // addr to ip
    inet_ntop(AF_INET, &(sender_addr->sin_addr), sender_ip, INET_ADDRSTRLEN);

    // iterator
    int32_t i=0;

    // the result of the compare operation
    int32_t test_result=0;

    #ifdef PPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("Recieved ping response from %s\n", inet_ntoa(sender_addr->sin_addr));
    pthread_mutex_unlock(&stdout_lock);
    #endif

    // loop through peer data for match
    while(i < max_peers)
    {
        // lock peer data list
        pthread_mutex_lock(&peer_list_lock);
        // get ip of test peer
        inet_ntop(AF_INET, &(peer_list[i].sin_addr), test_peer_ip, INET_ADDRSTRLEN);
        // unlock
        pthread_mutex_unlock(&peer_list_lock);

        // compare strings
        test_result = memcmp(sender_ip, test_peer_ip, sizeof(sender_ip));

        
        if(test_result == 0)
        {
            // lock
            pthread_mutex_lock(&peer_status_lock);
            // set peers that are ALIVE to ping status
            if(peer_status[i] == pstatus_DEAD)
            {
                // increase the number of live peers
                peer_status[i] = pstatus_ALIVE;
                pthread_mutex_lock(&peer_num_lock);
                peer_num++;
                pthread_mutex_unlock(&peer_num_lock);
            }
            else
            {
                // peer is alive: set status to alive
                peer_status[i] = pstatus_ALIVE;
            }

            #ifdef DPRINT
            pthread_mutex_lock(&stdout_lock);
            //printf("Peer %i status %i\n", i, peer_status[i]);
            pthread_mutex_unlock(&stdout_lock);
            #endif

            // unlock
            pthread_mutex_unlock(&peer_status_lock);

            // break out of loop
            break;
        }
        
        
        i++;
    }
}


// updates peerlist by asking peers for new peers. also pings current peers
void * update_peers(void *ptr)
{
    int32_t i=0;
    char ip_name[INET_ADDRSTRLEN];
    while(1)
    {
        // sleep for the update interval and update peers
        sleep(update_interval + (rand() % update_interval_modulus_delta));

        #ifdef DPRINT
        pthread_mutex_lock(&stdout_lock);
        printf("Updating peerlist\n");
        pthread_mutex_unlock(&stdout_lock);
        #endif

        i=0;
        while(i < max_peers)
        {
            // set peers that are ALIVE to ping status
            pthread_mutex_lock(&peer_status_lock);
            switch (peer_status[i])
            {
                case 1:
                    // kill peer
                    peer_status[i] = pstatus_DEAD;

                    // reduce the number of live peers
                    pthread_mutex_lock(&peer_num_lock);
                    peer_num--;
                    pthread_mutex_unlock(&peer_num_lock);
                    
                    break;
                case pstatus_DEAD:
                    break;
                default:
                    peer_status[i] -= 1;
                    break;
		    }
            pthread_mutex_unlock(&peer_status_lock);

            #ifdef DPRINT
            pthread_mutex_lock(&stdout_lock);
            pthread_mutex_lock(&peer_status_lock);
            pthread_mutex_lock(&peer_list_lock);
            if(peer_status[i] != pstatus_DEAD)
            {
                inet_ntop(AF_INET, &(peer_list[i].sin_addr), ip_name, INET_ADDRSTRLEN);
                printf("Peer %i status %i %s\n", i, peer_status[i], ip_name);
            }
            else
            {
                printf("Peer %i status %i\n", i, peer_status[i]);
            }
            
            pthread_mutex_unlock(&peer_list_lock);
            pthread_mutex_unlock(&peer_status_lock);
            pthread_mutex_unlock(&stdout_lock);
            #endif
            
            i++;
        }

        #ifdef DPRINT
        pthread_mutex_lock(&stdout_lock);
        pthread_mutex_lock(&peer_num_lock);
        printf("peer_num: %i\n", peer_num);
        pthread_mutex_unlock(&peer_num_lock);
        pthread_mutex_unlock(&stdout_lock);
        #endif
        
        i=0;
        while(i < max_peers)
        {
            // lock the peer status
            pthread_mutex_lock(&peer_status_lock);

            // send ping updates to not dead peers
            if(peer_status[i] != pstatus_DEAD)
            {
                send_ping_request(i);
            }

            // unlock peer status
            pthread_mutex_unlock(&peer_status_lock);

            if(peer_status[i] != pstatus_DEAD)
            {
                // wait a few seconds to allow the peer to respond
                sleep(update_interval + (rand() % update_interval_modulus_delta));
            }

            // lock the peer status
            pthread_mutex_lock(&peer_status_lock);

            // send peer update requests to peers that aren't dead
            if(peer_status[i] > (int32_t)(pstatus_ALIVE / 2))
            {
                send_peer_update_request(i);
            }

            // unlock peer status
            pthread_mutex_unlock(&peer_status_lock);

            i++;
        }
    }
}


// sends a random peer from our peer list in response
void reply_to_peer_update_request(struct sockaddr_in *sender_addr)
{
    // empty list check
    pthread_mutex_lock(&peer_num_lock);
    int32_t pnum = peer_num;
    pthread_mutex_unlock(&peer_num_lock);

    if(pnum != 0)
    {
        // ip strings
        char random_ip[INET_ADDRSTRLEN];
        char sender_ip[INET_ADDRSTRLEN];

        // addr to ip
        inet_ntop(AF_INET, &(sender_addr->sin_addr), sender_ip, INET_ADDRSTRLEN);

        #ifdef DPRINT
        pthread_mutex_lock(&stdout_lock);
        printf("PUpdate Request <- %s\n", sender_ip);
        pthread_mutex_unlock(&stdout_lock);
        #endif

        // format packet
        packet pkt;
        pkt.header.type = 'n';
        
        // fetch sender information
        // use random integer to get random peer
        // alive boolean
        char alive = pstatus_DEAD;

        // random integer value
        int32_t random_peer_num = 0;

        // loop until we find a live peer
        while(alive == pstatus_DEAD)
        {
            // generate random peer number
            random_peer_num = rand() % max_peers;

            // get peer status from list
            pthread_mutex_lock(&peer_status_lock);
            alive = peer_status[random_peer_num];
            pthread_mutex_unlock(&peer_status_lock);
        }

        // resolve peer ip from list
        pthread_mutex_lock(&peer_list_lock);
        inet_ntop(AF_INET, &(peer_list[random_peer_num].sin_addr), random_ip, INET_ADDRSTRLEN);
        pthread_mutex_unlock(&peer_list_lock);


        #ifdef DPRINT
        pthread_mutex_lock(&stdout_lock);
        printf("PUpdate %s -> %s\n", random_ip, sender_ip);
        pthread_mutex_unlock(&stdout_lock);
        #endif

        // send ping reply
        pkt.header.payload_length = strlen(random_ip) + 1;
        //pkt.header.payload_length = strlen(random_ip);
        memcpy(pkt.payload, random_ip, pkt.header.payload_length);
        //printf("%s\n", pkt.payload);

	    sendto(sock, &pkt, sizeof(pkt.header)+pkt.header.payload_length, 0, (struct sockaddr *)sender_addr, sizeof(struct sockaddr_in));
        //int32_t status = sendto(sock, &pkt, sizeof(pkt.header) + pkt.header.payload_length, 0, (struct sockaddr *)&(peer_list[i]), sizeof(struct sockaddr_in));
    }
    else
    {
        #ifdef EPRINT
        pthread_mutex_lock(&stdout_lock);
        printf("Not enough peers to respond to peer update request");
        pthread_mutex_unlock(&stdout_lock);
        #endif
    }
    
}


// returns true if a peer is listed in the peerlist
int32_t in_peer_list(char *sender_ip)
{
    // integer for while loop
    int32_t i=0;

    // the result of tbe operation
    int32_t test_result=0;

    char peer_list_str[INET_ADDRSTRLEN];

    // iterate through peers
    while(i < max_peers)
    {
        // lock peer list
        pthread_mutex_lock(&peer_list_lock);

        // addr to ip
        inet_ntop(AF_INET, &(peer_list[i].sin_addr), peer_list_str, INET_ADDRSTRLEN);

        // unlock peer list
        pthread_mutex_unlock(&peer_list_lock);

        test_result = memcmp(sender_ip, peer_list_str, sizeof(sender_ip));
        if(test_result == 0)
        {
            // return true if the results are equal
            #ifdef CPRINT
            pthread_mutex_lock(&stdout_lock);
            printf("<in_peer_list> Peer [%i]: %s == %s. Returning TRUE\n", i, peer_list_str, sender_ip);
            pthread_mutex_unlock(&stdout_lock);
            #endif
            return True;
        }
        else
        {
            #ifdef CDPRINT
            pthread_mutex_lock(&stdout_lock);
            printf("<in_peer_list> Peer [%i]: %s != %s\n", i, peer_list_str, sender_ip);
            pthread_mutex_unlock(&stdout_lock);
            #endif
        }
        
        i++;
    }

    // return false if all the peer ip's have been checked and it's false
    return False;
}


// sends a ping to the specified peer referenced by index
void send_ping_request(int32_t peer_index)
{
    // fork the thread allowing it to continue independently
    // the pid of the fork
    //int32_t fork_id;
    //fork_id = fork();
    //if(fork_id > 0 || fork_id == -1)
    //    {
    //        // return original process out of function
    //        return;
    //    }

	// format packet
	packet pkt;
	pkt.header.type = 'p';
	pkt.header.payload_length = 0;

	// send ping request
	int32_t status = sendto(sock, &pkt, sizeof(pkt.header), 0, (struct sockaddr *)&(peer_list[peer_index]), sizeof(struct sockaddr_in));

    #ifdef PPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("Sending ping request\n");
    pthread_mutex_unlock(&stdout_lock);
    #endif

    #ifdef EPRINT
	if (status == -1)
    {
		pthread_mutex_lock(&stdout_lock);
		fprintf(stderr, "%s\n", "error - error replying to ping message, possibility of being opt-out.");
		pthread_mutex_unlock(&stdout_lock);
	}
    #endif
}


// sends a ping to the specified peer referenced by index
void send_peer_update_request(int32_t peer_index)
{
    // fork the thread allowing it to continue independently
    // the pid of the fork
    //int32_t fork_id;
    //fork_id = fork();
    //if(fork_id > 0 || fork_id == -1)
    //    {
    //        // return original process to previous function
    //        return;
    //    }

	// format packet
	packet pkt;
	pkt.header.type = 'r';
	pkt.header.payload_length = 0;

	// send peer update request
	int32_t status = sendto(sock, &pkt, sizeof(pkt.header), 0, (struct sockaddr *)&(peer_list[peer_index]), sizeof(struct sockaddr_in));
    
    #ifdef PUPDATE
    char new_peer_ip[INET_ADDRSTRLEN];

    // addr to ip
    inet_ntop(AF_INET, &(peer_list[peer_index].sin_addr), new_peer_ip, INET_ADDRSTRLEN);

    pthread_mutex_lock(&stdout_lock);
    printf("PUpdate Request -> %s\n", new_peer_ip);
    pthread_mutex_unlock(&stdout_lock);
    #endif

    #ifdef EPRINT
	if (status == -1)
    {
		pthread_mutex_lock(&stdout_lock);
		fprintf(stderr, "%s\n", "error - error replying to ping message, possibility of being opt-out.");
		pthread_mutex_unlock(&stdout_lock);
	}
    #endif
}


// add a new peer to the peer list
void peer_list_update(struct sockaddr_in *sender_addr, packet *pkt, int32_t bytes_received)
{
    // storing the string form of the new peer ip
    char new_peer_ip[INET_ADDRSTRLEN];

    // used for testing if the ip conversion is valid
    struct sockaddr_in temp_addr;

    pthread_mutex_lock(&peer_num_lock);
    int32_t pnum = peer_num;
    pthread_mutex_unlock(&peer_num_lock);

    // max peers check
    if(max_peers != pnum)
    {  
        int32_t i=0;
        char alive = pstatus_DEAD;

        // find the first empty slot
        while(i < max_peers)
        {
            // get peer status from list
            pthread_mutex_lock(&peer_status_lock);
            alive = peer_status[i];
            pthread_mutex_unlock(&peer_status_lock);
            
            // break if peer dead
            if(alive == pstatus_DEAD)
            {
                break;
            }
            i++;
        }

        // confirm payload length is in acceptable range
        if(pkt->header.payload_length > MAX_PAYLOAD_LENGTH)
        {
            return;
        }

        // copy the string over
        memcpy(new_peer_ip, pkt->payload, pkt->header.payload_length);

        // verify that the new peer ip is not corrupted
        if (inet_aton(new_peer_ip, &temp_addr.sin_addr) <= 0) {
        	return;
        }

        #ifdef DPRINT
        char sender_ip[INET_ADDRSTRLEN];

        // addr to ip
        inet_ntop(AF_INET, &(sender_addr->sin_addr), sender_ip, INET_ADDRSTRLEN);

        // check to make sure the new_peer_ip is not corrupted
        // ip to addr
        inet_pton(AF_INET, new_peer_ip, &(peer_list[i].sin_addr));

        
        pthread_mutex_lock(&stdout_lock);
        printf("PUpdate %s <- %s\n", new_peer_ip, sender_ip);
        pthread_mutex_unlock(&stdout_lock);
        #endif


        // check if peer is in list
        if(in_peer_list(new_peer_ip) == False){

            // set the status for the peer
            pthread_mutex_lock(&peer_status_lock);
            peer_status[i] = pstatus_ALIVE;
            pthread_mutex_unlock(&peer_status_lock);

            // ip to addr
            inet_pton(AF_INET, new_peer_ip, &(peer_list[i].sin_addr));

            // set sin port
            peer_list[i].sin_port = htons(self_peer_port);

            // set sin family
            peer_list[i].sin_family = AF_INET;

            #ifdef PUPDATE
            pthread_mutex_lock(&stdout_lock);
            printf(" Peer %s successfully added\n", new_peer_ip);
            pthread_mutex_unlock(&stdout_lock);
            #endif
        }
        else
        {
            #ifdef PUPDATE
            pthread_mutex_lock(&stdout_lock);
            printf(" Peer %s already exists in the list. Ignoring\n", new_peer_ip);
            pthread_mutex_unlock(&stdout_lock);
            #endif
        }
        
    }
    else
    {
        #ifdef EPRINT
        pthread_mutex_lock(&stdout_lock);
		printf("Max peers reached\n");
		pthread_mutex_unlock(&stdout_lock);
        #endif
    }
    
}


// constantly sends announce packets to random ip addresses
void * peer_finder(void *ptr)
{
    // this is not implemented yet. I didn't feel like it was necessary to make the basic peer work
    while(1)
    {
        sleep(1);
    }
}


// sends an announce packet
void send_announce(struct sockaddr_in *destination_addr)
{
    // format packet
	packet pkt;
	pkt.header.type = 'a';
	pkt.header.payload_length = 0;
    
    #ifdef SENDCHECK
    int32_t status;

    status = sendto(sock, &pkt, sizeof(pkt.header), 0, (struct sockaddr *)destination_addr, sizeof(struct sockaddr_in));
    
    if (status == -1)
    {
        #ifdef EPRINT
		pthread_mutex_lock(&stdout_lock);
		fprintf(stderr, "%s\n", "error - error sending packet to bootstrap");
		pthread_mutex_unlock(&stdout_lock);
        #endif
	}

    #else
    sendto(sock, &pkt, sizeof(pkt.header), 0, (struct sockaddr *)destination_addr, sizeof(struct sockaddr_in));
    #endif

    #ifdef DPRINT
    char destination_ip[INET_ADDRSTRLEN];

    // addr to ip
    inet_ntop(AF_INET, &(destination_addr->sin_addr), destination_ip, INET_ADDRSTRLEN);

    pthread_mutex_lock(&stdout_lock);
    printf("Announce -> %s\n", destination_ip);
    pthread_mutex_unlock(&stdout_lock);
    #endif
}


// confirms the message is correct by comparing encrypted data to unencrypted data
char confirm_message(packet *pkt)
{
    #ifdef AUTHPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("Confirming message\n");
    pthread_mutex_unlock(&stdout_lock);
    #endif

    // the decrypted payload
    char decrypted_payload[240]; // this is MAX_PAYLOAD_LENGTH

    char plaintext_payload[240];

    // message num
    int32_t current_message_num;

    // temporary strings for decrypting
    char decrypted[4098]={};
    char encrypted[4098]={};

    // copy info from packet into plaintext_payload
    memcpy(plaintext_payload, pkt->payload, 240);

    // copy encrypted info from packet to encrypted array
    memcpy(encrypted, pkt->encrypted, 256);

    // decrypt payload from packet
    int32_t decrypted_length = public_decrypt(encrypted, 256, publicKey, decrypted);

    // copy from temp decrypted string to actual payload string
    memcpy(decrypted_payload, decrypted, 240);

    //for(int i=0; i < sizeof(pkt->payload); i++)
    //{
    //    pthread_mutex_lock(&stdout_lock);
    //    printf("%i Plain: %d Decrypted: %d\n", i, pkt->payload[i], decrypted_payload[i]);
    //    pthread_mutex_unlock(&stdout_lock);
    //}

    // copy message num from packet to variable
    memcpy(&current_message_num, &(pkt->payload[236]), 4);

    #ifdef AUTHPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("Packet: %i\nCurrent: %i\n", current_message_num, last_seen_message_num);
    pthread_mutex_unlock(&stdout_lock);
    #endif

    // check timestamp
    if((last_seen_message_num >= current_message_num))
    {
        // if the current message is not greater than the last seen message, ignore it
        #ifdef AUTHPRINT
        pthread_mutex_lock(&stdout_lock);
        printf("Message number in packet is not greater than current message number: ignoring\n");
        pthread_mutex_unlock(&stdout_lock);
        #endif
        return 0;
    }

    #ifdef AUTHPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("comparing memory\n");
    pthread_mutex_unlock(&stdout_lock);
    #endif

    // compare string
    int32_t result;
    result = memcmp(decrypted_payload, pkt->payload, 240);

    #ifdef AUTHPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("Compared memory. Result: %i\n", result);
    pthread_mutex_unlock(&stdout_lock);
    #endif

    if(result == 0)
    {
        // a result of 0 indicates the strings are the same
        // increase last message num
        last_seen_message_num = current_message_num;

        #ifdef AUTHPRINT
        pthread_mutex_lock(&stdout_lock);
        printf("New message num is %i\n", current_message_num);
        pthread_mutex_unlock(&stdout_lock);
        #endif

        return True;
    }
    else
    {
        #ifdef AUTHPRINT
        pthread_mutex_lock(&stdout_lock);
        printf("Returning false on message authenticity\n");
        pthread_mutex_unlock(&stdout_lock);
        #endif

        // any other result is false
        return False;
    }
}


// processes the command string
void process_command(char * buf, int32_t len)
{
    #ifdef COMPRINT
    pthread_mutex_lock(&stdout_lock);
    printf("Recieved Command:%s\n", buf);
    pthread_mutex_unlock(&stdout_lock);
    #endif
}