#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"
#include "./common.h"


#ifndef STATUS_FORBIDDEN
#define STATUS_FORBIDDEN 4
#endif


typedef struct {
    int sockfd;
    char remote_ip[IP_LEN];
    uint16_t remote_port;
} PeerRequest_t;

NetworkAddress_t *my_address; 
char my_raw_password[PASSWORD_LEN]; 
hashdata_t my_request_signature; 

NetworkAddress_t** network = NULL;
uint32_t peer_count = 0;
pthread_mutex_t network_mutex; 

#define MAX_PAYLOAD_SIZE (MAX_MSG_LEN - REPLY_HEADER_LEN)
#define LISTEN_BACKLOG 5

void calculate_signature(const char *password, const char *salt, hashdata_t signature)
{
    char data[PASSWORD_LEN + SALT_LEN];
    memset(data, 0, sizeof(data));
    memcpy(data, password, strlen(password));
    memcpy(data + strlen(password), salt, SALT_LEN); 
    get_data_sha(data, signature, sizeof(data), SHA256_HASH_SIZE);
}

int send_request(int sockfd, uint32_t command, const char *body, uint32_t body_len)
{
    RequestHeader_t req_h;
    memset(&req_h, 0, sizeof(RequestHeader_t));
    
    req_h.port = my_address->port;
    req_h.command = htobe32(command); 
    req_h.length = htobe32(body_len);

    memcpy(req_h.ip, my_address->ip, IP_LEN);
    memcpy(req_h.signature, my_request_signature, SHA256_HASH_SIZE); 

    if (compsys_helper_writen(sockfd, &req_h, REQUEST_HEADER_LEN) == -1) return -1;
    if (body_len > 0 && body != NULL) {
        if (compsys_helper_writen(sockfd, (void *)body, body_len) == -1) return -1;
    }
    return 0;
}

int send_reply(int sockfd, uint32_t status, const char *body, uint32_t body_len, 
               uint32_t block_num, uint32_t block_count, hashdata_t total_hash)
{
    ReplyHeader_t reply_h;
    memset(&reply_h, 0, sizeof(reply_h));
    hashdata_t block_hash;
    get_data_sha(body, block_hash, body_len, SHA256_HASH_SIZE);
    
    reply_h.length = htobe32(body_len);
    reply_h.status = htobe32(status);
    reply_h.this_block = htobe32(block_num);
    reply_h.block_count = htobe32(block_count);
    
    memcpy(reply_h.block_hash, block_hash, SHA256_HASH_SIZE);
    memcpy(reply_h.total_hash, total_hash, SHA256_HASH_SIZE);

    if (compsys_helper_writen(sockfd, &reply_h, REPLY_HEADER_LEN) == -1) return -1;
    if (body_len > 0 && body != NULL) {
        if (compsys_helper_writen(sockfd, (void *)body, body_len) == -1) return -1;
    }
    return 0;
}

NetworkAddress_t* find_peer(const char *ip, uint32_t port)
{
    for (uint32_t i = 0; i < peer_count; i++) {
        if (string_equal(network[i]->ip, ip) && (be32toh(network[i]->port) == port)) {
            return network[i];
        }
    }
    return NULL;
}

int add_peer_to_network(NetworkAddress_t *new_peer, int save_salt)
{
    pthread_mutex_lock(&network_mutex);
    if (find_peer(new_peer->ip, be32toh(new_peer->port)) != NULL) {
        pthread_mutex_unlock(&network_mutex);
        return 1;
    }

    NetworkAddress_t *peer_entry = (NetworkAddress_t*)malloc(sizeof(NetworkAddress_t));
    if (!peer_entry) {
        pthread_mutex_unlock(&network_mutex);
        return -1;
    }
    memcpy(peer_entry, new_peer, PEER_ADDR_LEN);

    if (save_salt) {
        char random_salt[SALT_LEN+1] = {0};
        generate_random_salt(random_salt);
        calculate_signature((char*)new_peer->signature, random_salt, peer_entry->signature);
        memcpy(peer_entry->salt, random_salt, SALT_LEN);
    }
    
    network = (NetworkAddress_t**)realloc(network, (peer_count + 1) * sizeof(NetworkAddress_t*));
    if (!network) {
        free(peer_entry);
        pthread_mutex_unlock(&network_mutex);
        return -1;
    }
    network[peer_count] = peer_entry;
    peer_count++;
    pthread_mutex_unlock(&network_mutex);
    return 0; 
}

int send_inform(NetworkAddress_t *target_peer, NetworkAddress_t *new_peer)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(be32toh(target_peer->port));
    inet_pton(AF_INET, target_peer->ip, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        return -1;
    }

    int result = send_request(sockfd, COMMAND_INFORM, (char*)new_peer, PEER_ADDR_LEN);
    close(sockfd);
    return result;
}

int send_inform_to_all_but(NetworkAddress_t *new_peer, NetworkAddress_t *exclude_peer)
{
    pthread_mutex_lock(&network_mutex);
    for (uint32_t i = 0; i < peer_count; i++) {
        NetworkAddress_t *target_peer = network[i];

        if (string_equal(target_peer->ip, my_address->ip) && (target_peer->port == my_address->port)) continue;
        if (exclude_peer != NULL) {
            if (string_equal(target_peer->ip, exclude_peer->ip) && (target_peer->port == exclude_peer->port)) continue;
        }

        send_inform(target_peer, new_peer);
    }
    pthread_mutex_unlock(&network_mutex);
    return 0;
}

int update_network_from_reply(int sockfd, uint32_t *total_peers)
{
    ReplyHeader_t reply_h;
    if (compsys_helper_readn(sockfd, &reply_h, REPLY_HEADER_LEN) == -1) return -1;

    uint32_t length = be32toh(reply_h.length);
    uint32_t status = be32toh(reply_h.status);

    if (status != STATUS_OK) {
        char *error_msg = (char*)malloc(length + 1);
        if (length > 0) compsys_helper_readn(sockfd, error_msg, length);
        free(error_msg);
        return -1;
    }

    if (length == 0 || (length % PEER_ADDR_LEN != 0)) return -1;

    *total_peers = length / PEER_ADDR_LEN;
    char *peer_list_data = (char*)malloc(length);
    if (!peer_list_data) return -1;

    if (compsys_helper_readn(sockfd, peer_list_data, length) == -1) {
        free(peer_list_data);
        return -1;
    }

    for (uint32_t i = 0; i < *total_peers; i++) {
        NetworkAddress_t *peer_addr = (NetworkAddress_t*)(peer_list_data + i * PEER_ADDR_LEN);
        add_peer_to_network(peer_addr, 0); 
    }

    free(peer_list_data);
    return 0;
}

int register_with_peer(NetworkAddress_t *peer_addr)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(be32toh(peer_addr->port)); 
    inet_pton(AF_INET, peer_addr->ip, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        return -1;
    }

    if (send_request(sockfd, COMMAND_REGISTER, NULL, 0) == -1) {
        close(sockfd);
        return -1;
    }

    uint32_t received_peers = 0;
    int result = update_network_from_reply(sockfd, &received_peers);

    close(sockfd);
    return result;
}

int request_file(char *filename)
{
    pthread_mutex_lock(&network_mutex);
    if (peer_count == 0) {
        fprintf(stderr, ">> Cannot retrieve file: No other peers in network.\n");
        pthread_mutex_unlock(&network_mutex);
        return -1;
    }
    
    
    NetworkAddress_t *target_peer = NULL;
    for (uint32_t i = 0; i < peer_count; i++) {
        if (be32toh(network[i]->port) == 12345) {
            target_peer = network[i];
            break;
        }
    }

    if (target_peer == NULL) {
        fprintf(stderr, ">> Cannot retrieve file: Target peer (12345) not found in network.\n");
        pthread_mutex_unlock(&network_mutex);
        return -1;
    }
    pthread_mutex_unlock(&network_mutex);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(be32toh(target_peer->port));
    inet_pton(AF_INET, target_peer->ip, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        return -1;
    }

    if (send_request(sockfd, COMMAND_RETREIVE, filename, strlen(filename)) == -1) {
        close(sockfd);
        return -1;
    }

    
    uint32_t received_blocks = 0, total_blocks = 0;
    FILE *file_out = NULL;
    int result = 0;
    char full_file_path[PATH_LEN + 5] = {0}; 
    ReplyHeader_t reply_h; 
    
    snprintf(full_file_path, sizeof(full_file_path), "./%s", filename); 

    for (;;) {
        if (compsys_helper_readn(sockfd, &reply_h, REPLY_HEADER_LEN) == -1) { result = -1; break; }

        uint32_t len = be32toh(reply_h.length);
        uint32_t status = be32toh(reply_h.status);
        uint32_t block_num = be32toh(reply_h.this_block);
        total_blocks = be32toh(reply_h.block_count);

        if (status != STATUS_OK) {
            char *error_msg = (char*)malloc(len + 1);
            memset(error_msg, 0, len + 1);
            if (len > 0) compsys_helper_readn(sockfd, error_msg, len);
            fprintf(stderr, ">> Retrieval failed with status %u: %s\n", status, error_msg);
            free(error_msg);
            result = -1;
            break;
        }

        
        if (file_out == NULL) {
            file_out = fopen(full_file_path, "wb");
            if (!file_out) { 
                fprintf(stderr, ">> Error opening file for writing: %s\n", full_file_path);
                result = -1; 
                break; 
            }
        }
        
        char *data_block = (char*)malloc(len);
        if (compsys_helper_readn(sockfd, data_block, len) == -1) {
            free(data_block);
            result = -1;
            break;
        }

        hashdata_t calculated_block_hash;
        get_data_sha(data_block, calculated_block_hash, len, SHA256_HASH_SIZE);
        if (memcmp(calculated_block_hash, reply_h.block_hash, SHA256_HASH_SIZE) != 0) {
            fprintf(stderr, ">> Block %u hash mismatch.\n", block_num);
            result = -1; 
            break; 
        }

        long offset = (long)block_num * MAX_PAYLOAD_SIZE;

        if (fseek(file_out, offset, SEEK_SET) != 0) {
            fprintf(stderr, ">> Error seeking to block %u offset %ld.\n", block_num, offset);
            free(data_block);
            result = -1;
            break;
        }

        
        if (fwrite(data_block, 1, len, file_out) != len) {
             fprintf(stderr, ">> Error writing block %u to file.\n", block_num);
             free(data_block);
             result = -1;
             break;
        }
        
        
        free(data_block);
        received_blocks++;

        if (received_blocks == total_blocks) break;
    }

    if (file_out) {
        
        fclose(file_out);
        if (result == 0) {
            hashdata_t calculated_total_hash;
            
            get_file_sha(full_file_path, calculated_total_hash, SHA256_HASH_SIZE);
            if (memcmp(calculated_total_hash, reply_h.total_hash, SHA256_HASH_SIZE) != 0) {
                fprintf(stderr, ">> File hash mismatch for %s.\n", filename);
                result = -1;
            } else {
                fprintf(stdout, ">> File '%s' successfully retrieved and verified.\n", filename);
            }
        } else {
             fprintf(stderr, ">> File retrieval failed before verification.\n");
        }
    }

    close(sockfd);
    return result;
}

int handle_register(int sockfd, RequestHeader_t *req_h, char *remote_ip)
{
    uint32_t remote_port = be32toh(req_h->port);

    pthread_mutex_lock(&network_mutex);
    if (find_peer(remote_ip, remote_port) != NULL) {
        pthread_mutex_unlock(&network_mutex);
        return send_reply(sockfd, STATUS_PEER_EXISTS, "Peer exists.", strlen("Peer exists.") + 1, 0, 1, req_h->signature);
    }
    pthread_mutex_unlock(&network_mutex);

    NetworkAddress_t joining_peer;
    memset(&joining_peer, 0, PEER_ADDR_LEN);
    memcpy(joining_peer.ip, remote_ip, IP_LEN);
    joining_peer.port = req_h->port; 
    memcpy(joining_peer.signature, req_h->signature, SHA256_HASH_SIZE);

    if (add_peer_to_network(&joining_peer, 1) != 0) {
        return send_reply(sockfd, STATUS_OTHER, "Internal error.", strlen("Internal error.") + 1, 0, 1, req_h->signature);
    }
    
    uint32_t reply_len = peer_count * PEER_ADDR_LEN;
    char *reply_body = (char*)malloc(reply_len);
    if (!reply_body) return -1;

    pthread_mutex_lock(&network_mutex);
    for (uint32_t i = 0; i < peer_count; i++) {
        memcpy(reply_body + i * PEER_ADDR_LEN, network[i], PEER_ADDR_LEN);
    }
    pthread_mutex_unlock(&network_mutex);

    int result = send_reply(sockfd, STATUS_OK, reply_body, reply_len, 0, 1, req_h->signature);
    free(reply_body);

    NetworkAddress_t *newly_added_peer = find_peer(remote_ip, remote_port);
    if (newly_added_peer) send_inform_to_all_but(newly_added_peer, newly_added_peer); 

    return result;
}

int handle_retrieve(int sockfd, RequestHeader_t *req_h)
{
    uint32_t remote_port = be32toh(req_h->port);
    NetworkAddress_t *source_peer = NULL;

    pthread_mutex_lock(&network_mutex);
    source_peer = find_peer(req_h->ip, remote_port);

    if (source_peer == NULL) {
        pthread_mutex_unlock(&network_mutex);
        return send_reply(sockfd, STATUS_FORBIDDEN, "Not registered.", strlen("Not registered.") + 1, 0, 1, req_h->signature);
    }

    hashdata_t expected_signature;
    calculate_signature((const char *)source_peer->signature, source_peer->salt, expected_signature);
    
    if (memcmp(req_h->signature, expected_signature, SHA256_HASH_SIZE) != 0) {
        pthread_mutex_unlock(&network_mutex);
        return send_reply(sockfd, STATUS_FORBIDDEN, "Invalid signature.", strlen("Invalid signature.") + 1, 0, 1, req_h->signature);
    }
    pthread_mutex_unlock(&network_mutex);

    uint32_t body_len = be32toh(req_h->length);
    char *filename = (char*)malloc(body_len + 1); 
    if (compsys_helper_readn(sockfd, filename, body_len) == -1) {
        free(filename);
        return -1;
    }
    filename[body_len] = '\0'; 

    FILE *file_in = fopen(filename, "rb");
    if (!file_in) {
        send_reply(sockfd, STATUS_BAD_REQUEST, "File not found.", strlen("File not found.") + 1, 0, 1, req_h->signature);
        free(filename);
        return -1;
    }

    fseek(file_in, 0, SEEK_END);
    long file_size = ftell(file_in);
    fseek(file_in, 0, SEEK_SET);

    hashdata_t total_file_hash;
    get_file_sha(filename, total_file_hash, SHA256_HASH_SIZE);

    uint32_t total_blocks = (file_size + MAX_PAYLOAD_SIZE - 1) / MAX_PAYLOAD_SIZE;
    uint32_t current_block_num = 0;
    long bytes_sent = 0;

    while (bytes_sent < file_size) {
        uint32_t current_block_len = (file_size - bytes_sent < MAX_PAYLOAD_SIZE) 
                                     ? (uint32_t)(file_size - bytes_sent) 
                                     : MAX_PAYLOAD_SIZE;

        char *buffer = (char*)malloc(current_block_len);
        fread(buffer, 1, current_block_len, file_in);

        if (send_reply(sockfd, STATUS_OK, buffer, current_block_len, 
                       current_block_num, total_blocks, total_file_hash) == -1) {
            free(buffer);
            fclose(file_in);
            free(filename);
            return -1;
        }

        free(buffer);
        bytes_sent += current_block_len;
        current_block_num++;
    }
    
    fclose(file_in);
    free(filename);
    return 0;
}

int handle_inform(int sockfd, RequestHeader_t *req_h)
{
    uint32_t body_len = be32toh(req_h->length);
    if (body_len != PEER_ADDR_LEN) return -1;

    NetworkAddress_t new_peer;
    if (compsys_helper_readn(sockfd, &new_peer, PEER_ADDR_LEN) == -1) return -1;
    
    add_peer_to_network(&new_peer, 0);

    return 0; 
}

void* handle_peer_request(void *socket_ptr)
{
    
    PeerRequest_t *req_info = (PeerRequest_t*)socket_ptr;
    int sockfd = req_info->sockfd;
    
    RequestHeader_t req_h;
    if (compsys_helper_readn(sockfd, &req_h, REQUEST_HEADER_LEN) == -1) goto cleanup;

    uint32_t command = be32toh(req_h.command);

    switch (command) {
        case COMMAND_REGISTER: handle_register(sockfd, &req_h, req_info->remote_ip); break;
        case COMMAND_RETREIVE: handle_retrieve(sockfd, &req_h); break;
        case COMMAND_INFORM: handle_inform(sockfd, &req_h); break;
        default:
            send_reply(sockfd, STATUS_MALFORMED, "Unknown command.", strlen("Unknown command.") + 1, 0, 1, req_h.signature);
            break;
    }

cleanup:
    close(sockfd);
    free(req_info);
    return NULL;
}

void* client_thread()
{
    char peer_ip[IP_LEN];
    fprintf(stdout, "Enter peer IP to connect to (or '0' for initial peer): ");
    scanf("%15s", peer_ip); 

    if (!string_equal(peer_ip, "0")) {
        char peer_port[PORT_STR_LEN];
        fprintf(stdout, "Enter peer port: ");
        scanf("%15s", peer_port); 

        NetworkAddress_t peer_address_target;
        memset(&peer_address_target, 0, sizeof(NetworkAddress_t));
        memcpy(peer_address_target.ip, peer_ip, IP_LEN);
        peer_address_target.port = htobe32(atoi(peer_port)); 

        if (register_with_peer(&peer_address_target) == -1) {
            fprintf(stderr, "Client: Registration failed. Exiting.\n");
            return NULL;
        }
    }

    while (1) {
        char file_path[PATH_LEN];
        fprintf(stdout, "\n--- Network Peers: %u ---\n", peer_count);
        fprintf(stdout, "Enter file path to retrieve (or 'quit'): ");
        scanf("%127s", file_path); 

        if (string_equal(file_path, "quit")) break;
        request_file(file_path);
    }
    
    return NULL;
}

void* server_thread()
{
    int listenfd, connfd;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen = sizeof(cli_addr);

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) return NULL;

    int optval = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(be32toh(my_address->port)); 
    
    if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(listenfd);
        return NULL;
    }
    
    if (listen(listenfd, LISTEN_BACKLOG) < 0) {
        close(listenfd);
        return NULL;
    }

    printf("Server listening on port %u...\n", be32toh(my_address->port));

    while (1) {
        connfd = accept(listenfd, (struct sockaddr *)&cli_addr, &clilen);
        if (connfd < 0) continue;

        char *client_ip = inet_ntoa(cli_addr.sin_addr);
        uint16_t client_port = ntohs(cli_addr.sin_port);
        
        
        PeerRequest_t *req_info = (PeerRequest_t*)malloc(sizeof(PeerRequest_t));
        if (!req_info) {
            close(connfd);
            continue;
        }
        req_info->sockfd = connfd;
        
        memcpy(req_info->remote_ip, client_ip, IP_LEN);
        req_info->remote_port = client_port;

        pthread_t worker_thread_id;
        pthread_create(&worker_thread_id, NULL, handle_peer_request, req_info);
        pthread_detach(worker_thread_id);
    }

    close(listenfd);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    my_address = (NetworkAddress_t*)malloc(sizeof(NetworkAddress_t));
    memset(my_address, 0, sizeof(NetworkAddress_t));
    memcpy(my_address->ip, argv[1], strlen(argv[1]));
    uint32_t host_port = atoi(argv[2]); 
    my_address->port = host_port;

    if (!is_valid_ip(my_address->ip) || !is_valid_port(my_address->port)) exit(EXIT_FAILURE);
    
    my_address->port = htobe32(my_address->port);

    fprintf(stdout, "Create a password: ");
    scanf("%15s", my_raw_password); 
    for (int i=strlen(my_raw_password); i<PASSWORD_LEN; i++) my_raw_password[i] = '\0';

    char salt[SALT_LEN+1] = "0123456789ABCDEF\0";
    memcpy(my_address->salt, salt, SALT_LEN);
    calculate_signature(my_raw_password, my_address->salt, my_request_signature);
    
    printf("Peer Address: %s:%u\n", my_address->ip, host_port);

    if (pthread_mutex_init(&network_mutex, NULL) != 0) exit(EXIT_FAILURE);

    pthread_t client_thread_id, server_thread_id;
    pthread_create(&server_thread_id, NULL, server_thread, NULL);
    pthread_create(&client_thread_id, NULL, client_thread, NULL);

    pthread_join(client_thread_id, NULL);
    pthread_cancel(server_thread_id); 
    pthread_join(server_thread_id, NULL);

    pthread_mutex_destroy(&network_mutex);
    if (my_address) free(my_address);
    if (network) {
        for (uint32_t i = 0; i < peer_count; i++) free(network[i]);
        free(network);
    }

    exit(EXIT_SUCCESS);          
}