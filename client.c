
#define JUST_FOR_FUN

/*
	TODO:
		Handle cd in server
		Need to handle stdout stderr
		inc TAB in readline
		Add Stat in server

	BUG:
	>>> When server terminated, SIGPIPE was detected only second subsequent command, first was return empty output
		i.e., client terminate with SIGPIPE detected on second subsequent command.

	>>> Secong cmd line wrap inside first line/overwite 

	Fixed:
	>>> if clint gives NULL ip / Empty line the subsequent commads failed to send to server.
		----Blocked empty input in clihandler. 

	>>> log cli input cause SIGABRT in free().
		----Handled with memset 

	>>> client not terminates if server shutdown.
		----Handled with SIGPIPE (Kill client)

	Added:
	>>> validate user command in client side itself <<< Implementated buitin functions.
	>>> Handle CD in client 

*/

//#define ENABLE_DEBUG

#ifdef ENABLE_DEBUG
	#define DEBUG_CMDLINE
	#define DEBUG_BUILTIN
	#define DEBUG_CLIHANDLER
	#define DEBUG_SENDRECV
	#define DEBUG_ENVIRON
	#define DEBUG_CHDIR
	#define DEBUG_RESOLVEDIR
	#define DBG_FILENAME_RESOLVER
	#define DEBUG_LS_CMD
	#define DEBUG_CP_CMD
#endif


#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>  /* read, close */
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> /* inet_addr */
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <readline/readline.h>
#include <readline/history.h>

#define LOCAL_MACHINE
#define PORT 2020


#define CLI_DELIM ":"
#define ENV_DELIM "|"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

//#define MAC_PROMPT_TEXT ANSI_COLOR_GREEN "%s" ANSI_COLOR_CYAN "@" ANSI_COLOR_BLUE "%s" ANSI_COLOR_MAGENTA "# " ANSI_COLOR_RESET

char *encode_cmdline(char **in_line);
extern char **environ;

enum rval {
	RETURN_FAILURE = -1,
	RETURN_SUCCESS = 0
};

enum boolean {
	TRUE = true,
	FALSE = false
};

enum flags {
	NO_VALUE = 0,
	GETPWD,
	STRIPDIR,
	MERGEDIR,
	NO_BUILTINS
};

int sockfd = -1;

char *stripwhite ( char *string );

/* Send/Receive the data to/from server */
int transceiver(size_t dataout_size, char *dataout, char *datain)
{
	int retval = -1;

	do {
		if ((dataout_size <= 0) || (dataout == NULL) || (datain == NULL)) {
			printf("transceiver: invalid args !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		if (send(sockfd, datain, strlen(datain), 0 ) < 0) {
			printf("transceiver: send failed !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		#ifdef JUST_FOR_FUN
		//sleep(1);
		#endif

		//memset(dataout, 0x00, sizeof dataout);
		if (recv(sockfd, dataout, dataout_size, 0) < 0) {
			printf("transceiver: recv failed !!!");
			retval = RETURN_FAILURE;
			break;
		}

		#ifdef DEBUG_SENDRECV
		printf("\n---------------------\n");
		printf("%s\n", dataout);
		printf("---------------------\n\n");
		#endif

		/* Write, only error message on console */ 
		/* Server sends ACK=1 (dataout = "1") on successful completion of request */
		if (atoi(dataout) == 1) {
			strcpy(dataout, "");
		}

		retval = RETURN_SUCCESS;
	} while (0);

	return retval;
}

/* Send data to server. client does'nt wait for reply */
int sendto_server(size_t dataout_size, char *dataout, char *datain)
{
	int retval = -1;

	do {
		if ((dataout_size <= 0) || (dataout == NULL) || (datain == NULL)) {
			printf("transceiver: invalid args !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		printf("sendto server [%s]\n", datain);

		if (send(sockfd, datain, strlen(datain), 0 ) < 0) {
			printf("transceiver: send failed !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		sleep(1);

		retval = RETURN_SUCCESS;
	} while (0);

	return retval;
}

int changedir(char *dir)
{
	int retval = -1;
	char *dirtok = NULL;
	char *saveptr = NULL;
	static char buffer[PIPE_BUF] = {0};


	do {
		#ifdef DEBUG_CHDIR
		printf("inside dir [%s]\n", dir);
		#endif

		if (dir == NULL) {
			printf("cd: invalid args !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		if (send(sockfd, dir, strlen(dir), 0 ) < 0) {
			printf("cd: send failed !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		memset(buffer, 0x00, sizeof buffer);
		if (recv(sockfd, buffer, sizeof buffer, 0) < 0) {
			printf("changedir: recv failed !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		if (strlen(buffer) != 0) {
			dirtok = strtok_r(buffer, CLI_DELIM, &saveptr);
			if ((dirtok != NULL) && (strcmp(dirtok, "1") == 0) && (saveptr != NULL) && (strlen(saveptr) != 0)) {
				#ifdef DEBUG_CHDIR
				printf("cd: output: %s\n", saveptr); /* saveptr hold the current working directory */
				#endif
				if (setenv("PWD", saveptr, 1) != 0 ) {
					perror("changedir: setenv failed !!!\n");
					retval = RETURN_FAILURE;
					break;
				}
			} else {
				printf("cd: %s\n", buffer);
			}
		}
		retval = RETURN_SUCCESS;
	} while (0);

	return retval;
}

/* In future this function may return funptr of inbuilt functions */
int exec_builtins(char *cli_cmd)
{
	int retval = -1;
	char *cmd = NULL;
	char *saveptr = NULL;
	static char cli_buffer[LINE_MAX] = {0};
 
	do {
		retval = RETURN_FAILURE; /* Added for readability */

		if (cli_cmd == NULL) {
			printf("is_builtin: invalid input args !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		strcpy(cli_buffer, cli_cmd);
		#ifdef DEBUG_BUILTIN
		printf("is_builtin: input cmd [%p] [%s] cli_buffer [%s]\n", cli_cmd, cli_cmd, cli_buffer);
		#endif
		cmd = strtok_r(cli_buffer, CLI_DELIM, &saveptr);
		#ifdef DEBUG_BUILTIN
		printf("is_builtin: fetched cli_cmd [%p] cmd [%s]\n", cli_cmd, cmd);
		#endif
		/* check inbuilt modules */
		if (strcmp(cmd, "cd") == 0) {
			//retval = changedir(saveptr);
			retval = changedir(cli_cmd);
			if (retval == RETURN_FAILURE) {
				printf("shell: cd: failed !!!\n");
			}
		} else {
			retval = NO_BUILTINS;
			break;
		}

		retval = RETURN_SUCCESS;	
	} while (0);

	return retval;
}

int cmdline_input_handler(char *cli_cmd)
{
	int retval = -1;
	static char buffer[PIPE_BUF] = {0};


	do {
		if (cli_cmd == NULL) {
			printf("clihandler: invalid args !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		#ifdef DEBUG_CLIHANDLER
		printf("clihandler: socket [%d] cli_cmd [%p] [%s]\n", sockfd, cli_cmd, cli_cmd);
		#endif

		memset(buffer, 0x00, sizeof buffer);

		#if 1
		retval = exec_builtins(cli_cmd); /* Exec builtin if available */
		#ifdef DEBUG_CLIHANDLER
		printf("exec_builtins return cli_cmd ptr [%p] [%s]\n", cli_cmd, cli_cmd); /* Must not unchanged */
		#endif
		if (retval == RETURN_SUCCESS) {
			#ifdef DEBUG_CLIHANDLER
			printf("clihandler: builtin executed.\n");
			#endif
			retval = RETURN_SUCCESS;
			break;
		} else if (retval == NO_BUILTINS) {
			/* If input is not a builtin
					Send to server to exec new process 
			*/
			memset(buffer, 0x00, sizeof buffer);
			#if 1
			if (transceiver(sizeof buffer, buffer, cli_cmd) == RETURN_FAILURE) {
				printf("shell: send-receive failed !!!\n");
				retval = RETURN_FAILURE;
				break;
			}

			if (strlen(buffer) != 0) {
				#ifdef JUST_FOR_FUN
				char *ptr = buffer;

				while(*ptr != '\0') {
					putc(*ptr, stdout);
					fflush(stdout);
					*ptr++;
					usleep(5000);
				}
				#else
				printf("%s", buffer);
				#endif
				fflush(stdout);
			}
			#else
			if (sendto_server(sizeof buffer, buffer, cli_cmd) == RETURN_FAILURE) {
				printf("shell: send failed !!!\n");
				retval = RETURN_FAILURE;
				break;
			}
			#endif
		}
		#endif

		#if 0
		if (transceiver(sizeof buffer, buffer, cli_cmd) == RETURN_FAILURE) {
			printf("shell: send-receive failed !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		if (strlen(buffer) != 0) {
			printf("%s", buffer);
			fflush(stdout);
		}
		#endif

		retval = RETURN_SUCCESS;
	} while (0);

	return retval;
}

/*
	Read the command line and encode it with delimiter
	Read cli from input arg: line (Heap array)
	Encode and again store it in same memory (line) also return the same pointer
*/
char *encode_cmdline(char **in_line)
{
	char *ptr = NULL;
	char *saveptr = NULL;
	static char str[LINE_MAX] = {0};
	static char dest[LINE_MAX] = {0};

	if (in_line == NULL) {
		printf("encode_cmdline: Error: Null Arg Recvd !!!\n");

		return NULL;
	}

	memset(str, 0x00, sizeof str);
	memset(dest, 0x00, sizeof dest);

	#ifdef DEBUG_CMDLINE
	printf("encode_cmdline: args in_line[%p]\n", *in_line);
	#endif
	strcpy(str, *in_line);
	#ifdef DEBUG_CMDLINE
	printf("encode_cmdline: before strtok: in_line [%s] str [%s]\n", *in_line, str);
	#endif
	ptr = strtok_r(str, " ", &saveptr);
	while(ptr != NULL) {
		strcat(dest, ptr);
		strcat(dest, CLI_DELIM);
		ptr = strtok_r(NULL, " ", &saveptr);
	}
	dest[strlen(dest) - 1 ] = '\0';

	memset(*in_line, 0x00, sizeof *in_line); /* TODO: check its good practice of memset the heap mmry */
	strcpy(*in_line, dest);
	#ifdef DEBUG_CMDLINE
	printf("encode_cmdline: out args output in_line[%p] [%s]\n", *in_line, *in_line);
	#endif

	return *in_line;
}

/*
	Strip whitespace from the start and end of STRING.
	Return a pointer into STRING.
*/
inline char *stripwhite ( char *string )
{
	register char *s, *t;

	if ( string == NULL ) {
		return NULL;
	}

	s = string;
	while( whitespace (*s)) {
	 s++;
	}

	if (*s == 0) {
		return (s);
	}

	t = s + strlen (s) - 1;
	while (t > s && whitespace (*t)) {
		t--;
	}

	*++t = '\0';

	return s;
}


/*
	Read command line data, encode and return a pointer to it.
	Returns NULL on EOF or EMPTY input. 
*/
char *get_cmdline()
{
	char *retval = NULL;
	static char *tmpline = NULL;
	static char *line_read = NULL;
	static char prompt[LINE_MAX] = {0};	

	do {
		/* Frame prompt string */
		memset(prompt, 0x00, sizeof prompt);
		sprintf(prompt,
			ANSI_COLOR_GREEN "%s" ANSI_COLOR_CYAN "@" ANSI_COLOR_BLUE "%s" ANSI_COLOR_MAGENTA "# " ANSI_COLOR_RESET,
			getenv("USER"), getenv("PWD"));

		if (line_read != NULL) { /* free heap mmry if already allocated by realine () */
			#ifdef DEBUG_CMDLINE
			printf("free existing heap memory allocated by realine () [%p]\n", line_read);
			#endif
			free(line_read);
			line_read = NULL;
		}

		/* Get a command line from the user */
		line_read = readline (prompt); /* returns pointer to heap mmry */
		#ifdef DEBUG_CMDLINE
		printf("readline return line_read ptr [%p]\n", line_read);
		#endif
		tmpline = NULL;
		tmpline = stripwhite(line_read); /* got valid str in heap mmry */
		#ifdef DEBUG_CMDLINE
		printf("stripwhite return tmpline [%p] [%s]\n", tmpline, tmpline);
		#endif

		if (tmpline && *tmpline) {
			add_history (tmpline); /* save command line to the history. equivalent to BASH_HISTORY */

			#ifdef DEBUG_CMDLINE
 			printf("Before encode [%p] [%s]\n", tmpline, tmpline);
			#endif
			if (encode_cmdline(&tmpline) == NULL) {
				printf("Encoding cli command failed: please retry !!!");
				retval = NULL;
				break;
			}
			#ifdef DEBUG_CMDLINE
			printf("After encode [%p] [%s] line_read [%s]\n", tmpline, tmpline, line_read);
			#endif
			retval = tmpline; /* return here in normal flow */
			break;
		}

		retval = NULL;
	} while (0);


	if ((line_read != NULL) && (retval == NULL)) { /* free heap mmry on failure */
		#ifdef DEBUG_CMDLINE
		printf("Failure: free existing heap memory allocated by realine () [%p]\n", line_read);
		#endif
		free(line_read);
		line_read = NULL;
	}

	return retval;
}

int get_server_environ(int socket)
{
	int retval = -1;
	int setenverr = 0;
	size_t nbytes = 0;
	char buffer[PIPE_BUF] = {0};
	char *ptr = NULL;
	char *saveptr = NULL;

	do {
		/* Client receive ACK here */
		memset(buffer, 0x00, sizeof buffer);
		nbytes = recv(socket, buffer, sizeof(buffer), 0);
		if (nbytes == 0) {
				printf("get_server_environ: sock recv: NULL Input !!!");
				retval = RETURN_FAILURE;
				break;
		} else if (nbytes == -1) {
				perror("get_server_environ: socket recv() failed !!!");
				close(socket);
				retval = RETURN_FAILURE;
				break;
		}

		#ifdef DEBUG_ENVIRON
		printf("get_server_environ: recvd buffer: %s\n", buffer );
		#endif

		#if 0 /* commented: disabled server environment variable sharing */
		ptr = strtok_r(buffer, ENV_DELIM, &saveptr);
		/* setenv */
		while(ptr != NULL) {
			if (strstr(ptr, "=") != NULL) {

				#ifdef DEBUG_ENVIRON 
				printf(">>> %s\n", ptr);
				#endif

				if (putenv(ptr) != 0) {
					setenverr = 1;
					break;
				}
			}

			/* decode next env */
			ptr = strtok_r(NULL, ENV_DELIM, &saveptr);
		}

		if (setenverr == 1) {
			perror("Setenv error :");
			retval = RETURN_FAILURE;
			break;
		}
		#else
		if (setenv("PWD", buffer, 1) != 0 ) {
			perror("get_server_environ: setenv failed !!!");
			retval = RETURN_FAILURE;
			break;
		}
		#endif

		retval = RETURN_SUCCESS;
	} while (0);


	#ifdef DEBUG_ENVIRON
	int i = 0;

	printf("\nEnvironment Variables...\n");
	while(*(environ + i) != NULL) {
			printf("%s\n", *(environ + i));
			i++;
	}
	#endif


	return retval;
}

int connect_server(char const *server_addr, struct sockaddr_in serv_addr)
{
	int retval = -1;

	do {
			if (server_addr == NULL) {
				printf("Connect_server: Invalid args !!!");
				retval = RETURN_FAILURE;
				break;
			}

			printf("\n=========================================================\n");
			printf("Connecting ...\n");

			if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
			{
				printf("\n Socket creation error !!!\n");
				retval = RETURN_FAILURE;
				break;
			}

			memset(&serv_addr, 0x00, sizeof(serv_addr));

			serv_addr.sin_family = AF_INET;
			serv_addr.sin_port = htons(PORT);
			serv_addr.sin_addr.s_addr=inet_addr(server_addr);

			if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
			{
				printf("\nConnection Failed !!!\n");
				retval = RETURN_FAILURE;
				break;
			}

			if ( get_server_environ( sockfd ) != RETURN_SUCCESS ) {
				printf("Getenv failed !!!\n");
				retval = RETURN_FAILURE;
				break;
			}

			retval = sockfd; /* Returns socket */
			printf("\nConnected to %s:%d \n", server_addr, PORT);
			printf("=========================================================\n");
	} while (0);

	return retval;
}

void sigpipe_handler(int signum)
{
    printf("SIGPIPE received !!! Exiting....\n");

	exit(1);

    return;
}

int main(int argc, char const *argv[])
{
	int pid = -1;
	int retval = -1;
	int isocket = -1;
	char const *server_addr = NULL;
	struct sockaddr_in serv_addr;
	char buffer[PIPE_BUF] = {0};
	char *cmdlineptr = NULL;

	signal(SIGPIPE, sigpipe_handler);

	#ifdef LOCAL_MACHINE
	server_addr = "127.0.0.1";
	#else
	if (argc < 2) {
		printf("usage: client.out <server ip address>\n");
		exit(1);
	}

	server_addr = argv[1];
	#endif

	isocket = connect_server(server_addr, serv_addr);
	if (isocket < 0) {
		printf("\nFailed to connect server: %s %d !!!\n\n", server_addr, PORT);
		return -1;
	}

	system("clear"); /* clear command prompt screen */

	while(1) {
		cmdlineptr = NULL;
		/* Getting Client side cli_cmd */
		memset(buffer, 0x00, sizeof buffer);
		cmdlineptr = get_cmdline();
		if (cmdlineptr == NULL) { /* Hit on empty input line or error */
			continue;
		}

		//printf(">>>>> [%s]\n", cmdlineptr);

		#if 0 /* Enable if need array to store command line input */
		strcpy(buffer, cmdlineptr);
		printf(">>>>> cmdlineptr [%s] [%s]\n", buffer, cmdlineptr);
		#ifdef DEBUG_CMDLINE
		printf("Input cli: buffer [%s] cmdlineptr [%p] [%s]\n", buffer, cmdlineptr);
		#endif
		if (strlen(buffer) == 0) {
			continue;
		}
		#endif

		/* Validate and Execute Commands */
		#if 0
		pid = fork();

		if (pid < 0) {
			printf("fork error !!!\n");
			exit(1);
		} else 	if (pid == 0) {
			retval = cmdline_input_handler(cmdlineptr);
			if (retval != RETURN_SUCCESS) {
				printf("exec failed !!!\n");
				continue;
			}
		} else {
			printf(">>\n ");
			continue;
		}
		#else
		/* Validate and Execute Commands */
		retval = cmdline_input_handler(cmdlineptr);
		if (retval != RETURN_SUCCESS) {
			printf("exec failed !!!\n");
			continue;
		}
		#endif
	}

	close(isocket);
	return 0;
}



/* EOF */
