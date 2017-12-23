#define JUST_FOR_FUN

/*

	TODO:
		Terminate thread task when Ctrl+C raise in client side
		Handle Path-resolution for non-builtin execs

	Fixed:
		Setenv failed for OLDPWD: Need a logic to add new environmental variable in set_thread_env()

	Added
		Free: argv allocated in decode_packet char** in execute_process & exec_builtins

*/

#define ENABLE_DEBUG

#ifdef ENABLE_DEBUG
	#define DEBUG
	#define DEBUG_EXEC
//	#define DEBUG_CHDIR
	#define DEBUG_PACKET_DECODER
	#define DEBUG_CALLBACK_PROCESS
//	#define DEBUG_PATH_RESOLVER
//	#define DEBUG_LIST_FILES
//	#define DEBUG_ASSIGN_ENVIRON
//	#define DEBUG_SETENV
//	#define DEBUG_GETENV
//	#define DEBUG_FSTAT
//	#define DEBUG_DSTAT
#endif

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <libgen.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>

#define MUTEX

#define BUFF_SIZE 1024
#define USER_ENV_MAX 10
#define ENV_MAX 10
#define PADD_NBYTES 256
#define MAX_THREADS 3
#define LS_BUFF_MAX 24
#define CLI_DELM ":"

extern const int max_clients;
//char *s_port = NULL;
char s_port[100];

extern char **environ;
char **g_env;

int portno = 0;
int numConnections = 0;
char *s_env[ENV_MAX] = { "HOME", "PWD" , "PATH", "SHELL", "USER", "SESSION" };

/* Added: A lock to access numConnections.
   Note that this file needs to be compiled
   with -DMUTEX for the lock to actually be used */
#ifdef MUTEX
pthread_mutex_t lock_client_count = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lock_cp = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lock_ls = PTHREAD_MUTEX_INITIALIZER;
#endif

/* Macro definition for boolean values */
enum boolean {
	TRUE = true,
	FALSE = false
};


/* Macros definition for -ve integers */
enum {
	PROCFAILED = -2,
	FAILURE = -1
};

/* Macro definition for +ve integers */
enum {
	SUCCESS = 0,
	BADPROC = 1,
	CONT_LOOP
};

enum rval {
	RETURN_ERROR = -2,
	RETURN_FAILURE = -1,
	RETURN_SUCCESS = 0
};

typedef struct st_clntinfo
{
	//pthread_t *t_id;
    int sockfd;
	char **envptr;
} clntdata_t;

struct st_cpargs {
	int cperrno;
	char *src_file;
	char *dest_file;
};

typedef struct st_ls {
	int socket;
	int ls_errno;
	int argc;
	char **argv;
	char **envptr;
} lsdata_t;


/* A structure which contains information on the commands this program
   can understand. */
typedef struct {
		char *name;           /* User printable name of the function. */
		int *process;       /* Function to call to do the job. */
		char **argv;
		char *doc;            /* Documentation for this function.  */
} builtins_t;

char **decode_packet(char *args);
builtins_t *is_builtin_function(char *name);

char *strcpy_w(char *dest, char *src);
int set_thread_env(char ***environ, const char *name, char *value);
char *get_thread_env(char **environ, const char *name);
int cp_wrapper(clntdata_t *client_data, char *output, char **command);
int ls_wrapper (clntdata_t *client_data, char *output, char **arg);
int cd_wrapper(clntdata_t *client_data, char *output, char **arg);
int get_pwd(clntdata_t *client_data, char *output_msgptr, char **arg);
void *list_files(void *arg);

builtins_t builtin_cmds[] = {
		{ "ls", (int *)ls_wrapper, NULL, "List directory contents" },
		{ "cp", (int *)cp_wrapper, NULL, "Copy files and directories" },
		{ "cd", (int *)cd_wrapper, NULL, "Change current working directory"},
		{ "pwd", (int *)get_pwd, NULL, "Print the current working directory" },
		//{ "exit", (int *)exit_cxn, NULL, "Terminate the requested client connectivity" },
#if 0
		{ "delete", com_delete, "Delete FILE" },
		{ "help", com_help, "Display this text" },
		{ "?", com_help, "Synonym for `help'" },
		{ "quit", com_quit, "Quit using Fileman" },
		{ "rename", com_rename, "Rename FILE to NEWNAME" },
		{ "stat", com_stat, "Print out statistics on FILE" },
		{ "view", com_view, "View the contents of FILE" },
#endif
		{ NULL, NULL, NULL, NULL }
};

int get_pwd(clntdata_t *client_data, char *output_msgptr, char **arg)
{
	int retval = 0;

	do {
		if ((client_data == NULL) || (output_msgptr == NULL) || (arg == NULL)) {
			printf("get_pwd: invalid arguments !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		if ((client_data->envptr == NULL) || (output_msgptr == NULL) || (arg == NULL)) {
			printf("get_pwd: invalid arguments\n");
			retval = RETURN_FAILURE;
			break;
		}

		sprintf(output_msgptr, "%s\n", get_thread_env(client_data->envptr, "PWD"));
		printf("get_pwd [%s]\n", output_msgptr);

		retval = RETURN_SUCCESS;
	} while (0);

	return retval;
}

char *strcpy_w(char *dest, char *src)
{
	if ((src == NULL) || (dest == NULL)) {
		return NULL;
	}
	memset(dest, 0x00, sizeof dest);
	return (strcpy(dest, src));
}

/*
 *  findenv -- [Derived from __findenv() used in getenv() library and customised for thread]
 *
 *	Returns pointer to value associated with name, if any, else NULL.
 *	Sets offset to be the offset of the name/value combination in the
 *	environmental array, for use by setenv().
 *
 *	Explicitly removes '=' in argument name.
 */
char *findenv(char **environ, const char *name, int *offset)
{
	size_t len = 0;
	const char *np = NULL;
	char **p = NULL;
	char *c = NULL;

	if ((name == NULL) || (environ == NULL) || (offset == NULL)) {
		printf("findenv: invalid argument !!!\n");
		return NULL;
	}

	for (np = name; *np && (*np != '='); ++np) {
		continue;
	}

	len = np - name;

	for (p = environ; (c = *p) != NULL; ++p) {
		if ((strncmp(c, name, len) == 0) && (c[len] == '=')) {
			*offset = p - environ;
			#ifdef DEBUG_GETENV
			//printf("findenv: output [%s]\n", c + len + 1);
			#endif
			return (c + len + 1);
		}
	}

	*offset = p - environ;

	return NULL;
}

int chdir_td(char **env, char *dir)
{
	int retval = -1;

	do {
		if ((env == NULL) || (dir == NULL)) {
			printf("chdir_td: invalid arguments !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		if (set_thread_env(&env, "PWD", dir) != 0) {
			printf("cd_wrapper: set_thread_env failed !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		printf("chdir_td [%s]\n", dir);

		retval = RETURN_SUCCESS;
	} while (0);

	return retval;
}

char *stat_file(char **envptr, char *file)
{
	char *result = NULL;
	struct passwd *pswd = NULL;
	struct group  *fgrp = NULL;
	struct stat fileinfo = {0};
	char datetime[LS_BUFF_MAX] = {0};
	char file_mode[LS_BUFF_MAX] = {0};
	static char buffer[LINE_MAX] = {0};


	do {
		if ((file == NULL) || (envptr == NULL)) {
			printf("fstat: invalid argument\n");
			result = NULL;
			break;
		}

		if(stat(file, &fileinfo) < 0 ) {
			printf("fstat: stat failed [%s] [%s]\n", strerror(errno), file);
			result = strerror(errno);
			break;
		}

		memset(file_mode, 0x00, sizeof file_mode);
		strcat(file_mode, (S_ISDIR(fileinfo.st_mode)) ? "d" : "-");
		strcat(file_mode, (fileinfo.st_mode & S_IRUSR) ? "r" : "-");
		strcat(file_mode, (fileinfo.st_mode & S_IWUSR) ? "w" : "-");
		strcat(file_mode, (fileinfo.st_mode & S_IXUSR) ? "x" : "-");
		strcat(file_mode, (fileinfo.st_mode & S_IRGRP) ? "r" : "-");
		strcat(file_mode, (fileinfo.st_mode & S_IWGRP) ? "w" : "-");
		strcat(file_mode, (fileinfo.st_mode & S_IXGRP) ? "x" : "-");
		strcat(file_mode, (fileinfo.st_mode & S_IROTH) ? "r" : "-");
		strcat(file_mode, (fileinfo.st_mode & S_IWOTH) ? "w" : "-");
		strcat(file_mode, (fileinfo.st_mode & S_IXOTH) ? "x" : "-");

		pswd = getpwuid(fileinfo.st_uid);
		if (pswd == NULL) {
			perror("stat_file: getuid failed");
			result = strerror(errno);
			break;
		}

		fgrp = getgrgid(fileinfo.st_gid);
		if (fgrp == NULL) {
			perror("stat_file: getgrgid failed");
			result = strerror(errno);
			break;
		}

		memset(datetime, 0x00, sizeof datetime);
		strftime(datetime, LS_BUFF_MAX, "%b %d %H:%M", localtime(&(fileinfo.st_ctime)));

		#if 0
		printf("Fmode [%s]\n", file_mode);
		printf("Fuser [%s: %s]\n", fgrp->gr_name, pswd->pw_name);
		printf("FLink [%d]\n", (int)fileinfo.st_nlink);
		printf("Fsize [%d]\n", (int)fileinfo.st_size);
		printf("Fsize [%luK]\n", fileinfo.st_size/1024);
		printf("Ftime [%s]\n", datetime);
		printf("Fname [%s]\n", basename(file));
		#endif

		memset(buffer, 0x00, sizeof buffer);
		sprintf(buffer, "%s  %d %s %s  %luK %s %s\n", 
			file_mode, (int)fileinfo.st_nlink, fgrp->gr_name, pswd->pw_name, fileinfo.st_size/1024, datetime, basename(file));	

		#ifdef DEBUG_FSTAT
		printf("stat_file: [%s]\n", buffer);
		#endif
		result = buffer;
	} while(0);

	return result;
}


bool is_directory(char *file)
{
	int retval = FALSE;
	struct stat fileinfo = {0};

	do {
		printf("inside: is_directory \n");
		if(stat(file, &fileinfo) < 0 ) {
			perror("is_directory: stat failed");
			retval = FALSE;
			break;
		}

		if (S_ISDIR(fileinfo.st_mode)) {
			retval = TRUE;
			break;
		}

	} while(0);

	return retval;
}

inline int get_argc(char **argv)
{
	char **ptr = NULL;
	int count = 0;

	if (argv == NULL) {
		printf("get_argc: invalid input !!!\n");
		return -1;
	}

	ptr = argv;
	while(*ptr != NULL) {
		count++;
		ptr++;
	}

	return count;
}


int ls_wrapper (clntdata_t *client_data, char *output, char **argv)
{
	void *tret = NULL;
	int retval = -1;
	pthread_t ls_thread;
	lsdata_t ls_args = {-1, -1, -1, NULL, NULL};

	pthread_mutex_init(&lock_ls, NULL);

	do {
		if ((client_data == NULL) || (output == NULL) || (argv == NULL)) {
			printf("ls_wrapper: invalid arguments\n");
			retval = RETURN_FAILURE;
			break;
		}

		ls_args.socket = client_data->sockfd;
		ls_args.envptr = client_data->envptr;
		ls_args.argv   = argv;
		ls_args.argc = get_argc(argv);

		printf("\nls_wrapper: socket [%d] envptr [%p] argc [%d] argv [%p]\n", ls_args.socket, ls_args.envptr, ls_args.argc, ls_args.argv);

		if (pthread_create(&ls_thread, NULL, list_files, (void *)&ls_args) != 0) {
			perror("ls_wrapper: pthread_create failed");	
			retval = RETURN_FAILURE;
			break;
		}

		printf("ls_wrapper: new thread %ld initiated...\n", ls_thread);
		pthread_join(ls_thread, &tret);

	} while(0);

	pthread_mutex_destroy(&lock_ls);

	return retval;
}


char *stat_directory(char **envptr, char *file)
{
	FILE *fp = NULL;
	struct dirent *dirptr = NULL;
	DIR *dir_stream = NULL;
	static char buffer[PATH_MAX] = {0};
	static char output[PIPE_BUF] = {0};
	char *retval = NULL;

	do {
		#ifdef DEBUG_DSTAT
		printf("\nInside stat_directory\n");
		#endif

		if ((envptr == NULL) || (file == NULL)) {
			printf("stat_directory: invalid arguments !!!\n");
			retval = NULL;
			break;
		}

		fp = fopen(file, "r");
		if (fp == NULL) {
			perror("fstat: fopen failed");
			retval = (void *)RETURN_FAILURE;
			break;
		}

		#ifdef DEBUG_DSTAT
		printf("Reading directory...[%s]\n", file);
		#endif

		dir_stream = opendir((const char*)file);
		if (dir_stream == NULL) {
			perror("fstat: opendir failed");
			retval = (void *)RETURN_FAILURE;
			break;
		}

		memset(output, 0x00, sizeof output);
		while((dirptr = readdir(dir_stream)) != NULL ) {
			if (dirptr->d_name[0] == '.') {
				continue;
			}
			memset(buffer, 0x00, sizeof buffer);
			sprintf(buffer, "%s/%s", file, dirptr->d_name);
			//printf("dir [%s] [%s] [%s]\n", dirptr->d_name, buffer, stat_file(envptr, buffer));
			//printf("%s", stat_file(envptr, buffer));
			//fflush(stdout);
			strcat(output, stat_file(envptr, buffer));
		}

		#ifdef DEBUG_DSTAT
		printf("Reading done.\n");
		#endif

		//strcat(output, "\n");
		retval = output;

	} while (0);

	return retval;
}

void *list_files(void *arg)
{

	void *retval = NULL;
	lsdata_t *data = NULL;
	#if 1
	int i = 0;
	int socket = -1;
	int argc = -1;
	int option = -1;
	char **envptr = NULL;
	char **argv = NULL;
	char *exe = "ls";
	bool no_files = TRUE;

	int l_flag = 0;
	int r_flag = 0;
	int t_flag = 0;
	int h_flag = 0;
	int a_flag = 0;
	
	static char file[PATH_MAX] = {0};
	static char buffer[NAME_MAX] = {0};
	static char output[PIPE_BUF] = {0};
	
	
	#ifdef DEBUG_LIST_FILES
	printf("\nInside: %s\n", __FUNCTION__);
	#endif


	pthread_mutex_lock (&lock_ls);

	do {
		if ((arg == NULL)) {
			printf("ls_wrapper: invalid arguments\n");
			retval = (void *)RETURN_FAILURE;
			break;
		}

		memset(output, 0x00, sizeof output);
		memset(buffer, 0x00, sizeof buffer);

		data = (lsdata_t*)arg;
		socket = data->socket;
		envptr = data->envptr;
		argv = data->argv;
		argc = data->argc;

		optind = 0;
		opterr = 0;

		#ifdef DEBUG_LIST_FILES
		printf("ls: input: socket [%d] envptr [%p] argc [%d] argv [%p]\n", socket, envptr, argc, argv);
		#endif

		if (argc <= 0) {
			printf("ls_wrapper: invalid argument count !!!\n");
			retval = (void *)RETURN_FAILURE;
			break;
		}

		while ((option = getopt (argc, argv, "lrtha")) != -1) {
			switch (option)
			{
				case 'l':
					l_flag = 1;
					break;

				case 'r':
					r_flag = 1;
					break;

				case 't':
					t_flag = 1;
					break;

				case 'a':
					a_flag = 1;
					break;

				default:
					printf("Usage ls [OPTION= -lrta] [FILE]\n");
					retval = (void *)RETURN_SUCCESS;
					break;
			}

		}

		#ifdef DEBUG_LIST_FILES
		printf ("ls: l_flag = %d, r_flag = %d, t_value = %d a_flag = %d\n", l_flag, r_flag, t_flag, a_flag);
		#endif

		for (i = optind; i < argc; i++) {
			no_files = FALSE;
			memset(file, 0x00, sizeof file);
			sprintf(file, "%s/%s", get_thread_env(envptr, "PWD"), *(argv + i));
			//strcpy(*(argv + i), buffer);
			#ifdef DEBUG_LIST_FILES
			printf ("ls: Non-option argument [%s]\n", *(argv + i));
			#endif

			if (is_directory(file) == TRUE ) {
				memset(buffer, 0x00, sizeof buffer);
				sprintf(buffer, "\n%s:\n", *(argv + i));
				strcat(output, buffer);
				strcat(output, stat_directory(envptr, file));
			} else {
				strcat(output, stat_file(envptr, file));
			}
		}

		if (no_files == TRUE) {
			#ifdef DEBUG_LIST_FILES
			printf("ls_wrapper: no files spedified.\n");
			#endif
			strcat(output, stat_directory(envptr, get_thread_env(envptr, "PWD")));
		}

		//printf("\nLS TOTAL OUT...\n%s\n", output);
		if (sendto_client(socket, output) == RETURN_FAILURE ) {
			printf("ls: Sendto_Client failed !!!\n");
			retval = (void *)RETURN_FAILURE;
			break;
		}


		retval = (void *)RETURN_SUCCESS;
	} while (0);

	pthread_mutex_unlock (&lock_ls);
	#endif

	pthread_exit(retval);
}

int exec_builtins(clntdata_t *client_data, char *output , builtins_t *command, char *data)
{
	int i = 0;
	int retval = -1;
	int (*callback_process)( clntdata_t *, char *, char **) = NULL;

	do {
		#ifdef DEBUG_CALLBACK_PROCESS
		printf("\ninside %s\n", __FUNCTION__);
		#endif
		if ((client_data == NULL) || (output == NULL) || (command == NULL) || (data == NULL)) {
			printf("exec_builtins: invalid arguments\n");
			retval = RETURN_ERROR;
			break;
		}

		#ifdef DEBUG_CALLBACK_PROCESS
		printf("exec_builtins: input: command[name: %s] data [%s]\n", command->name, data );
		#endif

		(command->argv) = decode_packet(data); /* Preparing arguments to the builtin_functions*/

		#ifdef DEBUG_CALLBACK_PROCESS
		printf("exec_builtins: command->argv [%p]\n", command->argv);

		for (i = 0; (command->argv)[i] != NULL; i++) {
			printf("exec_builtins: command->argv[%d] [%p] [%s]\n", i, (command->argv)[i], (command->argv)[i]);
		}
		#endif

		callback_process = (command->process);  /* Assigning builtin_functions to callback function */
		retval = callback_process(client_data, output, command->argv); /* Function pointer to call builtin_functions */

		#ifdef DEBUG_CALLBACK_PROCESS
		printf("\ncallback_process: returns: %d output: %s\n", retval, output);
		#endif

		#if 1
		if ((command->argv) != NULL) {
			printf("exec_builtins: free: command->argv [%p]\n", command->argv);
			for (i = 0; (command->argv)[i] != NULL; i++) {
				printf("exec_builtins: free: command->argv[%d] [%p] [%s]\n", i, (command->argv)[i], (command->argv)[i]);
				free((command->argv)[i]);
				(command->argv)[i] = NULL;
			}
			free((command->argv));
			(command->argv) = NULL;
		}
		#endif
		//retval = RETURN_SUCCESS;
	} while (0);

	#if 0
	/* ACK */
	if (retval == RETURN_SUCCESS) {
		strcpy(output, "1");
	}
	#endif

	//printf("OUTPUT >>> [%s]\n", output);
	return retval;
}

builtins_t *is_builtin_function(char *name)
{
	register int i;

	//printf("In: %s\n", __FUNCTION__);

	for (i = 0; builtin_cmds[i].name; i++)
		if (strcmp (name, builtin_cmds[i].name) == 0)
			return (&builtin_cmds[i]);

	return ((builtins_t *)NULL);
}


int sendto_client(int socket, char *data_in)
{
	int retval = -1;
	size_t nbytes = 0;
	char *data_out = NULL;


	do {
		if ((socket < 0) || (data_in == NULL)) {
			printf("Sendto_Client: invalid args recvd !!!");
			retval = RETURN_FAILURE;
			break;
		}

		nbytes = strlen(data_in);

		#ifdef DEBUG
		printf("Sendto_Client: len of data in [%ld] bytes\n", nbytes);
		#endif

		data_out = calloc((nbytes + PADD_NBYTES), sizeof *data_out);
		if (data_out == NULL) {
			perror("Send_ACK: Malloc");
			retval = RETURN_FAILURE;
			break;
		}

		strcpy(data_out, data_in);

		#ifdef DEBUG
		printf("Sendto_Client: Data OUT [%s]\n", data_out);
		#endif

		nbytes = send(socket, data_out, strlen(data_out), 0 );
		if ( nbytes < 0 ) {
			perror("Sendto_Client: send() failed ");
			retval = RETURN_FAILURE;
			break;
		}

		#ifdef DEBUG
		printf("Sendto_Client: Written [%ld] bytes\n", nbytes);
		#endif

		retval = RETURN_SUCCESS;
	} while(0);

	if (data_out != NULL) {
		free(data_out);
		data_out = NULL;
	}
	return retval;
}

void *copy_file(void *cpargs)
{
	void *retval = NULL;
	ssize_t n = -1;
	int srcfd = -1;
	int destfd = -1;
	pthread_t crnt_tid = -1;
	char buffer[LINE_MAX] = {0};
	struct st_cpargs *args = cpargs;

	pthread_mutex_lock (&lock_cp);

	do {
		if (args == NULL) {
			printf("cp: invalid arguments !!!\n");
			retval = (void *)RETURN_FAILURE;
			break;
		}

		crnt_tid = pthread_self();

		#ifdef DEBUG_COPY_TASK
		printf("cp: tid_%ld input: src [%s] dest [%s]\n", crnt_tid, args->src_file, args->dest_file);
		#endif

		//pthread_detach(pthread_self());
		srcfd = open(args->src_file, O_RDONLY);
		if (srcfd < 0) {
			perror("cp: open failed: src_file");
			retval = (void *)RETURN_FAILURE;
			break;
		}

		//destfd = open(args->dest_file, O_CREAT | O_RDWR | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
		//destfd = open(args->dest_file, O_CREAT | O_RDWR , S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
		destfd = open(args->dest_file, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
		if (destfd < 0) {
			perror("cp: open failed: dest_file");
			retval = (void *)RETURN_FAILURE;
			break;
		}

		memset(buffer, 0x00, sizeof buffer);

		#ifdef JUST_FOR_FUN
		while ((n = read(srcfd, buffer, 1)) > 0) {
		#else
		while ((n = read(srcfd, buffer, LINE_MAX)) > 0) {
		#endif
			#ifdef DEBUG_COPY_TASK
			printf("%s", buffer);
			fflush(stdout);
			#endif

			usleep(5000);
			if (write(destfd, buffer, n) != n) {
				perror("cp: write failed");
				retval = (void *)RETURN_FAILURE;
				break;
			}

			if (n < 0) {
				perror("cp: read error");
				retval = (void *)RETURN_FAILURE;
				break;
			}
			memset(buffer, 0x00, sizeof buffer);
		}

		retval = (void *)RETURN_SUCCESS;

		#ifdef DEBUG_COPY_TASK
		printf("cp: tid_%ld completed.\n", crnt_tid);
		#endif

	} while(0);

	args->cperrno = errno;

	if (srcfd >= 0) {
		if (close(srcfd) < 0) {
			perror("cp: close srcfd failed");
		}
	}
	
	if (destfd >= 0) {
		if (close(destfd) < 0) {
			perror("cp: close destfd failed");
		}
	}

	pthread_mutex_unlock (&lock_cp);
	pthread_exit(retval);
}

/* socket copy */
int cp_wrapper(clntdata_t *client_data, char *output, char **argv)
{
	void *tret = NULL;
	int retval = -1;
	struct st_cpargs cp_args = {-1, NULL, NULL};
	pthread_t copy_thread;
#ifdef DEBUG_COPY_TASK
	char **argv_debug = NULL;
#endif


	pthread_mutex_init(&lock_cp, NULL);

	do {
		if ((output == NULL) || (argv == NULL)) {
			printf("cp: invalid arguments !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

#ifdef DEBUG_COPY_TASK
		argv_debug = argv;
		printf("cp_wrapper: fork: args to exec\n");
		while (*argv_debug != NULL) {
			printf("\targv [%s]\n", *argv_debug);
			argv_debug++;
		}
#endif

		memset(output, 0x00, sizeof output);

		cp_args.src_file = *(argv + 1);
		cp_args.dest_file = *(argv + 2);

		if (pthread_create(&copy_thread, NULL, copy_file, (void *)&cp_args) != 0) {
			perror("cp: pthread_create failed");
			retval = RETURN_FAILURE;
			break;
		}

		printf("cp: new thread %ld initiated...\n", copy_thread);
		pthread_join(copy_thread, &tret);

		if (cp_args.cperrno == 0) {
			retval = RETURN_SUCCESS;
		} else {
			retval = RETURN_FAILURE;
			break;
		}
	} while (0);

	/* Send ACK to client */
	if (retval == RETURN_SUCCESS) {
		strcpy(output, "1"); /* return 1 as success */
		retval = RETURN_SUCCESS;
	} else {
		strcpy(output, strerror(cp_args.cperrno)); /* Send error message to client */
		retval = RETURN_FAILURE;
	}
	
	pthread_mutex_destroy(&lock_cp);

	return retval;
}

int share_environ(int socket)
{
	int i = 0;
	int retval = -1;
	char buffer[BUFF_SIZE] = { 0 };
	char *envdata = NULL;

	do {
		printf("Inside %s() Args: socket []\n", __FUNCTION__ );
		if (socket < 0) {
			printf("Share_environ: invalid args recvd !!!");
			retval = RETURN_FAILURE;
			break;
		}
		#if 1
		envdata = calloc(PIPE_BUF, sizeof *envdata);
		if (envdata == NULL) {
			perror("Share_environ: Malloc");
			retval = RETURN_FAILURE;
			break;
		}
		#endif

		i = 0;
		strcpy(envdata, "|");

		while (*(s_env + i ) != NULL) {
			printf("%s [%s]\n", *(s_env + i ), getenv(*(s_env + i )));
			memset(buffer, 0x0, sizeof buffer);
			sprintf(buffer, "%s=%s|",*(s_env + i ), getenv(*(s_env + i )));
			strcat(envdata, buffer);
			i++;
		}

		printf("ENV[%s]\n", envdata);

		if (sendto_client(socket, envdata) == RETURN_FAILURE ) {
			printf("Share_environ: Sendto_Client failed !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		retval = RETURN_SUCCESS;

		#ifdef DEBUG
		//printf("Malloc: Share_environ: ENV Size [%d]\n", (int)strlen( s_env));
		#endif
	} while(0);


	if (envdata != NULL ) {
		free(envdata);
		envdata= NULL;
	}
	return retval;
}

size_t strlen_w(char *str)
{
	if (str == NULL)
		return 0;
	else
		return (strlen(str));
}

char **assign_new_environment(char ***envptr)
{
	int i = 0;
	int count = 0;
	int nsys_env = 0;
	int n_user_env = USER_ENV_MAX;
	char **retval = NULL;

	do {
		if ((environ == NULL)) {
			printf("assign_env: invalid arguments !!!\n");
			retval = NULL;
			break;
		}

		printf("\nInside assign_env\n");

		for(i = 0; (*(environ + i) != NULL); i++ ) {
			#ifdef DEBUG_ASSIGN_ENVIRON
			printf("Env Count [%d] [%d] [%s]\n", i, strlen(*(environ + i)), *(environ + i));
			#endif
			//count++;
			nsys_env++;
		}

		count = nsys_env + n_user_env;
		#ifdef DEBUG_ASSIGN_ENVIRON
		puts("");
		printf("*envptr size i [%d] n_sys_env [%d] n_user_env [%d] count [%d]\n", i, nsys_env, n_user_env, count);
		#endif

/*
		   **argv 
			  |---> argv[0]
			  |---> argv[1]
			  |---> argv[2]
			  |     ---
			  |---> argv[count]
			  |---> argv[count + 1]     = NULL
*/


		*envptr = (char **)calloc((count + 1), sizeof **envptr); /* +1 for NULL */
		if (*envptr == NULL) {
			perror("assign_env: malloc failed");
			retval = NULL;
			break;
		}

		#ifdef DEBUG_ASSIGN_ENVIRON
		printf("assign_env: @init: *envptr [%p]\n", *envptr);
		puts("");
		#endif

		//for(i = 0; (i < count) && (*(environ + i) != NULL); i++ ) 
		for(i = 0; (i < count); i++ ) {
			//printf("**envptr size [%d]\n", (strlen(*(environ + i)))*(sizeof ***envptr));
			*(*envptr + i) = (char *)calloc(NAME_MAX, sizeof (char));

			#if 0
			if (*(*envptr + i) == NULL) {
				perror("assign_env: malloc failed");
				free(*envptr);
				*envptr = NULL;
				retval = NULL;
				break;
			}
			strcpy_w(*(*envptr + i), *(environ + i));
			#ifdef DEBUG_ASSIGN_ENVIRON
			printf("[%d] [%p] [%s]\n", i, *(*envptr + i), *(*envptr + i));
			#endif
			#else

			if (*(*envptr + i) == NULL) {
				perror("assign_env: malloc failed");
				free(*envptr);
				*envptr = NULL;
				retval = NULL;
				break;
			} else if ((*(environ + i) != NULL) && ( i < nsys_env)) {
				strcpy_w(*(*envptr + i), *(environ + i));

				#ifdef DEBUG_ASSIGN_ENVIRON
				printf("Assign [%d] [%p] [%s]\n", i, *(*envptr + i), *(*envptr + i));
			} else {
				printf("Assign [%d] [%p] [%s]\n", i, *(*envptr + i), *(*envptr + i));
				#endif

			}
			#endif
		}

		*(*envptr + (count+1)) = NULL;

		#ifdef DEBUG_ASSIGN_ENVIRON
		puts("");
		for(i = 0; (*(*envptr + i) != NULL); i++ ) {
			printf("Testing [%d] [%p] [%s]\n", i, *(*envptr + i), *(*envptr + i));
		}
		printf("Testing [%d] [%p] [%s]\n", i, *(*envptr + i), *(*envptr + i));
		puts("");
		#endif

		retval = *envptr;
		printf("assign_env: @end: *envptr [%p]\n", *envptr);
	} while (0);

	return retval;
}

int accept_new_client(int serversocket, struct sockaddr **clntaddr, socklen_t addrlen,  clntdata_t **clntinfo)
{
	int retval = -1;
	int clientsocket = -1;
	char *init_path = NULL;

	#ifdef DEBUG_ACCEPT_CLIENT
	printf("Inside %s() Args: serversocket[%d] clntaddr [%p] addrlen[%d]\n", 
			__FUNCTION__, serversocket, *clntaddr, addrlen);
	#endif

	do {
		if ((serversocket < 0) || (clntaddr == NULL) || (addrlen < 0)) {
			printf("accept_new_client: invalid args recvd !!!");
			retval = RETURN_FAILURE;
			break;
		}

		if ((*clntaddr = malloc(addrlen)) == NULL) {
			perror("Malloc: client address");
			retval = RETURN_FAILURE;
			break;
		}

		if ((clientsocket = accept(serversocket, (struct sockaddr *) *clntaddr, &addrlen)) < 0)
		{
			free(clntaddr);
			perror("Could not accept() connection");
			retval = RETURN_FAILURE;
			break;
		}

		if ((*clntinfo = malloc(sizeof(clntdata_t))) == NULL) {
			free(clntaddr);
			perror("Malloc: client info");
			retval = RETURN_FAILURE;
			break;
		}

		if (clientsocket < 0) {
			printf("Accept: Invalid Client Socket [%d] !!!\n", clientsocket);
			retval = RETURN_FAILURE;
			break;
		} else {
			(*clntinfo)->sockfd = clientsocket;
		}

		/* Assign environment for new threads/clients/connection */
		if (assign_new_environment(&((*clntinfo)->envptr)) == NULL ) {
			printf("Accept: assign_env failed !!!\n");
			retval = RETURN_FAILURE;
			break;
		}	

		#ifdef DEBUG_ACCEPT_CLIENT
		printf("Accept: Socket [%d] environ [%p]\n", clientsocket, (*clntinfo)->envptr);
		#endif

		#if 0 /* commented: disabled server environment variable sharing */
		if (share_environ(clientsocket) < 0) {
			free(clntaddr);
			free(clntinfo);
			printf("Accept: Env Share failed !!!");
			retval = RETURN_FAILURE;
			break;
		}
		#else
		/* share home directory of server process to client as pwd at init */
		if ((init_path = getenv("HOME")) != NULL) {
			if (sendto_client(clientsocket, init_path) == RETURN_FAILURE ) {
				printf("Share_environ: Sendto_Client failed !!!\n");
				retval = RETURN_FAILURE;
				break;
			}
		} else {
			free(clntaddr);
			free(clntinfo);
			printf("share environ: failed !!!\n");
			retval = RETURN_FAILURE;
			break;
		}
		#endif

		#ifdef DEBUG_ACCEPT_CLIENT
		printf("Accept: @end clntaddr [%p]; clientsocket[%d]; clntinfo [%p]; clntinfo->sockfd [%d]\n",
				*clntaddr, clientsocket, *clntinfo, (*clntinfo)->sockfd);
		#endif

		retval = RETURN_SUCCESS;
	} while(0);

	return retval;
}

/*
	Decode the formatted data from args(recvd from socket)
		convert into argument verctor

	Useful when need to sent to execvp

	Output: 2D Array of commandline ponters [Heap location]
*/
char **decode_packet(char *packet)
{
	int i = 0;
	int argc = 0;
	char **argv = NULL;
	char *arg_tokn = NULL;
	char **retval = NULL;
	char *saveptr = NULL;
	char buffer[LINE_MAX] = {0};

	do {
		if (packet == NULL) {
			printf("decode: invalid arguments !!!\n");
			retval = NULL; /* Retval */
			break;
		}

		#ifdef DEBUG_PACKET_DECODER
		printf("\ndecode: input [%s]\n", packet);
		#endif

		memset(buffer, 0x00, sizeof buffer);
		strcpy(buffer, packet);

		arg_tokn = strtok_r(buffer, CLI_DELM, &saveptr);
		while (arg_tokn != NULL) {
			argc++;
			arg_tokn = strtok_r(NULL, CLI_DELM, &saveptr);
		}

		#ifdef DEBUG_PACKET_DECODER
		printf("decode: argument count [%d]\n", argc);
		#endif

/*		argv ---> argv[0]
			|---> argv[1]
			|     ---
			|---> argv[argc]
			|---> argv[argc + 1] = NULL
*/
		argv = (char **) calloc((argc + 1), sizeof(char *));
		if (argv == NULL) {
			perror("decode: calloc failed: argv");
			retval = NULL;
			break;
		}

		#ifdef DEBUG_PACKET_DECODER
		printf("decode: alloc: argv [%p]\n", argv);
		#endif

		for (i = 0; i < argc; i++) {
			argv[i] = (char *) calloc(NAME_MAX, sizeof(char));
			if (argv[i] == NULL) {
				perror("decode: calloc failed: argv[x]");
				free(argv);
				argv = retval = NULL;
				break;
			}
			#ifdef DEBUG_PACKET_DECODER
			printf("decode: alloc: argv[%d] [%p] [%s]\n", i,  argv[i], argv[i]);
			#endif

		}

		argv[i] = NULL;
		#ifdef DEBUG_PACKET_DECODER
		printf("decode: alloc: argv[%d] [%p]\n\n", i,  argv[i]);
		#endif

		i = 0;
		saveptr = NULL;
		arg_tokn = strtok_r(packet, CLI_DELM, &saveptr);
		while (arg_tokn != NULL) {
			strcpy_w(argv[i], arg_tokn);
			#ifdef DEBUG_PACKET_DECODER
			printf("decode: alloc: argv[%d] [%p] [%s]\n", i, argv[i], argv[i]);
			#endif
			arg_tokn = strtok_r(NULL, CLI_DELM, &saveptr);
			i++;
		}

		#ifdef DEBUG_PACKET_DECODER
		printf("\ndecode: test: argv [%p]\n", argv);
		for(i = 0; i < argc; i++) {
			printf("decode: test: argv[%d] [%p] [%s]\n", i, argv[i], argv[i]);
		}
		puts("");
		#endif 
	
		retval = argv;
	} while(0);

	return retval;
}

int execute_process(const int socket, char *output ,const char *command)
{
	pid_t pid = -1;
	int status = -1;
	FILE *pfp = NULL;
	char buffer[BUFF_SIZE] = {0};
	char *saveptr = NULL;
	int retval = -1;
	int server_stdin = -1;
	int server_stdout = -1;
	int server_stderr = -1;
	char *input_cmd = (char *)command;
	char *ptr = NULL;
	char **argv = NULL;
	#ifdef DEBUG_EXEC
	char **argv_debug = NULL;
	#endif
	int i = 0;
	printf("Inside %s: Socket [%d] Actual command [%s]\n", __FUNCTION__, socket, command);

	do {

		if ((socket < 0) || (output == NULL) || (command == NULL)) {
			printf("exec: invalid arguments !!!\n");
			retval = FAILURE;
			break;
		}

		memset(buffer, 0x0, sizeof buffer);
		/* checking args for any previous dynamic memory allocations */
		if (argv != NULL) {
			printf("exec: free at init: argv.\n");
			free(argv);
			argv = NULL;
		}

		argv = decode_packet(input_cmd);
		if (argv == NULL) {
			printf("exec: decode failed !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		pid = fork();
		if (pid < 0) {
			printf("exec: fork failed !!!\n");
			retval = RETURN_FAILURE;
			break;
		} else if (pid == 0) {
			#ifdef DEBUG_EXEC
			argv_debug = argv;
			printf("exec: fork: args to exec\n");
			while (*argv_debug != NULL) {
				printf("\targv [%s]\n", *argv_debug);
				argv_debug++;
			}
			#endif

			/* We will revert back the processes standard file if exec failed */
			server_stdout = dup(STDOUT_FILENO);
			server_stderr = dup(STDERR_FILENO);

			/* Mapping server's (child process) stdio to socket */
			dup2(socket, STDOUT_FILENO);
			dup2(socket, STDERR_FILENO);

			//sleep(5);
			if (execvp(argv[0], argv) == -1) {
				printf("exec: execvp failed !!!\n");
				exit(EXIT_FAILURE);
			}

			/* Reverting processes standard files. if exec failed !!! */
			dup2(server_stdout, STDOUT_FILENO);
			dup2(server_stderr, STDERR_FILENO);

			retval = RETURN_FAILURE;
			break;
		} else {
			do {
				#ifdef DEBUG_EXEC
				printf("exec: parent waiting...\n");
				#endif
				waitpid(pid, &status, WUNTRACED);
			} while (!WIFEXITED(status) && !WIFSIGNALED(status));

			#ifdef DEBUG_EXEC
			printf("exec: child process done.\n");
			#endif

			if (argv != NULL) {
				printf("exec: free: argv [%p]\n", argv);
				for (i = 0; argv[i] != NULL; i++) {
					printf("exec: free: argv[%d] [%p] [%s]\n", i, argv[i], argv[i]);
					free(argv[i]);
					(argv)[i] = NULL;
				}
				free(argv);
				argv = NULL;
			}
		}
		retval = SUCCESS;
	} while(0);

	return retval;
}

int handle_client_request( clntdata_t *client_data, char *output, const char *input_cmd) /* input change to const */
{
	char *saveptr = NULL;
	int retval = -1;
	int procno = -1;
	char *cmd = NULL;
	char cmd_buff[LINE_MAX] = {0};
	builtins_t *command;

	strcpy(cmd_buff, input_cmd);

	//printf("Inside %s: input_cmd [%s]\n", __FUNCTION__, input_cmd);
	printf("Input_cmd [%s]\n", input_cmd);

	do {
		if ((output == NULL) || (input_cmd == NULL)) {
			retval = FAILURE;
			break;
		}
		cmd = strtok_r(cmd_buff, ":", &saveptr);
		if (cmd == NULL) {
			printf("Null input: strtok_r @ %s\n", __FUNCTION__);
			retval = RETURN_FAILURE;
			break;
		}

		command = is_builtin_function(cmd);
		if (command != NULL) {
			if (exec_builtins(client_data, output, command, (char *)input_cmd) ==  RETURN_ERROR) {
				printf("exec_builtins: failed\n");
				strcpy(output, "Request Failed !!!\n");
				retval = RETURN_FAILURE;
				break;
			}
			//break;
		} else {
			printf("handle_client_request: no builtin_functions \n");
			execute_process(client_data->sockfd, output, input_cmd);
		}

		printf("____STOP____\n");

		retval = SUCCESS;
	} while (0);

	return retval;
}

void *read_client_request(void *args)
{
	clntdata_t *clntinfo;
	int nbytes, i;
	char buffer[PIPE_BUF] = {0};
	char output[PIPE_BUF] = {0};
	clntinfo = (clntdata_t *) args;

	#ifdef DEBUG_READ_REQUEST
	printf("%s()\n", __FUNCTION__);
	#endif

	pthread_detach(pthread_self());

	/* ADDED: Protect access to numConnections with the lock */
	#ifdef MUTEX
	pthread_mutex_lock (&lock_client_count);
	#endif

	/* The following two loops will result in numConnections
	   being ultimately incremented by just one, but we do
	   this with these loops to increase the chances of a
	   race condition happening */
	for(i = 0; i < MAX_THREADS; i++) {
		numConnections++;
	}
	for(i = 0; i < MAX_THREADS - 1; i++) {
		numConnections--;
	}

	fprintf(stderr, "+ Number of connections is %d\n", numConnections);

	/* ADDED: Unlock the lock when we're done with it. */
	#ifdef MUTEX
	pthread_mutex_unlock (&lock_client_count);
	#endif

	while(TRUE)
	{
		memset(buffer, 0x0, sizeof buffer);
		nbytes = recv(clntinfo->sockfd, buffer, sizeof(buffer), 0);
		if (nbytes == 0) {
			printf("NULL Input.");
			break;
		} else if (nbytes == -1) {
			perror("Socket recv() failed");
			//close(socket);
			close(clntinfo->sockfd);
			pthread_exit(NULL);
			continue;
		}

		buffer[nbytes] = '\0'; //set the string terminating NULL byte at end of the data read

		printf("\n======================================================\n");

		/* Serving client needs */
		#ifdef DEBUG_READ_REQUEST
		printf("Recv tid [%d] nbytes [%d] buffer [%s] \n",(int)pthread_self(), nbytes, buffer);
		#endif

		memset(output, 0x0, sizeof output);
		if (handle_client_request(clntinfo, output, buffer) < 0) {
			printf("Error: handle_client_request\n");
			//send(socket, "Query failed !!!", strlen(output) , 0 );  
			//continue;
		}

		if (sendto_client(clntinfo->sockfd, output ) == RETURN_FAILURE ) {
			printf("Error: send_client\n");
		}

		printf("======================================================\n");
	}


	/* ADDED: Same as the above loops, but decrementing numConnections by one */
	#ifdef MUTEX
	pthread_mutex_lock (&lock_client_count);
	#endif
	for(i = 0; i < MAX_THREADS; i++) {
		numConnections--;
	}
	for(i = 0; i < MAX_THREADS - 1; i++) {
		numConnections++;
	}

	fprintf(stderr, "- Number of connections is %d\n", numConnections);
	#ifdef MUTEX
	pthread_mutex_unlock (&lock_client_count);
	#endif

	close(clntinfo->sockfd);
	pthread_exit(NULL);

	return;
}

int init_server_daemon()
{
	int retval = -1;
	int serverSocket = -1;

	pthread_t worker_thread;
	struct addrinfo hints, *res, *p;
	struct sockaddr_storage *clientAddr = NULL;
	socklen_t sinSize = sizeof(struct sockaddr_storage);
	clntdata_t *clntinfo = NULL;
	int yes = 1;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	#ifdef DEBUG_DAEMON
	printf("%s()\n", __FUNCTION__);
	#endif
	do {

		if (getaddrinfo(NULL, s_port, &hints, &res) != 0) {
			perror("getaddrinfo() failed");
			//pthread_exit(NULL);
			retval = RETURN_FAILURE;
			break;
		}

		for(p = res;p != NULL; p = p->ai_next) {
			if ((serverSocket = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
				perror("Could not open socket");
				continue;
			}

			if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
				perror("Socket setsockopt() failed");
				close(serverSocket);
				continue;
			}

			if (bind(serverSocket, p->ai_addr, p->ai_addrlen) == -1) {
				perror("Socket bind() failed");
				close(serverSocket);
				continue;
			}

			if (listen(serverSocket, 5) == -1) {
				perror("Socket listen() failed");
				close(serverSocket);
				continue;
			}

			break;
		}

		freeaddrinfo(res);

		if (p == NULL) {
			fprintf(stderr, "Could not find a socket to bind to.\n");
			retval = RETURN_FAILURE;
			break;

			//pthread_exit(NULL);
		}


		/* We are not locking client. Locking the mechanism of no-of client connection count */
		#ifdef MUTEX
		pthread_mutex_init(&lock_client_count, NULL);
		#endif

		while (TRUE) {
			retval = accept_new_client(serverSocket, (struct sockaddr **) &clientAddr, sinSize, &clntinfo);
			if (retval == RETURN_FAILURE) {
				printf("Accept failed !!!\n");
				if ((clntinfo->sockfd) > 0 ) {
					printf("Terminating connection...\n");
					close(clntinfo->sockfd);
				}
				continue;
			}

			#ifdef DEBUG
			printf("OUT: clntaddr [%p]; clntinfo [%p]; clntinfo->sockfd [%d]\n",
				clientAddr, clntinfo, clntinfo->sockfd);
			#endif

			if (pthread_create(&worker_thread, NULL, read_client_request, (void *)clntinfo) != 0) {
				perror("Could not create a worker thread");

				if (clientAddr != NULL) {
					free(clientAddr);
					clientAddr = NULL;
				}

				if (clntinfo != NULL) {
					free(clntinfo);
					clntinfo = NULL;
				}

				close(clntinfo->sockfd);
				close(serverSocket);

				perror("daemon: pthread failed");
				retval = RETURN_FAILURE;
				continue;
			}
		}

		#ifdef MUTEX
		pthread_mutex_destroy(&lock_client_count);
		#endif 

		retval = RETURN_SUCCESS;
	} while(0);

	if (clientAddr != NULL) {
		free(clientAddr);
		clientAddr = NULL;
	}

	if (clntinfo != NULL) {
		free(clntinfo);
		clntinfo = NULL;
	}

	return 0;
}

void help_menu()
{
	printf("USAGE: server -p PORT\n");
	return;
}

void sigpipe_handler(int signum)
{
	printf("SIGPIPE received !!! Exiting\n");

	return;
}

int main(int argc, char *argv[])
{
	int retval = -1;
	int opt = -1; /* Used by getopt */
	char dir[PATH_MAX] = {0};
	char **g_env = environ;

	//printf("GLOBAL ENV ADDR [%p]\n", g_env);

	#if 0
    sigset_t new;
    sigemptyset (&new);
    sigaddset(&new, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &new, NULL) != 0)
    {
        perror("Unable to mask SIGPIPE");
        exit(-1);
    }
	#endif

	signal(SIGPIPE, sigpipe_handler);

	sprintf(dir, "%s", getenv("HOME"));
	if (chdir(dir) != 0) {
		printf("Main: chdir failed !!!\n");
		exit(1);
	}

	if (setenv("PWD", dir, 1) != 0 ) {
		perror("Main: setenv failed !!!");
		exit(1);
	}

	do {
		#if 0
		if (argc < 2) {
			help_menu();
			retval = EXIT_FAILURE;
			break;
		}

		/* Use getopt() to fetch the server port no from cli */
		while ((opt = getopt(argc, argv, "p:")) != -1) {
			switch (opt) {
				case 'p':
					s_port = strdup(optarg);
					if (s_port != NULL) {
						portno = atoi(s_port);
						//free(s_port); /* s_port points heap memory malloced in strdup() */
					}
					break;

				default:
					printf("Invalid Port !!!\n");
					break;
			}
		}

		if (s_port == NULL) {
			help_menu();
			retval = EXIT_FAILURE;
			break;
		}
		#else
		strcpy(s_port, "2020");
		#endif

		printf("Service started at [%s] port...\n", s_port);

		if (init_server_daemon() < 0) {
				printf("Failed to init server daemon !!!\n");
			retval = EXIT_FAILURE;
			break;
		}
		retval = EXIT_SUCCESS;
	} while(0);

	free(s_port); /* s_port points heap memory malloced in strdup() */
	return retval;
}

char *get_thread_env(char **environ, const char *name)
{
	int offset = 0;
	char *result = NULL;

	if ((environ == NULL) || (name == NULL)) {
		printf("get_thread_env: invalid arguments !!!\n");
		return NULL;
	}

	//rwlock_rdlock(&__environ_lock);
	result = findenv(environ, name, &offset);
	//rwlock_unlock(&__environ_lock);

	#ifdef DEBUG_GETENV
	printf("get_thread_env: result: [%s] name [%s]\n", result, name);
	#endif

	return result;
}

/*
	Change working directory:

	Following pathresolutions was handled.
	1. Resolve /home/user/file/ >>> /home/user/file

    2. cd ~ >>> Resolve to Home directory
       cd - >>> Resolve OLDPWD

	3. cd    >>> Resolve to Home directory
       cd .  >>> Resolve to current directory 
       cd .. >>> Resolve to last directory 

	4. cd dirname  >>> Resolve to /actual_path_of_dir
	   ls filename >>> Resolve to /actual_path_of_file

	Args: int flag - May use in future
          char *tmpdir - Recv raw dir name

	Input: Directory name.
	Return: Stripped resolved directory
*/
int cd_wrapper(clntdata_t *client_data, char *output_msgptr, char **arg)
{
	int retval = -1;
	int socket = -1;
	char *last = NULL;
	bool goto_root = FALSE;
	bool goto_home = FALSE;
	bool goto_cwd = FALSE;
	bool goto_oldpwd = FALSE;
	bool goto_stepback = FALSE;
	static char **environ = NULL;
	static char abspath[PATH_MAX] = {0};
	static char *option[LINE_MAX] = {0};
	static char oldpwd[PATH_MAX] = {0};
	static char    pwd[PATH_MAX] = {0};
	static char output[PATH_MAX] = {0};
	static char dirname[PATH_MAX] = {0};
	static char dir_path[PATH_MAX] = {0};
	static char data_out[PATH_MAX] = {0};

	environ = client_data->envptr;

	if (get_thread_env(environ, "OLDPWD") != NULL) 
		printf("getenv: OLDPWD = %s \n", get_thread_env(environ, "OLDPWD"));

	do {

		printf("\nInside cd_wrapper\n");

		if ((client_data == NULL) || (output == NULL) || (arg == NULL)) {
			printf("cd_wrapper: invalid arguments\n");
			retval = RETURN_FAILURE;
			break;
		}

		#ifdef DEBUG_GETENV
		#if 1
		printf("TESTING PARALLEL GETENV OUTPUT... \n[%s]\n[%s]\n[%s]\n[%s]\n[%s]\n\n",  
									get_thread_env(environ, "HOME"), 
									get_thread_env(environ, "SHELL"),
									get_thread_env(environ, "USER"),
									get_thread_env(environ, "XDG_GREETER_DATA_DIR"),
									get_thread_env(environ, "XAUTHORITY"));
		#endif
		#endif

		if (get_thread_env(environ, "OLDPWD") != NULL) {
			memset(oldpwd, 0x00, sizeof oldpwd);
			strcpy(oldpwd, get_thread_env(environ, "OLDPWD"));
			printf("AT CD INIT oldpwd [%s]\n", oldpwd);
		}

		memset(pwd, 0x00, sizeof pwd);
		strcpy(pwd, get_thread_env(environ, "PWD"));

		memset(dirname, 0x00, sizeof dirname);
		strcpy_w(dirname, (*(arg + 1)));
		socket = client_data->sockfd;

		printf("cd @init: socket [%d] environ [%p] pwd[%s] oldpwd[%s] dirname[%s]\n", socket, environ, pwd, oldpwd, dirname); 

		if ((strlen(dirname) == 0) || (strcmp(dirname, "~") == 0)) {
			goto_home = TRUE;
		} else if (strcmp(dirname, "-") == 0 ) {
			goto_oldpwd = TRUE;
		} else if ((strcmp(dirname, "..") == 0 ) || (strncmp(dirname, "../", 3) == 0)) { /* if  cd .. */ /* One step back */
			goto_stepback = TRUE;
		} else if ((strcmp(dirname, ".") == 0 ) || (strncmp(dirname, "./", 2) == 0 )) { /* if cd . */ /* Stay on current directory */
			goto_cwd = TRUE;
		} else if ((strcmp(dirname, "/") == 0 ) || (strncmp(dirname, "//", 2) == 0 )) { /* if cd / */
			goto_root = TRUE;
		}

		/* PHASE I */ /* Getting respected pathnames */
		memset(output, 0x00, sizeof output);
		if (goto_oldpwd == TRUE) {
			if (get_thread_env(environ, "OLDPWD") != NULL) {
				#ifdef DEBUG_CHDIR
				printf("goto oldpwd...\n");
				#endif
				strcpy(output, oldpwd);
			} else {
				printf("shell: cd: OLDPWD not set\n");
				strcpy(output_msgptr, "OLDPWD not set");
				retval = RETURN_FAILURE;
				break;
			}
		} else if (goto_home == TRUE) {
			#ifdef DEBUG_CHDIR
			printf("goto home directory...\n");
			#endif
			//set_thread_env(&environ, "OLDPWD", get_thread_env(environ, "PWD"));
			strcpy(output, get_thread_env(environ, "HOME"));
		} else if (goto_stepback == TRUE) {
			//set_thread_env(&environ, "OLDPWD", get_thread_env(environ, "PWD"));
			strcpy(output, get_thread_env(environ, "PWD"));
			#ifdef DEBUG_CHDIR
			printf("step back: pwd: %s\n", output);
			#endif

			last = output;
			while(*last != '\0') {
				*(last++);
			}

			while(*last != '/') {
				last--;
			}

			if ((output == last) && (output[0] == '/') && (*last == '/')) { /* if cd / then dont strip slash */
				strcpy(output, "/");
			} else {
				*(last) = '\0';
			}

			#ifdef DEBUG_CHDIR
			printf("step back: end: %s\n", output);
			#endif
		} else if (goto_cwd == TRUE) {
			#ifdef DEBUG_CHDIR
			printf("Hold on current directory...\n");
			#endif
			//set_thread_env(&environ, "OLDPWD", get_thread_env(environ, "PWD"));
			strcpy(output, get_thread_env(environ, "PWD"));
		} else {
			/* else goto specified directory */
			//set_thread_env(&environ, "OLDPWD", get_thread_env(environ, "PWD"));
			strcpy(output, dirname);
			#ifdef DEBUG_CHDIR
			printf("cd_wrapper: output [%s] oldpwd[%s]\n", output, oldpwd);
			#endif
		}
		/* End of PHASE I */

		/* PHASE II */ /* Stripping post slash, resolve fullpath & resolve root directory */
		/* if [cd user/ ] to [cd /home/user ] */
		if ((*output + 0) != '/') {
			memset(abspath, 0x00, sizeof abspath);
			sprintf(abspath, "%s/%s", get_thread_env(environ, "PWD"), output);
			memset(output, 0x00, sizeof output);
			strcpy(output, abspath);
			#ifdef DEBUG_CHDIR
			printf("cd_wrapper: path resolved into [%s]\n", output);
			#endif
		}

		/* if [ cd / ] then simply return */
		if (strcmp(output, "/") == 0) {
			#ifdef DEBUG_CHDIR
			printf("Input is root dir[%s] retval[%s]\n", dirname, output);
			#endif
			retval = RETURN_SUCCESS;
			break;
		}

		/* strip slash at endof path i.e., [cd /home/user/ >>> cd /home/user]*/
		if (( output[strlen(output) - 1] == '/' )) {
			#ifdef DEBUG_CHDIR
			printf("Stripping directory...\n");
			#endif
			output[strlen(output) - 1] = '\0';
		}
		/* End of PHASE II */

		if (access(output, F_OK | X_OK) != 0) {
			sprintf(output_msgptr, "%s", strerror(errno));
			printf("cd_wrapper: access failed: %s\n", output_msgptr);
			retval = RETURN_FAILURE;
			break;
		} else {
			/* sending directory to change over socket     */
			/* This directory will update in client as cwd */
			/* Data is formatted as [1:/dirname]           */
			memset(data_out, 0x00, sizeof data_out);
			sprintf(data_out, "1:%s", output);
			if (send(socket, data_out, strlen(data_out), 0 ) < 0 ) {
				perror("Sendto_Client: send() failed ");
				retval = RETURN_FAILURE;
				break;
			}

			/* Change thread working directory */
			if (chdir_td(environ, output) != 0) {
				printf("cd_wrapper: chdir failed !!!\n");
				retval = RETURN_FAILURE;
				break;
			}

			if (set_thread_env(&environ, "OLDPWD", pwd) != 0) {
				printf("cd_wrapper: set_thread_env failed !!!\n");
				retval = RETURN_FAILURE;
				break;
			}

			retval = RETURN_SUCCESS;
		}

	} while (0);

	printf("cd @end: home [%s] pwd[%s] oldpwd[%s]\n",
								get_thread_env(environ, "HOME"),
								get_thread_env(environ, "PWD"),
								get_thread_env(environ, "OLDPWD"));
	printf("__END_OF_CD_WRAPPER__ [%s] \n\n", output);

	return retval;
}


/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
int set_thread_env(char ***environ, const char *name, char *value)
{
	size_t new_size = 0;
	int retval = -1;
	int i = 0;
	char *destptr = NULL;
	bool is_exist = FALSE;

	do {
		if ((*environ == NULL) || (name == NULL) || (value == NULL)) {
			printf("set_thread_env: invalid arguments !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		#ifdef DEBUG_SETENV
		printf("\nset_thread_env: name [%s] value [%s]\n", name, value);
		#endif

		if ((strlen(name) == 0) || (strlen(value) == 0)) {
			printf("set_thread_env: invalid arguments !!!\n");
			retval = RETURN_FAILURE;
			break;
		}

		for(i = 0; *(*environ + i) != NULL; i++) {
			if (strstr(*(*environ + i), name) != NULL) {
				#ifdef DEBUG_SETENV
				printf("set_env: ALREADY EXIST [%p] name [%s] oldval [%s] \n", *(*environ + i), name, *(*environ + i));
				#endif
				destptr = *(*environ + i);
				is_exist = TRUE;
				break;
			}
		}

		/*
			If env_variable "name" is not already exist
				then, alloc new memory spcace for variable "name" in available user space in environment pointer
				and, assign "value" to the env_variable "name"
			else
				update new "value" to the existing env_variable "name"
		*/
		if (is_exist != TRUE) {
			#ifdef DEBUG_SETENV
			printf("set_env: [%s] NOT EXIST\n", name);
			#endif
			/* Traverse to empty region to set new environ value */
			i = 0;
			while((*(*environ + i) != NULL) && (*(*(*environ + i)) != '\0')) {
				#ifdef DEBUG_SETENV
				printf("Search [%d] [%p] [%d] [%s]\n", i, *(*environ + i), strlen(*(*environ + i)), *(*environ + i));
				#endif
				i++;
			}

			#ifdef DEBUG_SETENV
			if (*(*environ + i) != NULL) {
				printf("Search [%d] [%p] [%d] [%s]\n", i, *(*environ + i), strlen(*(*environ + i)), *(*environ + i));
			}
			#endif

			destptr = *(*environ + i);
		}

		if (destptr != NULL) {
			new_size = (strlen(name) + strlen(value) + 2); /* { +1 for '=' } { +1 for '\0' } */
			if ((destptr = (char *)realloc(destptr, new_size)) == NULL ) {
				perror("set_env: realloc failed");
				retval = RETURN_FAILURE;
				break;
			}

			if (sprintf(destptr, "%s=%s", name, value) > 0 ) {
				#ifdef DEBUG_SETENV
				printf("set_env: updated [%p] [%s]\n", destptr, destptr);
				#endif
				printf("set_env: updated [%p] [%s]\n", destptr, destptr);
				retval = RETURN_SUCCESS;
				break;
			} else {
				printf("set_env: env value update error !!!\n");
				retval = RETURN_FAILURE;
				break;
			}

		} else {
			printf("set_env: failed: ENV BUFFER FULL: \n");
			retval = RETURN_FAILURE;
			break;
		}
	} while (0);

#ifdef DEBUG_SETENV
	#if 1
	puts("");
	for(i = 0; (*(*environ + i) != NULL); i++ ) {
		printf("SetEnv Test [%d] [%p] [%s]\n", i, *(*environ + i), *(*environ + i));
	}
	printf("SetEnv Test [%d] [%p] [%s]\n", i, *(*environ + i), *(*environ + i));
	puts("");
	#endif
#endif

	return retval;
}


/* EOF */
