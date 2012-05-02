#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/stat.h>

struct syscall {
	void *packet;
	int length;
};

void syscall_proxy(int sockfd);
unsigned long get_remote_sp(int sockfd);
int send_syscall(int sockfd, struct syscall* sysc, int will_return);

struct syscall* build_exit(unsigned long remote_sp, int code);
struct syscall* build_write(unsigned long remote_sp, int fd, char *msg, int bytes);
struct syscall* build_open(unsigned long remote_sp, char *path, int flags);
struct syscall* build_close(unsigned long remote_sp, int fd);
struct syscall* build_unlink(unsigned long remote_sp, char *path);
struct syscall* build_chmod(unsigned long remote_sp, char* path, mode_t mode);
struct syscall* build_setid(unsigned long remote_sp, int id_type, int newid);
struct syscall* build_getid(unsigned long remote_sp, int id_type);
struct syscall* build_umask(unsigned long remote_sp, mode_t mask);
struct syscall* build_mkdir(unsigned long remote_sp, char *path, mode_t mode);
struct syscall* build_rmdir(unsigned long remote_sp, char *path);

int main(int argc, char *argv[]) {
	int sockfd;
	struct hostent *he;
	struct sockaddr_in their_addr;

	if (argc < 3) {
		printf("usage: hostname port\n");
		exit(1);
	}

	if ((he=gethostbyname(argv[1])) == NULL) {
		perror("gethostbyname");
		exit(1);
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	their_addr.sin_family = AF_INET;
	their_addr.sin_port = htons(atoi(argv[2]));
	their_addr.sin_addr = *((struct in_addr *)he->h_addr);
	memset(&(their_addr.sin_zero), '\0', 8);

	if (connect(sockfd, (struct sockaddr *)&their_addr,
				sizeof(struct sockaddr)) == -1) {
		perror("connect");
		exit(1);
	}

	syscall_proxy(sockfd);

	exit(0);
}

void syscall_proxy(int sockfd) {
	unsigned long remote_sp=0;
	int retval = 0, myfd;
	struct syscall *sysc;

	remote_sp = get_remote_sp(sockfd);
	printf("Got remote stack pointer: 0x%.4lx\n", remote_sp);

	sysc = build_getid(remote_sp, 0);
	retval = send_syscall(sockfd, sysc, 1);
	printf("Got return value of: %d from getid(0)\n", retval);

	sysc = build_umask(remote_sp, 022);
	retval = send_syscall(sockfd, sysc, 1);
	printf("Got return value of: %d from umask(022)\n", retval);
	
	sysc = build_mkdir(remote_sp, "/tmp/syscall", 00700);
	retval = send_syscall(sockfd, sysc, 1);
	printf("Got return value of: %d from mkdir(%s, %o)\n", retval, 
		   "/tmp/syscall", 00700);

	sysc = build_open(remote_sp, "/tmp/syscall/passwd", 
					  O_WRONLY|O_CREAT|O_APPEND);
	retval = send_syscall(sockfd, sysc, 1);
	printf("Got return value of: %d from open(\"/tmp/syscall/passwd\")\n", 
		   retval);

	myfd = retval;

	sysc = build_write(remote_sp, myfd, "root:*:0:0:Charlie &:/root:/bin/csh", 
					   35);
	retval = send_syscall(sockfd, sysc, 1);
	printf("Got return value of: %d from write(%d, ...)\n", retval, myfd);

	sysc = build_close(remote_sp, myfd);
	retval = send_syscall(sockfd, sysc, 1);
	printf("Got return value of: %d from close(%d)\n", retval, myfd);

	sysc = build_chmod(remote_sp, "/tmp/syscall/passwd", 0644);
	retval = send_syscall(sockfd, sysc, 1);
	printf("Got return value of: %d from chmod(%s,%o)\n", retval, 
		   "/tmp/syscall/passwd", 0644);

	sysc = build_unlink(remote_sp, "/tmp/syscall/passwd");
	retval = send_syscall(sockfd, sysc, 1);
	printf("Got return value of: %d from unlink(%s)\n", retval, 
		   "/tmp/syscall/passwd");

	sysc = build_rmdir(remote_sp, "/tmp/syscall");
	retval = send_syscall(sockfd, sysc, 1);
	printf("Got return value of: %d from rmdir(%s)\n", retval, "/tmp/syscall");

	sysc = build_exit(remote_sp, 5);
	retval = send_syscall(sockfd, sysc, 0);
	printf("Sent exit() syscall!\n");
}

unsigned long get_remote_sp(int sockfd) {
	int datalen = 0;
	unsigned long remote_sp;
	unsigned char retbuf[8] = {0};

	while(datalen < 8)
		datalen += recvfrom(sockfd, (&retbuf)+datalen, 8-datalen, 0, 0, 0);
	
	remote_sp = retbuf[0] | retbuf[1]<<8 | retbuf[2]<<16 | retbuf[3]<<24;
	if (remote_sp == 4) {
		remote_sp = retbuf[4] | retbuf[5]<<8 | retbuf[6]<<16 | retbuf[7]<<24;
	}
	return remote_sp;
}

int send_syscall(int sockfd, struct syscall* sysc, int will_return) {
	int retval = 0, datalen = 0, newdatalen = 0;
	unsigned char *retbuf;

	send(sockfd, sysc->packet, sysc->length, 0);
	free(sysc->packet);
	free(sysc);

	if (will_return) {
		retbuf = (unsigned char*)malloc(4);
		while(datalen < 4) {
			datalen += recvfrom(sockfd, (retbuf)+datalen, 4-datalen, 0, 0, 0);
			usleep(10); // to prevent CPU burn on blocking
		}

		newdatalen = retbuf[0] | retbuf[1]<<8 | retbuf[2]<<16 | retbuf[3]<<24;

		free(retbuf);
		retbuf = (unsigned char*)malloc(newdatalen);
		memset(retbuf, 0, newdatalen);

		datalen = 0;
		while(datalen < newdatalen) {
			datalen += recvfrom(sockfd, (retbuf)+datalen, newdatalen-datalen,
								0, 0, 0);
			usleep(10);
		}

		retval = retbuf[0] | retbuf[1]<<8 | retbuf[2]<<16 | retbuf[3]<<24;
		free(retbuf);
	}

	return retval;
}

// SYS_exit: 1
struct syscall* build_exit(unsigned long remote_sp, int code) {
	typedef struct {
		unsigned int length;
		unsigned int syscall_no;
		unsigned int null;
		unsigned int code;
	} __attribute__((packed)) exit_struct;

	struct syscall *sysc = calloc(1, sizeof(struct syscall));
	exit_struct *es = calloc(1, sizeof(exit_struct));

	memset(es, 0, sizeof(exit_struct));
	es->length = sizeof(exit_struct) - 4;
	es->code = code;
	es->syscall_no = SYS_exit;
	
	sysc->packet = es;
	sysc->length = sizeof(exit_struct);

	return sysc;
}

// SYS_write: 4
struct syscall* build_write(unsigned long remote_sp, int fd, 
							char *msg, int bytes) {
	typedef struct {
		unsigned int length;
		unsigned int syscall_no;
		unsigned int null;
		unsigned int fd;
		unsigned int msgaddr;
		unsigned int bytes;
	} __attribute__((packed)) write_struct;

	struct syscall *sysc = calloc(1, sizeof(struct syscall));
	write_struct *ws = calloc(1, sizeof(write_struct));

	int paddedmsglen, packetlen;
	char *packet;

	paddedmsglen = strlen(msg) + 1;
	if (paddedmsglen % 4)
		paddedmsglen += 4 - (paddedmsglen % 4);

	packetlen = sizeof(write_struct) + paddedmsglen;

	memset(ws, 0, sizeof(write_struct));
	ws->length = packetlen - 4;
	ws->syscall_no = SYS_write;
	ws->fd = fd;
	ws->msgaddr = remote_sp - (4 + paddedmsglen);
	ws->bytes = bytes;

	if ((packet = malloc(packetlen))) {

		memset(packet, 0, packetlen);
		memcpy(packet, (char*)ws, sizeof(write_struct));
		strncpy(packet + sizeof(write_struct), msg, strlen(msg));

 		sysc->length = packetlen;
 		sysc->packet = packet;

 		return sysc;

	}
	return 0;
}

// SYS_open: 5
struct syscall* build_open(unsigned long remote_sp, char *path, int flags){
	
	typedef struct {
		unsigned int length;
		unsigned int syscall_no;
		unsigned int null;
		unsigned int pathaddr;
		unsigned int flags;
	} __attribute__((packed)) open_struct;

	struct syscall *sysc = calloc(1, sizeof(struct syscall));
	open_struct *os = calloc(1, sizeof(open_struct));

	int packetlen, paddedpathlen;
	char *packet;

	paddedpathlen = strlen(path) + 1;
	if (paddedpathlen % 4)
		paddedpathlen += 4 - (paddedpathlen % 4);

	packetlen = sizeof(open_struct) + paddedpathlen;

	memset(os, 0, sizeof(open_struct));
	os->length = packetlen - 4;
	os->syscall_no = SYS_open;
	os->pathaddr = remote_sp - (4 + paddedpathlen);
	os->flags = flags;

	if ((packet = malloc(packetlen))) {

		memset(packet, 0, packetlen);
		memcpy(packet, (char*)os, sizeof(open_struct));
		strncpy(packet + sizeof(open_struct), path, strlen(path));

 		sysc->length = packetlen;
 		sysc->packet = packet;

 		return sysc;

	}
	return 0;
}


// SYS_close: 6
struct syscall* build_close(unsigned long remote_sp, int fd) {
	typedef struct {
		unsigned int length;
		unsigned int syscall_no;
		unsigned int null;
		unsigned int fd;
	} __attribute__((packed)) close_struct;

	struct syscall *sysc = calloc(1, sizeof(struct syscall));
	close_struct *cs = calloc(1, sizeof(close_struct));

	memset(cs, 0, sizeof(close_struct));
	cs->length = sizeof(close_struct) - 4;
	cs->syscall_no = SYS_close;
	cs->fd = fd;
	
	sysc->packet = cs;
	sysc->length = sizeof(close_struct);

	return sysc;
}

// SYS_unlink: 10
struct syscall* build_unlink(unsigned long remote_sp, char *path) {
	typedef struct {
		unsigned int length;
		unsigned int syscall_no;
		unsigned int null;
		unsigned int pathaddr;
	} __attribute__((packed)) unlink_struct;

	struct syscall *sysc = calloc(1, sizeof(struct syscall));
	unlink_struct *us = calloc(1, sizeof(unlink_struct));

	int packetlen, paddedpathlen;
	char *packet;

	paddedpathlen = strlen(path) + 1;
	if (paddedpathlen % 4)
		paddedpathlen += 4 - (paddedpathlen % 4);
	
	packetlen = sizeof(unlink_struct) + paddedpathlen;

	memset(us, 0, sizeof(unlink_struct));
	us->length = packetlen - 4;
	us->syscall_no = SYS_unlink;
	us->pathaddr = remote_sp - (4 + paddedpathlen);

	if ((packet = malloc(packetlen))) {

		memset(packet, 0, packetlen);
		memcpy(packet, (char*)us, sizeof(unlink_struct));
		strncpy(packet + sizeof(unlink_struct), path, strlen(path));

 		sysc->length = packetlen;
 		sysc->packet = packet;
		
 		return sysc;

	}
	return 0;
}

// SYS_chmod 15
struct syscall* build_chmod(unsigned long remote_sp, char* path, mode_t mode) {
	typedef struct {
		unsigned int length;
		unsigned int syscall_no;
		unsigned int null;
		unsigned int pathaddr;
		mode_t mode;
	} __attribute__((packed)) chmod_struct;

	struct syscall *sysc = calloc(1, sizeof(struct syscall));
	chmod_struct *chmds = calloc(1, sizeof(chmod_struct));

	int packetlen, paddedpathlen;
	char *packet;

	paddedpathlen = strlen(path) + 1;
	if (paddedpathlen % 4)
		paddedpathlen += 4 - (paddedpathlen % 4);
	
	packetlen = sizeof(chmod_struct) + paddedpathlen;

	memset(chmds, 0, sizeof(chmod_struct));
	chmds->length = packetlen - 4;
	chmds->syscall_no = SYS_chmod;
	chmds->pathaddr = remote_sp - (4 + paddedpathlen);
	chmds->mode = mode;

	if ((packet = malloc(packetlen))) {
		
		memset(packet, 0, packetlen);
		memcpy(packet, (char*)chmds, sizeof(chmod_struct));
		strncpy(packet + sizeof(chmod_struct), path, strlen(path));

 		sysc->length = packetlen;
 		sysc->packet = packet;
		
 		return sysc;

	}
	return 0;
}

// SYS_setuid: 23, SYS_seteuid: 183
struct syscall* build_setid(unsigned long remote_sp, int id_type, int newid) {
	typedef struct {
		unsigned int length;
		unsigned int syscall_no;
		unsigned int null;
		unsigned int newid;
	} __attribute__((packed)) setid_struct;

	struct syscall *sysc = calloc(1, sizeof(struct syscall));
	setid_struct *sids = calloc(1, sizeof(setid_struct));

	memset(sids, 0, sizeof(setid_struct));
	sids->length = sizeof(setid_struct) - 4;
	sids->syscall_no = id_type ? SYS_seteuid : SYS_setuid;
	sids->newid = newid;

	sysc->packet = sids;
	sysc->length = sizeof(setid_struct);
	
	return sysc;
}

// SYS_getuid: 24, SYS_geteuid: 25
struct syscall* build_getid(unsigned long remote_sp, int id_type) {
	typedef struct {
		unsigned int length;
		unsigned int syscall_no;
		unsigned null;
	} __attribute__((packed)) getid_struct;
	
	struct syscall *sysc = calloc(1, sizeof(struct syscall));
	getid_struct *gids = calloc(1, sizeof(getid_struct));

	memset(gids, 0, sizeof(getid_struct));
	gids->length = sizeof(getid_struct) - 4;
	gids->syscall_no = id_type ? SYS_geteuid : SYS_getuid;

	sysc->packet = gids;
	sysc->length = sizeof(getid_struct);

	return sysc;
}

// SYS_close: 60
struct syscall* build_umask(unsigned long remote_sp, mode_t mask) {
	typedef struct {
		unsigned int length;
		unsigned int syscall_no;
		unsigned int null;
		mode_t mask;
	} __attribute__((packed)) umask_struct;

	struct syscall *sysc = calloc(1, sizeof(struct syscall));
	umask_struct *us = calloc(1, sizeof(umask_struct));

	memset(us, 0, sizeof(umask_struct));
	us->length = sizeof(umask_struct) - 4;
	us->syscall_no = SYS_umask;
	us->mask = mask;

	sysc->packet = us;
	sysc->length = sizeof(umask_struct);

	return sysc;
}

// SYS_mkdir: 136
struct syscall* build_mkdir(unsigned long remote_sp, char *path, mode_t mode) {
	typedef struct {
		unsigned int length;
		unsigned int syscall_no;
		unsigned int null;
		unsigned int pathaddr;
		mode_t mode;
	} __attribute__((packed)) mkdir_struct;

	struct syscall *sysc = calloc(1, sizeof(struct syscall));
	mkdir_struct *mkds = calloc(1, sizeof(mkdir_struct));

	int packetlen, paddedpathlen;
	char *packet;

	paddedpathlen = strlen(path) + 1;
	if (paddedpathlen % 4)
		paddedpathlen += 4 - (paddedpathlen % 4);
	
	packetlen = sizeof(mkdir_struct) + paddedpathlen;

	memset(mkds, 0, sizeof(mkdir_struct));
	mkds->length = packetlen - 4;
	mkds->syscall_no = SYS_mkdir;
	mkds->pathaddr = remote_sp - (4 + paddedpathlen);
	mkds->mode = mode;

	if ((packet = malloc(packetlen))) {
		
		memset(packet, 0, packetlen);
		memcpy(packet, (char*)mkds, sizeof(mkdir_struct));
		strncpy(packet + sizeof(mkdir_struct), path, strlen(path));

 		sysc->length = packetlen;
 		sysc->packet = packet;
		
 		return sysc;

	}
	return 0;
}

// SYS_rmdir: 137
struct syscall* build_rmdir(unsigned long remote_sp, char *path) {
	typedef struct {
		unsigned int length;
		unsigned int syscall_no;
		unsigned int null;
		unsigned int pathaddr;
	} __attribute__((packed)) rmdir_struct;

	struct syscall *sysc = calloc(1, sizeof(struct syscall));
	rmdir_struct *rmds = calloc(1, sizeof(rmdir_struct));

	int packetlen, paddedpathlen;
	char *packet;

	paddedpathlen = strlen(path) + 1;
	if (paddedpathlen % 4)
		paddedpathlen += 4 - (paddedpathlen % 4);
	
	packetlen = sizeof(rmdir_struct) + paddedpathlen;

	memset(rmds, 0, sizeof(rmdir_struct));
	rmds->length = packetlen - 4;
	rmds->syscall_no = SYS_rmdir;
	rmds->pathaddr = remote_sp - (4 + paddedpathlen);

	if ((packet = malloc(packetlen))) {

		memset(packet, 0, packetlen);
		memcpy(packet, (char*)rmds, sizeof(rmdir_struct));
		strncpy(packet + sizeof(rmdir_struct), path, strlen(path));

 		sysc->length = packetlen;
 		sysc->packet = packet;
		
 		return sysc;

	}
	return 0;
}
