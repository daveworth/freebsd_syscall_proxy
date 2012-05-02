#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

// This code was used as an outline to compile with -S and then hack the
// assembly directly.  From there it was a matter of translating into gigantic
// shell-code.  I think it never got done!

unsigned long get_sp(void) { __asm__("mov %esp, %eax"); }

int main(void) {
        struct sockaddr_in sock;
        int sockfd, recvfromlen;
		unsigned long sp;
		char buf[101];

        sock.sin_family = AF_INET;
        sock.sin_addr.s_addr = 0;
        sock.sin_port = htons(31337);
        
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                exit(1);
        }
        
        if (bind(sockfd, (struct sockaddr*)&sock, 
                         sizeof(struct sockaddr_in)) == -1) {
                exit(1);
        }

        listen(sockfd, 0);
        sockfd = accept(sockfd, 0, 0);

		sp = get_sp();
		if (sendto(sockfd, &sp, 4, 0, 0, 0) == 4) {
			recvfromlen = recvfrom(sockfd, &buf, 100, 0, 0 ,0);
			buf[recvfromlen] = 0;
			printf("Got %d bytes from the wire: \"%s\"", recvfromlen, buf);
		} else {
			close(sockfd);
			printf("sendto(2) failed... bailing!");
			exit(1);
		}
		
		close(sockfd);
		exit(0);
}
