# Makefile for the hello (now secret) driver.
PROG=	secret	
SRCS=	secret.c

DPADD+=	${LIBDRIVER} ${LIBSYS}
LDADD+=	-ldriver -lsys

MAN=

BINDIR?= /usr/sbin
testing: down clean install start 
start: 
	service up /usr/sbin/secret -dev /dev/secret
down:
	service down secret
test:
	echo "hi" > /dev/secret



.include <bsd.prog.mk>
