# $FreeBSD: src/sbin/vinum/Makefile,v 1.12.2.2 2001/08/01 09:13:24 obrien Exp $
# $DragonFly: src/sbin/vinum/Makefile,v 1.9 2007/07/22 22:46:09 corecode Exp $

PROG=	vinum
SRCS=	v.c list.c vinumparser.c vinumutil.c vext.h commands.c
MAN=	vinum.8
WARNS?=	2

CFLAGS+=	-I${.CURDIR}/../../lib/libedit -I${.CURDIR}/../../sys
DPADD=	${LIBEDIT} ${LIBTERMCAP} ${LIBDEVSTAT}
LDADD=	-ledit -ltermcap -ldevstat

.include <bsd.prog.mk>
