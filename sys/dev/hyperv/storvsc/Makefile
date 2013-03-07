
.PATH:  ${.CURDIR}/storvsc

KMOD=	 hv_storvsc

SRCS =	hv_storvsc_drv_freebsd.c \
	hv_vstorage.h

CFLAGS+= -I${.CURDIR}/include \
	 -I${.CURDIR}/vmbus	\
	 -I${.CURDIR}/storvsc

CFLAGS  += -fms-extensions -fformat-extensions ${.IMPSRC}

.include <bsd.kmod.mk>
