# $FreeBSD: src/sys/modules/sound/sound/Makefile,v 1.16.2.2 2006/09/13 08:40:21 des Exp $

KMOD=	sound
SRCS=	device_if.h bus_if.h pci_if.h
SRCS+=	ac97_if.h channel_if.h feeder_if.h mixer_if.h
SRCS+=	ac97_if.c channel_if.c feeder_if.c mixer_if.c
SRCS+=	ac97.c ac97_patch.c buffer.c channel.c dsp.c
SRCS+=	fake.c feeder.c feeder_fmt.c feeder_rate.c feeder_volume.c
SRCS+=	mixer.c sndstat.c sound.c vchan.c

EXPORT_SYMS=	YES	# XXX evaluate

.include <bsd.kmod.mk>
