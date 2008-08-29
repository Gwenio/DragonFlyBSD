# $FreeBSD: src/sys/conf/kern.mk,v 1.52 2007/05/24 21:53:42 obrien Exp $
# $DragonFly: src/sys/platform/pc64/conf/kern.mk,v 1.2 2008/08/29 17:07:15 dillon Exp $

#
# Warning flags for compiling the kernel and components of the kernel.
#
# For AMD64, we explicitly prohibit the use of FPU, SSE and other SIMD
# operations inside the kernel itself.  These operations are exclusively
# reserved for user applications.
#
CFLAGS+=	-mpreferred-stack-boundary=4
CFLAGS+=	-mcmodel=small -mno-red-zone \
		-mfpmath=387 -mno-sse -mno-sse2 -mno-sse3 -mno-mmx -mno-3dnow \
		-msoft-float -fno-asynchronous-unwind-tables \
		-fno-omit-frame-pointer
INLINE_LIMIT?=	8000
