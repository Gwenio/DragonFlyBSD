/*
 * Written by J.T. Conklin <jtc@NetBSD.org>.
 * Public domain.
 *
 * $NetBSD: e_fmod.S,v 1.7 2003/07/26 19:24:58 salo Exp $
 */

#include <machine/asm.h>

#include "abi.h"

ENTRY(fmod)
	XMM_TWO_ARG_DOUBLE_PROLOGUE
	fldl	ARG_DOUBLE_TWO
	fldl	ARG_DOUBLE_ONE
1:	fprem
	fstsw	%ax
	btw	$10,%ax
	jc	1b
	fstp	%st(1)
	XMM_DOUBLE_EPILOGUE
	ret
END(fmod)

	.section .note.GNU-stack,"",%progbits
