#!/bin/sh

#
# Copyright (c) 2009 Peter Holm <pho@FreeBSD.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $FreeBSD$
#

# Simple union test scenario

[ `id -u ` -ne 0 ] && echo "Must be root!" && exit 1

. ../default.cfg

u1=$mdstart
u2=$((u1 + 1))
[ -d mp1 ] || mkdir mp1

mount | grep -q /dev/md${u2}$part && umount -f /dev/md${u2}$part
mount | grep -q /dev/md${u1}$part && umount -f /dev/md${u1}$part
mdconfig -l | grep -q md${u2} && mdconfig -d -u $u2
mdconfig -l | grep -q md${u1} && mdconfig -d -u $u1

mdconfig -s 256m -u $u1
bsdlabel -w md$u1 auto
newfs md${u1}${part} > /dev/null

mdconfig -s 256m -u $u2
bsdlabel -w md$u2 auto
newfs md${u2}${part} > /dev/null

mount -o ro    /dev/md${u1}$part mp1
mount -o union /dev/md${u2}$part mp1

export RUNDIR=`pwd`/mp1/stressX
export runRUNTIME=10m
(cd ..; ./run.sh marcus.cfg)

umount /dev/md${u2}$part
umount /dev/md${u1}$part

mount | grep -q /dev/md${u2}$part && umount -f /dev/md${u2}$part
mount | grep -q /dev/md${u1}$part && umount -f /dev/md${u1}$part

mdconfig -d -u $u2
mdconfig -d -u $u1

rm -rf mp1
