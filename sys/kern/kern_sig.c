/*
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_sig.c	8.7 (Berkeley) 4/18/94
 * $FreeBSD: src/sys/kern/kern_sig.c,v 1.72.2.17 2003/05/16 16:34:34 obrien Exp $
 * $DragonFly: src/sys/kern/kern_sig.c,v 1.61 2007/01/14 07:59:03 dillon Exp $
 */

#include "opt_ktrace.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysproto.h>
#include <sys/signalvar.h>
#include <sys/resourcevar.h>
#include <sys/vnode.h>
#include <sys/event.h>
#include <sys/proc.h>
#include <sys/nlookup.h>
#include <sys/pioctl.h>
#include <sys/systm.h>
#include <sys/acct.h>
#include <sys/fcntl.h>
#include <sys/lock.h>
#include <sys/wait.h>
#include <sys/ktrace.h>
#include <sys/syslog.h>
#include <sys/stat.h>
#include <sys/sysent.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/interrupt.h>
#include <sys/unistd.h>
#include <sys/kern_syscall.h>
#include <sys/vkernel.h>
#include <sys/thread2.h>

#include <machine/cpu.h>
#include <machine/smp.h>

static int	coredump(struct proc *);
static char	*expand_name(const char *, uid_t, pid_t);
static int	dokillpg(int sig, int pgid, int all);
static int	sig_ffs(sigset_t *set);
static int	sigprop(int sig);
#ifdef SMP
static void	signotify_remote(void *arg);
#endif
static int	kern_sigtimedwait(sigset_t set, siginfo_t *info,
		    struct timespec *timeout);

static int	filt_sigattach(struct knote *kn);
static void	filt_sigdetach(struct knote *kn);
static int	filt_signal(struct knote *kn, long hint);

struct filterops sig_filtops =
	{ 0, filt_sigattach, filt_sigdetach, filt_signal };

static int	kern_logsigexit = 1;
SYSCTL_INT(_kern, KERN_LOGSIGEXIT, logsigexit, CTLFLAG_RW, 
    &kern_logsigexit, 0, 
    "Log processes quitting on abnormal signals to syslog(3)");

/*
 * Can process p, with pcred pc, send the signal sig to process q?
 */
#define CANSIGNAL(q, sig) \
	(!p_trespass(curproc->p_ucred, (q)->p_ucred) || \
	((sig) == SIGCONT && (q)->p_session == curproc->p_session))

/*
 * Policy -- Can real uid ruid with ucred uc send a signal to process q?
 */
#define CANSIGIO(ruid, uc, q) \
	((uc)->cr_uid == 0 || \
	    (ruid) == (q)->p_ucred->cr_ruid || \
	    (uc)->cr_uid == (q)->p_ucred->cr_ruid || \
	    (ruid) == (q)->p_ucred->cr_uid || \
	    (uc)->cr_uid == (q)->p_ucred->cr_uid)

int sugid_coredump;
SYSCTL_INT(_kern, OID_AUTO, sugid_coredump, CTLFLAG_RW, 
	&sugid_coredump, 0, "Enable coredumping set user/group ID processes");

static int	do_coredump = 1;
SYSCTL_INT(_kern, OID_AUTO, coredump, CTLFLAG_RW,
	&do_coredump, 0, "Enable/Disable coredumps");

/*
 * Signal properties and actions.
 * The array below categorizes the signals and their default actions
 * according to the following properties:
 */
#define	SA_KILL		0x01		/* terminates process by default */
#define	SA_CORE		0x02		/* ditto and coredumps */
#define	SA_STOP		0x04		/* suspend process */
#define	SA_TTYSTOP	0x08		/* ditto, from tty */
#define	SA_IGNORE	0x10		/* ignore by default */
#define	SA_CONT		0x20		/* continue if suspended */
#define	SA_CANTMASK	0x40		/* non-maskable, catchable */
#define SA_CKPT         0x80            /* checkpoint process */


static int sigproptbl[NSIG] = {
        SA_KILL,                /* SIGHUP */
        SA_KILL,                /* SIGINT */
        SA_KILL|SA_CORE,        /* SIGQUIT */
        SA_KILL|SA_CORE,        /* SIGILL */
        SA_KILL|SA_CORE,        /* SIGTRAP */
        SA_KILL|SA_CORE,        /* SIGABRT */
        SA_KILL|SA_CORE,        /* SIGEMT */
        SA_KILL|SA_CORE,        /* SIGFPE */
        SA_KILL,                /* SIGKILL */
        SA_KILL|SA_CORE,        /* SIGBUS */
        SA_KILL|SA_CORE,        /* SIGSEGV */
        SA_KILL|SA_CORE,        /* SIGSYS */
        SA_KILL,                /* SIGPIPE */
        SA_KILL,                /* SIGALRM */
        SA_KILL,                /* SIGTERM */
        SA_IGNORE,              /* SIGURG */
        SA_STOP,                /* SIGSTOP */
        SA_STOP|SA_TTYSTOP,     /* SIGTSTP */
        SA_IGNORE|SA_CONT,      /* SIGCONT */
        SA_IGNORE,              /* SIGCHLD */
        SA_STOP|SA_TTYSTOP,     /* SIGTTIN */
        SA_STOP|SA_TTYSTOP,     /* SIGTTOU */
        SA_IGNORE,              /* SIGIO */
        SA_KILL,                /* SIGXCPU */
        SA_KILL,                /* SIGXFSZ */
        SA_KILL,                /* SIGVTALRM */
        SA_KILL,                /* SIGPROF */
        SA_IGNORE,              /* SIGWINCH  */
        SA_IGNORE,              /* SIGINFO */
        SA_KILL,                /* SIGUSR1 */
        SA_KILL,                /* SIGUSR2 */
	SA_IGNORE,              /* SIGTHR */
	SA_CKPT,                /* SIGCKPT */ 
	SA_KILL|SA_CKPT,        /* SIGCKPTEXIT */  
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,
	SA_IGNORE,

};

static __inline int
sigprop(int sig)
{

	if (sig > 0 && sig < NSIG)
		return (sigproptbl[_SIG_IDX(sig)]);
	return (0);
}

static __inline int
sig_ffs(sigset_t *set)
{
	int i;

	for (i = 0; i < _SIG_WORDS; i++)
		if (set->__bits[i])
			return (ffs(set->__bits[i]) + (i * 32));
	return (0);
}

int
kern_sigaction(int sig, struct sigaction *act, struct sigaction *oact)
{
	struct thread *td = curthread;
	struct proc *p = td->td_proc;
	struct sigacts *ps = p->p_sigacts;

	if (sig <= 0 || sig > _SIG_MAXSIG)
		return (EINVAL);

	if (oact) {
		oact->sa_handler = ps->ps_sigact[_SIG_IDX(sig)];
		oact->sa_mask = ps->ps_catchmask[_SIG_IDX(sig)];
		oact->sa_flags = 0;
		if (SIGISMEMBER(ps->ps_sigonstack, sig))
			oact->sa_flags |= SA_ONSTACK;
		if (!SIGISMEMBER(ps->ps_sigintr, sig))
			oact->sa_flags |= SA_RESTART;
		if (SIGISMEMBER(ps->ps_sigreset, sig))
			oact->sa_flags |= SA_RESETHAND;
		if (SIGISMEMBER(ps->ps_signodefer, sig))
			oact->sa_flags |= SA_NODEFER;
		if (SIGISMEMBER(ps->ps_siginfo, sig))
			oact->sa_flags |= SA_SIGINFO;
		if (SIGISMEMBER(ps->ps_sigmailbox, sig))
			oact->sa_flags |= SA_MAILBOX;
		if (sig == SIGCHLD && p->p_procsig->ps_flag & PS_NOCLDSTOP)
			oact->sa_flags |= SA_NOCLDSTOP;
		if (sig == SIGCHLD && p->p_procsig->ps_flag & PS_NOCLDWAIT)
			oact->sa_flags |= SA_NOCLDWAIT;
	}
	if (act) {
		/*
		 * Check for invalid requests.  KILL and STOP cannot be
		 * caught.
		 */
		if (sig == SIGKILL || sig == SIGSTOP) {
			if (act->sa_handler != SIG_DFL)
				return (EINVAL);
#if 0
			/* (not needed, SIG_DFL forces action to occur) */
			if (act->sa_flags & SA_MAILBOX)
				return (EINVAL);
#endif
		}

		/*
		 * Change setting atomically.
		 */
		crit_enter();

		ps->ps_catchmask[_SIG_IDX(sig)] = act->sa_mask;
		SIG_CANTMASK(ps->ps_catchmask[_SIG_IDX(sig)]);
		if (act->sa_flags & SA_SIGINFO) {
			ps->ps_sigact[_SIG_IDX(sig)] =
			    (__sighandler_t *)act->sa_sigaction;
			SIGADDSET(ps->ps_siginfo, sig);
		} else {
			ps->ps_sigact[_SIG_IDX(sig)] = act->sa_handler;
			SIGDELSET(ps->ps_siginfo, sig);
		}
		if (!(act->sa_flags & SA_RESTART))
			SIGADDSET(ps->ps_sigintr, sig);
		else
			SIGDELSET(ps->ps_sigintr, sig);
		if (act->sa_flags & SA_ONSTACK)
			SIGADDSET(ps->ps_sigonstack, sig);
		else
			SIGDELSET(ps->ps_sigonstack, sig);
		if (act->sa_flags & SA_RESETHAND)
			SIGADDSET(ps->ps_sigreset, sig);
		else
			SIGDELSET(ps->ps_sigreset, sig);
		if (act->sa_flags & SA_NODEFER)
			SIGADDSET(ps->ps_signodefer, sig);
		else
			SIGDELSET(ps->ps_signodefer, sig);
		if (act->sa_flags & SA_MAILBOX)
			SIGADDSET(ps->ps_sigmailbox, sig);
		else
			SIGDELSET(ps->ps_sigmailbox, sig);
		if (sig == SIGCHLD) {
			if (act->sa_flags & SA_NOCLDSTOP)
				p->p_procsig->ps_flag |= PS_NOCLDSTOP;
			else
				p->p_procsig->ps_flag &= ~PS_NOCLDSTOP;
			if (act->sa_flags & SA_NOCLDWAIT) {
				/*
				 * Paranoia: since SA_NOCLDWAIT is implemented
				 * by reparenting the dying child to PID 1 (and
				 * trust it to reap the zombie), PID 1 itself
				 * is forbidden to set SA_NOCLDWAIT.
				 */
				if (p->p_pid == 1)
					p->p_procsig->ps_flag &= ~PS_NOCLDWAIT;
				else
					p->p_procsig->ps_flag |= PS_NOCLDWAIT;
			} else {
				p->p_procsig->ps_flag &= ~PS_NOCLDWAIT;
			}
		}
		/*
		 * Set bit in p_sigignore for signals that are set to SIG_IGN,
		 * and for signals set to SIG_DFL where the default is to
		 * ignore. However, don't put SIGCONT in p_sigignore, as we
		 * have to restart the process.
		 */
		if (ps->ps_sigact[_SIG_IDX(sig)] == SIG_IGN ||
		    (sigprop(sig) & SA_IGNORE &&
		     ps->ps_sigact[_SIG_IDX(sig)] == SIG_DFL)) {
			/* never to be seen again */
			SIGDELSET(p->p_siglist, sig);
			if (sig != SIGCONT)
				/* easier in ksignal */
				SIGADDSET(p->p_sigignore, sig);
			SIGDELSET(p->p_sigcatch, sig);
		} else {
			SIGDELSET(p->p_sigignore, sig);
			if (ps->ps_sigact[_SIG_IDX(sig)] == SIG_DFL)
				SIGDELSET(p->p_sigcatch, sig);
			else
				SIGADDSET(p->p_sigcatch, sig);
		}

		crit_exit();
	}
	return (0);
}

int
sys_sigaction(struct sigaction_args *uap)
{
	struct sigaction act, oact;
	struct sigaction *actp, *oactp;
	int error;

	actp = (uap->act != NULL) ? &act : NULL;
	oactp = (uap->oact != NULL) ? &oact : NULL;
	if (actp) {
		error = copyin(uap->act, actp, sizeof(act));
		if (error)
			return (error);
	}
	error = kern_sigaction(uap->sig, actp, oactp);
	if (oactp && !error) {
		error = copyout(oactp, uap->oact, sizeof(oact));
	}
	return (error);
}

/*
 * Initialize signal state for process 0;
 * set to ignore signals that are ignored by default.
 */
void
siginit(struct proc *p)
{
	int i;

	for (i = 1; i <= NSIG; i++)
		if (sigprop(i) & SA_IGNORE && i != SIGCONT)
			SIGADDSET(p->p_sigignore, i);
}

/*
 * Reset signals for an exec of the specified process.
 */
void
execsigs(struct proc *p)
{
	struct sigacts *ps = p->p_sigacts;
	int sig;

	/*
	 * Reset caught signals.  Held signals remain held
	 * through p_sigmask (unless they were caught,
	 * and are now ignored by default).
	 */
	while (SIGNOTEMPTY(p->p_sigcatch)) {
		sig = sig_ffs(&p->p_sigcatch);
		SIGDELSET(p->p_sigcatch, sig);
		if (sigprop(sig) & SA_IGNORE) {
			if (sig != SIGCONT)
				SIGADDSET(p->p_sigignore, sig);
			SIGDELSET(p->p_siglist, sig);
		}
		ps->ps_sigact[_SIG_IDX(sig)] = SIG_DFL;
	}
	/*
	 * Reset stack state to the user stack.
	 * Clear set of signals caught on the signal stack.
	 */
	p->p_sigstk.ss_flags = SS_DISABLE;
	p->p_sigstk.ss_size = 0;
	p->p_sigstk.ss_sp = 0;
	p->p_flag &= ~P_ALTSTACK;
	/*
	 * Reset no zombies if child dies flag as Solaris does.
	 */
	p->p_procsig->ps_flag &= ~PS_NOCLDWAIT;
}

/*
 * kern_sigprocmask() - MP SAFE ONLY IF p == curproc
 *
 *	Manipulate signal mask.  This routine is MP SAFE *ONLY* if
 *	p == curproc.
 */
int
kern_sigprocmask(int how, sigset_t *set, sigset_t *oset)
{
	struct thread *td = curthread;
	struct proc *p = td->td_proc;
	int error;

	if (oset != NULL)
		*oset = p->p_sigmask;

	error = 0;
	if (set != NULL) {
		switch (how) {
		case SIG_BLOCK:
			SIG_CANTMASK(*set);
			SIGSETOR(p->p_sigmask, *set);
			break;
		case SIG_UNBLOCK:
			SIGSETNAND(p->p_sigmask, *set);
			break;
		case SIG_SETMASK:
			SIG_CANTMASK(*set);
			p->p_sigmask = *set;
			break;
		default:
			error = EINVAL;
			break;
		}
	}
	return (error);
}

/*
 * sigprocmask() - MP SAFE
 */
int
sys_sigprocmask(struct sigprocmask_args *uap)
{
	sigset_t set, oset;
	sigset_t *setp, *osetp;
	int error;

	setp = (uap->set != NULL) ? &set : NULL;
	osetp = (uap->oset != NULL) ? &oset : NULL;
	if (setp) {
		error = copyin(uap->set, setp, sizeof(set));
		if (error)
			return (error);
	}
	error = kern_sigprocmask(uap->how, setp, osetp);
	if (osetp && !error) {
		error = copyout(osetp, uap->oset, sizeof(oset));
	}
	return (error);
}

int
kern_sigpending(struct __sigset *set)
{
	struct thread *td = curthread;
	struct proc *p = td->td_proc;

	*set = p->p_siglist;

	return (0);
}

int
sys_sigpending(struct sigpending_args *uap)
{
	sigset_t set;
	int error;

	error = kern_sigpending(&set);

	if (error == 0)
		error = copyout(&set, uap->set, sizeof(set));
	return (error);
}

/*
 * Suspend process until signal, providing mask to be set
 * in the meantime.
 */
int
kern_sigsuspend(struct __sigset *set)
{
	struct thread *td = curthread;
	struct proc *p = td->td_proc;
	struct sigacts *ps = p->p_sigacts;

	/*
	 * When returning from sigsuspend, we want
	 * the old mask to be restored after the
	 * signal handler has finished.  Thus, we
	 * save it here and mark the sigacts structure
	 * to indicate this.
	 */
	p->p_oldsigmask = p->p_sigmask;
	p->p_flag |= P_OLDMASK;

	SIG_CANTMASK(*set);
	p->p_sigmask = *set;
	while (tsleep(ps, PCATCH, "pause", 0) == 0)
		/* void */;
	/* always return EINTR rather than ERESTART... */
	return (EINTR);
}

/*
 * Note nonstandard calling convention: libc stub passes mask, not
 * pointer, to save a copyin.
 */
int
sys_sigsuspend(struct sigsuspend_args *uap)
{
	sigset_t mask;
	int error;

	error = copyin(uap->sigmask, &mask, sizeof(mask));
	if (error)
		return (error);

	error = kern_sigsuspend(&mask);

	return (error);
}

int
kern_sigaltstack(struct sigaltstack *ss, struct sigaltstack *oss)
{
	struct thread *td = curthread;
	struct proc *p = td->td_proc;

	if ((p->p_flag & P_ALTSTACK) == 0)
		p->p_sigstk.ss_flags |= SS_DISABLE;

	if (oss)
		*oss = p->p_sigstk;

	if (ss) {
		if (ss->ss_flags & SS_DISABLE) {
			if (p->p_sigstk.ss_flags & SS_ONSTACK)
				return (EINVAL);
			p->p_flag &= ~P_ALTSTACK;
			p->p_sigstk.ss_flags = ss->ss_flags;
		} else {
			if (ss->ss_size < p->p_sysent->sv_minsigstksz)
				return (ENOMEM);
			p->p_flag |= P_ALTSTACK;
			p->p_sigstk = *ss;
		}
	}

	return (0);
}

int
sys_sigaltstack(struct sigaltstack_args *uap)
{
	stack_t ss, oss;
	int error;

	if (uap->ss) {
		error = copyin(uap->ss, &ss, sizeof(ss));
		if (error)
			return (error);
	}

	error = kern_sigaltstack(uap->ss ? &ss : NULL,
	    uap->oss ? &oss : NULL);

	if (error == 0 && uap->oss)
		error = copyout(&oss, uap->oss, sizeof(*uap->oss));
	return (error);
}

/*
 * Common code for kill process group/broadcast kill.
 * cp is calling process.
 */
struct killpg_info {
	int nfound;
	int sig;
};

static int killpg_all_callback(struct proc *p, void *data);

static int
dokillpg(int sig, int pgid, int all)
{
	struct killpg_info info;
	struct proc *cp = curproc;
	struct proc *p;
	struct pgrp *pgrp;

	info.nfound = 0;
	info.sig = sig;

	if (all) {
		/*
		 * broadcast
		 */
		allproc_scan(killpg_all_callback, &info);
	} else {
		if (pgid == 0) {
			/*
			 * zero pgid means send to my process group.
			 */
			pgrp = cp->p_pgrp;
		} else {
			pgrp = pgfind(pgid);
			if (pgrp == NULL)
				return (ESRCH);
		}
		lockmgr(&pgrp->pg_lock, LK_EXCLUSIVE);
		LIST_FOREACH(p, &pgrp->pg_members, p_pglist) {
			if (p->p_pid <= 1 || 
			    (p->p_flag & (P_SYSTEM | P_ZOMBIE)) ||
			    !CANSIGNAL(p, sig)) {
				continue;
			}
			++info.nfound;
			if (sig)
				ksignal(p, sig);
		}
		lockmgr(&pgrp->pg_lock, LK_RELEASE);
	}
	return (info.nfound ? 0 : ESRCH);
}

static int
killpg_all_callback(struct proc *p, void *data)
{
	struct killpg_info *info = data;

	if (p->p_pid <= 1 || (p->p_flag & P_SYSTEM) ||
	    p == curproc || !CANSIGNAL(p, info->sig)) {
		return (0);
	}
	++info->nfound;
	if (info->sig)
		ksignal(p, info->sig);
	return(0);
}

int
kern_kill(int sig, int pid)
{
	struct thread *td = curthread;
	struct proc *p = td->td_proc;

	if ((u_int)sig > _SIG_MAXSIG)
		return (EINVAL);
	if (pid > 0) {
		/* kill single process */
		if ((p = pfind(pid)) == NULL)
			return (ESRCH);
		if (!CANSIGNAL(p, sig))
			return (EPERM);
		if (sig)
			ksignal(p, sig);
		return (0);
	}
	switch (pid) {
	case -1:		/* broadcast signal */
		return (dokillpg(sig, 0, 1));
	case 0:			/* signal own process group */
		return (dokillpg(sig, 0, 0));
	default:		/* negative explicit process group */
		return (dokillpg(sig, -pid, 0));
	}
	/* NOTREACHED */
}

int
sys_kill(struct kill_args *uap)
{
	int error;

	error = kern_kill(uap->signum, uap->pid);

	return (error);
}

/*
 * Send a signal to a process group.
 */
void
gsignal(int pgid, int sig)
{
	struct pgrp *pgrp;

	if (pgid && (pgrp = pgfind(pgid)))
		pgsignal(pgrp, sig, 0);
}

/*
 * Send a signal to a process group.  If checktty is 1,
 * limit to members which have a controlling terminal.
 *
 * pg_lock interlocks against a fork that might be in progress, to
 * ensure that the new child process picks up the signal.
 */
void
pgsignal(struct pgrp *pgrp, int sig, int checkctty)
{
	struct proc *p;

	if (pgrp) {
		lockmgr(&pgrp->pg_lock, LK_EXCLUSIVE);
		LIST_FOREACH(p, &pgrp->pg_members, p_pglist) {
			if (checkctty == 0 || p->p_flag & P_CONTROLT)
				ksignal(p, sig);
		}
		lockmgr(&pgrp->pg_lock, LK_RELEASE);
	}
}

/*
 * Send a signal caused by a trap to the current process.
 * If it will be caught immediately, deliver it with correct code.
 * Otherwise, post it normally.
 */
void
trapsignal(struct proc *p, int sig, u_long code)
{
	struct sigacts *ps = p->p_sigacts;

	/*
	 * If we are a virtual kernel running an emulated user process
	 * context, switch back to the virtual kernel context before
	 * trying to post the signal.
	 */
	if (p->p_vkernel && p->p_vkernel->vk_current) {
		struct trapframe *tf = curthread->td_lwp->lwp_md.md_regs;
		tf->tf_trapno = 0;
		vkernel_trap(p, tf);
	}


	if ((p->p_flag & P_TRACED) == 0 && SIGISMEMBER(p->p_sigcatch, sig) &&
	    !SIGISMEMBER(p->p_sigmask, sig)) {
		p->p_lwp.lwp_ru.ru_nsignals++;
#ifdef KTRACE
		if (KTRPOINT(p->p_thread, KTR_PSIG))
			ktrpsig(p, sig, ps->ps_sigact[_SIG_IDX(sig)],
				&p->p_sigmask, code);
#endif
		(*p->p_sysent->sv_sendsig)(ps->ps_sigact[_SIG_IDX(sig)], sig,
						&p->p_sigmask, code);
		SIGSETOR(p->p_sigmask, ps->ps_catchmask[_SIG_IDX(sig)]);
		if (!SIGISMEMBER(ps->ps_signodefer, sig))
			SIGADDSET(p->p_sigmask, sig);
		if (SIGISMEMBER(ps->ps_sigreset, sig)) {
			/*
			 * See kern_sigaction() for origin of this code.
			 */
			SIGDELSET(p->p_sigcatch, sig);
			if (sig != SIGCONT &&
			    sigprop(sig) & SA_IGNORE)
				SIGADDSET(p->p_sigignore, sig);
			ps->ps_sigact[_SIG_IDX(sig)] = SIG_DFL;
		}
	} else {
		p->p_code = code;	/* XXX for core dump/debugger */
		p->p_sig = sig;		/* XXX to verify code */
		ksignal(p, sig);
	}
}

/*
 * Send the signal to the process.  If the signal has an action, the action
 * is usually performed by the target process rather than the caller; we add
 * the signal to the set of pending signals for the process.
 *
 * Exceptions:
 *   o When a stop signal is sent to a sleeping process that takes the
 *     default action, the process is stopped without awakening it.
 *   o SIGCONT restarts stopped processes (or puts them back to sleep)
 *     regardless of the signal action (eg, blocked or ignored).
 *
 * Other ignored signals are discarded immediately.
 */
void
ksignal(struct proc *p, int sig)
{
	struct lwp *lp = &p->p_lwp;
	int prop;
	sig_t action;

	if (sig > _SIG_MAXSIG || sig <= 0) {
		kprintf("ksignal: signal %d\n", sig);
		panic("ksignal signal number");
	}

	crit_enter();
	KNOTE(&p->p_klist, NOTE_SIGNAL | sig);
	crit_exit();

	prop = sigprop(sig);

	/*
	 * If proc is traced, always give parent a chance;
	 * if signal event is tracked by procfs, give *that*
	 * a chance, as well.
	 */
	if ((p->p_flag & P_TRACED) || (p->p_stops & S_SIG)) {
		action = SIG_DFL;
	} else {
		/*
		 * If the signal is being ignored,
		 * then we forget about it immediately.
		 * (Note: we don't set SIGCONT in p_sigignore,
		 * and if it is set to SIG_IGN,
		 * action will be SIG_DFL here.)
		 */
		if (SIGISMEMBER(p->p_sigignore, sig) || (p->p_flag & P_WEXIT))
			return;
		if (SIGISMEMBER(p->p_sigmask, sig))
			action = SIG_HOLD;
		else if (SIGISMEMBER(p->p_sigcatch, sig))
			action = SIG_CATCH;
		else
			action = SIG_DFL;
	}

	if (p->p_nice > NZERO && action == SIG_DFL && (prop & SA_KILL) &&
	    (p->p_flag & P_TRACED) == 0) {
		p->p_nice = NZERO;
	}

	/*
	 * If continuing, clear any pending STOP signals.
	 */
	if (prop & SA_CONT)
		SIG_STOPSIGMASK(p->p_siglist);
	
	if (prop & SA_STOP) {
		/*
		 * If sending a tty stop signal to a member of an orphaned
		 * process group, discard the signal here if the action
		 * is default; don't stop the process below if sleeping,
		 * and don't clear any pending SIGCONT.
		 */
		if (prop & SA_TTYSTOP && p->p_pgrp->pg_jobc == 0 &&
		    action == SIG_DFL) {
		        return;
		}
		SIG_CONTSIGMASK(p->p_siglist);
	}
	SIGADDSET(p->p_siglist, sig);

	/*
	 * Defer further processing for signals which are held,
	 * except that stopped processes must be continued by SIGCONT.
	 */
	if (action == SIG_HOLD) {
		if ((prop & SA_CONT) == 0 || (p->p_flag & P_STOPPED) == 0)
			return;
	}

	crit_enter();

	/*
	 * Process is in tsleep and not stopped
	 */
	if (p->p_stat == SSLEEP && (p->p_flag & P_STOPPED) == 0) {
		/*
		 * If the process is sleeping uninterruptibly
		 * we can't interrupt the sleep... the signal will
		 * be noticed when the process returns through
		 * trap() or syscall().
		 */
		if ((p->p_flag & P_SINTR) == 0)
			goto out;

		/*
		 * If the process is sleeping and traced, make it runnable
		 * so it can discover the signal in issignal() and stop
		 * for the parent.
		 *
		 * If the process is stopped and traced, no further action
		 * is necessary.
		 */
		if (p->p_flag & P_TRACED)
			goto run;

		/*
		 * If the process is sleeping and SA_CONT, and the signal
		 * mode is SIG_DFL, then make the process runnable.
		 *
		 * However, do *NOT* set P_BREAKTSLEEP.  We do not want 
		 * a SIGCONT to terminate an interruptable tsleep early
		 * and generate a spurious EINTR.
		 */
		if ((prop & SA_CONT) && action == SIG_DFL) {
			SIGDELSET(p->p_siglist, sig);
			goto run_no_break;
		}

		/*
		 * If the process is sleeping and receives a STOP signal,
		 * process immediately if possible.  All other (caught or
		 * default) signals cause the process to run.
		 */
		if (prop & SA_STOP) {
			if (action != SIG_DFL)
				goto run;

			/*
			 * If a child holding parent blocked, stopping 
			 * could cause deadlock.  Take no action at this
			 * time.
			 */
			if (p->p_flag & P_PPWAIT)
				goto out;

			/*
			 * Do not actually try to manipulate the process
			 * while it is sleeping, simply set P_STOPPED to
			 * indicate that it should stop as soon as it safely
			 * can.
			 */
			SIGDELSET(p->p_siglist, sig);
			p->p_flag |= P_STOPPED;
			p->p_flag &= ~P_WAITED;
			p->p_xstat = sig;
			wakeup(p->p_pptr);
			if ((p->p_pptr->p_procsig->ps_flag & PS_NOCLDSTOP) == 0)
				ksignal(p->p_pptr, SIGCHLD);
			goto out;
		}

		/*
		 * Otherwise the signal can interrupt the sleep.
		 */
		goto run;
	}

	/*
	 * Process is in tsleep and is stopped
	 */
	if (p->p_stat == SSLEEP && (p->p_flag & P_STOPPED)) {
		/*
		 * If the process is stopped and is being traced, then no
		 * further action is necessary.
		 */
		if (p->p_flag & P_TRACED)
			goto out;

		/*
		 * If the process is stopped and receives a KILL signal,
		 * make the process runnable.
		 */
		if (sig == SIGKILL)
			goto run;

		/*
		 * If the process is stopped and receives a CONT signal,
		 * then try to make the process runnable again.
		 */
		if (prop & SA_CONT) {
			/*
			 * If SIGCONT is default (or ignored), we continue the
			 * process but don't leave the signal in p_siglist, as
			 * it has no further action.  If SIGCONT is held, we
			 * continue the process and leave the signal in
			 * p_siglist.  If the process catches SIGCONT, let it
			 * handle the signal itself.
			 */
			if (action == SIG_DFL)
				SIGDELSET(p->p_siglist, sig);
			if (action == SIG_CATCH)
				goto run;

			/*
			 * Make runnable but do not break a tsleep unless
			 * some other signal was pending.
			 */
			goto run_no_break;
		}

		/*
		 * If the process is stopped and receives another STOP
		 * signal, we do not need to stop it again.  If we did
		 * the shell could get confused.
		 */
		if (prop & SA_STOP) {
			SIGDELSET(p->p_siglist, sig);
			goto out;
		}

		/*
		 * Otherwise the process is sleeping interruptably but
		 * is stopped, just set the P_BREAKTSLEEP flag and take
		 * no further action.  The next runnable action will wake
		 * the process up.
		 */
		p->p_flag |= P_BREAKTSLEEP;
		goto out;
	}

	/*
	 * Otherwise the process is running
	 *
	 * SRUN, SIDL, SZOMB do nothing with the signal,
	 * other than kicking ourselves if we are running.
	 * It will either never be noticed, or noticed very soon.
	 *
	 * Note that p_thread may be NULL or may not be completely
	 * initialized if the process is in the SIDL or SZOMB state.
	 *
	 * For SMP we may have to forward the request to another cpu.
	 * YYY the MP lock prevents the target process from moving
	 * to another cpu, see kern/kern_switch.c
	 *
	 * If the target thread is waiting on its message port,
	 * wakeup the target thread so it can check (or ignore)
	 * the new signal.  YYY needs cleanup.
	 */
	if (lp == lwkt_preempted_proc()) {
		signotify();
	} else if (p->p_stat == SRUN) {
		struct thread *td = p->p_thread;

		KASSERT(td != NULL, 
		    ("pid %d NULL p_thread stat %d flags %08x",
		    p->p_pid, p->p_stat, p->p_flag));

#ifdef SMP
		if (td->td_gd != mycpu)
			lwkt_send_ipiq(td->td_gd, signotify_remote, lp);
		else
#endif
		if (td->td_msgport.mp_flags & MSGPORTF_WAITING)
			lwkt_schedule(td);
	}
	goto out;
	/*NOTREACHED*/
run:
	/*
	 * Make runnable and break out of any tsleep as well.
	 */
	p->p_flag |= P_BREAKTSLEEP;
run_no_break:
	setrunnable(p);
out:
	crit_exit();
}

#ifdef SMP

/*
 * This function is called via an IPI.  We will be in a critical section but
 * the MP lock will NOT be held.  Also note that by the time the ipi message
 * gets to us the process 'p' (arg) may no longer be scheduled or even valid.
 */
static void
signotify_remote(void *arg)
{
	struct lwp *lp = arg;

	if (lp == lwkt_preempted_proc()) {
		signotify();
	} else {
		struct thread *td = lp->lwp_thread;
		if (td->td_msgport.mp_flags & MSGPORTF_WAITING)
			lwkt_schedule(td);
	}
}

#endif

static int
kern_sigtimedwait(sigset_t waitset, siginfo_t *info, struct timespec *timeout)
{
	sigset_t savedmask, set;
	struct proc *p = curproc;
	int error, sig, hz, timevalid = 0;
	struct timespec rts, ets, ts;
	struct timeval tv;

	error = 0;
	sig = 0;
	SIG_CANTMASK(waitset);
	savedmask = p->p_sigmask;

	if (timeout) {
		if (timeout->tv_sec >= 0 && timeout->tv_nsec >= 0 &&
		    timeout->tv_nsec < 1000000000) {
			timevalid = 1;
			getnanouptime(&rts);
		 	ets = rts;
			timespecadd(&ets, timeout);
		}
	}

	for (;;) {
		set = p->p_siglist;
		SIGSETAND(set, waitset);
		if ((sig = sig_ffs(&set)) != 0) {
			SIGFILLSET(p->p_sigmask);
			SIGDELSET(p->p_sigmask, sig);
			SIG_CANTMASK(p->p_sigmask);
			sig = issignal(p);
			/*
			 * It may be a STOP signal, in the case, issignal
			 * returns 0, because we may stop there, and new
			 * signal can come in, we should restart if we got
			 * nothing.
			 */
			if (sig == 0)
				continue;
			else
				break;
		}

		/*
		 * Previous checking got nothing, and we retried but still
		 * got nothing, we should return the error status.
		 */
		if (error)
			break;

		/*
		 * POSIX says this must be checked after looking for pending
		 * signals.
		 */
		if (timeout) {
			if (!timevalid) {
				error = EINVAL;
				break;
			}
			getnanouptime(&rts);
			if (timespeccmp(&rts, &ets, >=)) {
				error = EAGAIN;
				break;
			}
			ts = ets;
			timespecsub(&ts, &rts);
			TIMESPEC_TO_TIMEVAL(&tv, &ts);
			hz = tvtohz_high(&tv);
		} else
			hz = 0;

		p->p_sigmask = savedmask;
		SIGSETNAND(p->p_sigmask, waitset);
		error = tsleep(&p->p_sigacts, PCATCH, "sigwt", hz);
		if (timeout) {
			if (error == ERESTART) {
				/* can not restart a timeout wait. */
				error = EINTR;
			} else if (error == EAGAIN) {
				/* will calculate timeout by ourself. */
				error = 0;
			}
		}
		/* Retry ... */
	}

	p->p_sigmask = savedmask;
	if (sig) {
		error = 0;
		bzero(info, sizeof(*info));
		info->si_signo = sig;
		SIGDELSET(p->p_siglist, sig);	/* take the signal! */

		if (sig == SIGKILL)
			sigexit(p, sig);
	}
	return (error);
}

int
sys_sigtimedwait(struct sigtimedwait_args *uap)
{
	struct timespec ts;
	struct timespec *timeout;
	sigset_t set;
	siginfo_t info;
	int error;

	if (uap->timeout) {
		error = copyin(uap->timeout, &ts, sizeof(ts));
		if (error)
			return (error);
		timeout = &ts;
	} else {
		timeout = NULL;
	}
	error = copyin(uap->set, &set, sizeof(set));
	if (error)
		return (error);
	error = kern_sigtimedwait(set, &info, timeout);
	if (error)
		return (error);
 	if (uap->info)
		error = copyout(&info, uap->info, sizeof(info));
	/* Repost if we got an error. */
	if (error)
		ksignal(curproc, info.si_signo);
	else
		uap->sysmsg_result = info.si_signo;
	return (error);
}

int
sys_sigwaitinfo(struct sigwaitinfo_args *uap)
{
	siginfo_t info;
	sigset_t set;
	int error;

	error = copyin(uap->set, &set, sizeof(set));
	if (error)
		return (error);
	error = kern_sigtimedwait(set, &info, NULL);
	if (error)
		return (error);
	if (uap->info)
		error = copyout(&info, uap->info, sizeof(info));
	/* Repost if we got an error. */
	if (error)
		ksignal(curproc, info.si_signo);
	else
		uap->sysmsg_result = info.si_signo;
	return (error);
}

/*
 * If the current process has received a signal that would interrupt a
 * system call, return EINTR or ERESTART as appropriate.
 */
int
iscaught(struct proc *p)
{
	int sig;

	if (p) {
		if ((sig = CURSIG(p)) != 0) {
			if (SIGISMEMBER(p->p_sigacts->ps_sigintr, sig))
				return (EINTR);                        
			return (ERESTART);     
		}                         
	}
	return(EWOULDBLOCK);
}

/*
 * If the current process has received a signal (should be caught or cause
 * termination, should interrupt current syscall), return the signal number.
 * Stop signals with default action are processed immediately, then cleared;
 * they aren't returned.  This is checked after each entry to the system for
 * a syscall or trap (though this can usually be done without calling issignal
 * by checking the pending signal masks in the CURSIG macro.) The normal call
 * sequence is
 *
 * This routine is called via CURSIG/__cursig and the MP lock might not be
 * held.  Obtain the MP lock for the duration of the operation.
 *
 *	while (sig = CURSIG(curproc))
 *		postsig(sig);
 */
int
issignal(struct proc *p)
{
	sigset_t mask;
	int sig, prop;

	get_mplock();
	for (;;) {
		int traced = (p->p_flag & P_TRACED) || (p->p_stops & S_SIG);

		mask = p->p_siglist;
		SIGSETNAND(mask, p->p_sigmask);
		if (p->p_flag & P_PPWAIT)
			SIG_STOPSIGMASK(mask);
		if (!SIGNOTEMPTY(mask)) { 	/* no signal to send */
			rel_mplock();
			return (0);
		}
		sig = sig_ffs(&mask);

		STOPEVENT(p, S_SIG, sig);

		/*
		 * We should see pending but ignored signals
		 * only if P_TRACED was on when they were posted.
		 */
		if (SIGISMEMBER(p->p_sigignore, sig) && (traced == 0)) {
			SIGDELSET(p->p_siglist, sig);
			continue;
		}
		if ((p->p_flag & P_TRACED) && (p->p_flag & P_PPWAIT) == 0) {
			/*
			 * If traced, always stop, and stay stopped until
			 * released by the parent.
			 *
			 * NOTE: P_STOPPED may get cleared during the loop,
			 * but we do not re-notify the parent if we have 
			 * to loop several times waiting for the parent
			 * to let us continue.
			 */
			p->p_xstat = sig;
			p->p_flag |= P_STOPPED;
			p->p_flag &= ~P_WAITED;
			ksignal(p->p_pptr, SIGCHLD);
			do {
				tstop(p);
			} while (!trace_req(p) && (p->p_flag & P_TRACED));
			p->p_flag &= ~P_STOPPED;

			/*
			 * If parent wants us to take the signal,
			 * then it will leave it in p->p_xstat;
			 * otherwise we just look for signals again.
			 */
			SIGDELSET(p->p_siglist, sig);	/* clear old signal */
			sig = p->p_xstat;
			if (sig == 0)
				continue;

			/*
			 * Put the new signal into p_siglist.  If the
			 * signal is being masked, look for other signals.
			 */
			SIGADDSET(p->p_siglist, sig);
			if (SIGISMEMBER(p->p_sigmask, sig))
				continue;

			/*
			 * If the traced bit got turned off, go back up
			 * to the top to rescan signals.  This ensures
			 * that p_sig* and ps_sigact are consistent.
			 */
			if ((p->p_flag & P_TRACED) == 0)
				continue;
		}

		prop = sigprop(sig);

		/*
		 * Decide whether the signal should be returned.
		 * Return the signal's number, or fall through
		 * to clear it from the pending mask.
		 */
		switch ((int)(intptr_t)p->p_sigacts->ps_sigact[_SIG_IDX(sig)]) {
		case (int)SIG_DFL:
			/*
			 * Don't take default actions on system processes.
			 */
			if (p->p_pid <= 1) {
#ifdef DIAGNOSTIC
				/*
				 * Are you sure you want to ignore SIGSEGV
				 * in init? XXX
				 */
				kprintf("Process (pid %lu) got signal %d\n",
					(u_long)p->p_pid, sig);
#endif
				break;		/* == ignore */
			}

			/*
			 * Handle the in-kernel checkpoint action
			 */
			if (prop & SA_CKPT) {
				checkpoint_signal_handler(p);
				break;
			}

			/*
			 * If there is a pending stop signal to process
			 * with default action, stop here,
			 * then clear the signal.  However,
			 * if process is member of an orphaned
			 * process group, ignore tty stop signals.
			 */
			if (prop & SA_STOP) {
				if (p->p_flag & P_TRACED ||
		    		    (p->p_pgrp->pg_jobc == 0 &&
				    prop & SA_TTYSTOP))
					break;	/* == ignore */
				p->p_xstat = sig;
				p->p_flag |= P_STOPPED;
				p->p_flag &= ~P_WAITED;

				if ((p->p_pptr->p_procsig->ps_flag & PS_NOCLDSTOP) == 0)
					ksignal(p->p_pptr, SIGCHLD);
				while (p->p_flag & P_STOPPED) {
					tstop(p);
				}
				break;
			} else if (prop & SA_IGNORE) {
				/*
				 * Except for SIGCONT, shouldn't get here.
				 * Default action is to ignore; drop it.
				 */
				break;		/* == ignore */
			} else {
				rel_mplock();
				return (sig);
			}

			/*NOTREACHED*/

		case (int)SIG_IGN:
			/*
			 * Masking above should prevent us ever trying
			 * to take action on an ignored signal other
			 * than SIGCONT, unless process is traced.
			 */
			if ((prop & SA_CONT) == 0 &&
			    (p->p_flag & P_TRACED) == 0)
				kprintf("issignal\n");
			break;		/* == ignore */

		default:
			/*
			 * This signal has an action, let
			 * postsig() process it.
			 */
			rel_mplock();
			return (sig);
		}
		SIGDELSET(p->p_siglist, sig);		/* take the signal! */
	}
	/* NOTREACHED */
}

/*
 * Take the action for the specified signal
 * from the current set of pending signals.
 */
void
postsig(int sig)
{
	struct thread *td = curthread;
	struct proc *p = td->td_proc;
	struct sigacts *ps = p->p_sigacts;
	sig_t action;
	sigset_t returnmask;
	int code;

	KASSERT(sig != 0, ("postsig"));

	/*
	 * If we are a virtual kernel running an emulated user process
	 * context, switch back to the virtual kernel context before
	 * trying to post the signal.
	 */
	if (p->p_vkernel && p->p_vkernel->vk_current) {
		struct trapframe *tf = curthread->td_lwp->lwp_md.md_regs;
		tf->tf_trapno = 0;
		vkernel_trap(p, tf);
	}

	SIGDELSET(p->p_siglist, sig);
	action = ps->ps_sigact[_SIG_IDX(sig)];
#ifdef KTRACE
	if (KTRPOINT(td, KTR_PSIG))
		ktrpsig(p, sig, action, p->p_flag & P_OLDMASK ?
			&p->p_oldsigmask : &p->p_sigmask, 0);
#endif
	STOPEVENT(p, S_SIG, sig);

	if (action == SIG_DFL) {
		/*
		 * Default action, where the default is to kill
		 * the process.  (Other cases were ignored above.)
		 */
		sigexit(p, sig);
		/* NOTREACHED */
	} else {
		/*
		 * If we get here, the signal must be caught.
		 */
		KASSERT(action != SIG_IGN && !SIGISMEMBER(p->p_sigmask, sig),
		    ("postsig action"));

		crit_enter();

		/*
		 * Reset the signal handler if asked to
		 */
		if (SIGISMEMBER(ps->ps_sigreset, sig)) {
			/*
			 * See kern_sigaction() for origin of this code.
			 */
			SIGDELSET(p->p_sigcatch, sig);
			if (sig != SIGCONT &&
			    sigprop(sig) & SA_IGNORE)
				SIGADDSET(p->p_sigignore, sig);
			ps->ps_sigact[_SIG_IDX(sig)] = SIG_DFL;
		}

		/*
		 * Handle the mailbox case.  Copyout to the appropriate
		 * location but do not generate a signal frame.  The system
		 * call simply returns EINTR and the user is responsible for
		 * polling the mailbox.
		 */
		if (SIGISMEMBER(ps->ps_sigmailbox, sig)) {
			int sig_copy = sig;
			copyout(&sig_copy, (void *)action, sizeof(int));
			curproc->p_flag |= P_MAILBOX;
			crit_exit();
			goto done;
		}

		/*
		 * Set the signal mask and calculate the mask to restore
		 * when the signal function returns.
		 *
		 * Special case: user has done a sigsuspend.  Here the
		 * current mask is not of interest, but rather the
		 * mask from before the sigsuspend is what we want
		 * restored after the signal processing is completed.
		 */
		if (p->p_flag & P_OLDMASK) {
			returnmask = p->p_oldsigmask;
			p->p_flag &= ~P_OLDMASK;
		} else {
			returnmask = p->p_sigmask;
		}
		SIGSETOR(p->p_sigmask, ps->ps_catchmask[_SIG_IDX(sig)]);
		if (!SIGISMEMBER(ps->ps_signodefer, sig))
			SIGADDSET(p->p_sigmask, sig);

		crit_exit();
		p->p_lwp.lwp_ru.ru_nsignals++;
		if (p->p_sig != sig) {
			code = 0;
		} else {
			code = p->p_code;
			p->p_code = 0;
			p->p_sig = 0;
		}
		(*p->p_sysent->sv_sendsig)(action, sig, &returnmask, code);
	}
done:
	;
}

/*
 * Kill the current process for stated reason.
 */
void
killproc(struct proc *p, char *why)
{
	log(LOG_ERR, "pid %d (%s), uid %d, was killed: %s\n", 
		p->p_pid, p->p_comm,
		p->p_ucred ? p->p_ucred->cr_uid : -1, why);
	ksignal(p, SIGKILL);
}

/*
 * Force the current process to exit with the specified signal, dumping core
 * if appropriate.  We bypass the normal tests for masked and caught signals,
 * allowing unrecoverable failures to terminate the process without changing
 * signal state.  Mark the accounting record with the signal termination.
 * If dumping core, save the signal number for the debugger.  Calls exit and
 * does not return.
 */
void
sigexit(struct proc *p, int sig)
{
	p->p_acflag |= AXSIG;
	if (sigprop(sig) & SA_CORE) {
		p->p_sig = sig;
		/*
		 * Log signals which would cause core dumps
		 * (Log as LOG_INFO to appease those who don't want
		 * these messages.)
		 * XXX : Todo, as well as euid, write out ruid too
		 */
		if (coredump(p) == 0)
			sig |= WCOREFLAG;
		if (kern_logsigexit)
			log(LOG_INFO,
			    "pid %d (%s), uid %d: exited on signal %d%s\n",
			    p->p_pid, p->p_comm,
			    p->p_ucred ? p->p_ucred->cr_uid : -1,
			    sig &~ WCOREFLAG,
			    sig & WCOREFLAG ? " (core dumped)" : "");
	}
	exit1(W_EXITCODE(0, sig));
	/* NOTREACHED */
}

static char corefilename[MAXPATHLEN+1] = {"%N.core"};
SYSCTL_STRING(_kern, OID_AUTO, corefile, CTLFLAG_RW, corefilename,
	      sizeof(corefilename), "process corefile name format string");

/*
 * expand_name(name, uid, pid)
 * Expand the name described in corefilename, using name, uid, and pid.
 * corefilename is a kprintf-like string, with three format specifiers:
 *	%N	name of process ("name")
 *	%P	process id (pid)
 *	%U	user id (uid)
 * For example, "%N.core" is the default; they can be disabled completely
 * by using "/dev/null", or all core files can be stored in "/cores/%U/%N-%P".
 * This is controlled by the sysctl variable kern.corefile (see above).
 */

static char *
expand_name(const char *name, uid_t uid, pid_t pid)
{
	char *temp;
	char buf[11];		/* Buffer for pid/uid -- max 4B */
	int i, n;
	char *format = corefilename;
	size_t namelen;

	temp = kmalloc(MAXPATHLEN + 1, M_TEMP, M_NOWAIT);
	if (temp == NULL)
		return NULL;
	namelen = strlen(name);
	for (i = 0, n = 0; n < MAXPATHLEN && format[i]; i++) {
		int l;
		switch (format[i]) {
		case '%':	/* Format character */
			i++;
			switch (format[i]) {
			case '%':
				temp[n++] = '%';
				break;
			case 'N':	/* process name */
				if ((n + namelen) > MAXPATHLEN) {
					log(LOG_ERR, "pid %d (%s), uid (%u):  Path `%s%s' is too long\n",
					    pid, name, uid, temp, name);
					kfree(temp, M_TEMP);
					return NULL;
				}
				memcpy(temp+n, name, namelen);
				n += namelen;
				break;
			case 'P':	/* process id */
				l = ksprintf(buf, "%u", pid);
				if ((n + l) > MAXPATHLEN) {
					log(LOG_ERR, "pid %d (%s), uid (%u):  Path `%s%s' is too long\n",
					    pid, name, uid, temp, name);
					kfree(temp, M_TEMP);
					return NULL;
				}
				memcpy(temp+n, buf, l);
				n += l;
				break;
			case 'U':	/* user id */
				l = ksprintf(buf, "%u", uid);
				if ((n + l) > MAXPATHLEN) {
					log(LOG_ERR, "pid %d (%s), uid (%u):  Path `%s%s' is too long\n",
					    pid, name, uid, temp, name);
					kfree(temp, M_TEMP);
					return NULL;
				}
				memcpy(temp+n, buf, l);
				n += l;
				break;
			default:
			  	log(LOG_ERR, "Unknown format character %c in `%s'\n", format[i], format);
			}
			break;
		default:
			temp[n++] = format[i];
		}
	}
	temp[n] = '\0';
	return temp;
}

/*
 * Dump a process' core.  The main routine does some
 * policy checking, and creates the name of the coredump;
 * then it passes on a vnode and a size limit to the process-specific
 * coredump routine if there is one; if there _is not_ one, it returns
 * ENOSYS; otherwise it returns the error from the process-specific routine.
 */

static int
coredump(struct proc *p)
{
	struct vnode *vp;
	struct ucred *cred = p->p_ucred;
	struct flock lf;
	struct nlookupdata nd;
	struct vattr vattr;
	int error, error1;
	char *name;			/* name of corefile */
	off_t limit;
	
	STOPEVENT(p, S_CORE, 0);

	if (((sugid_coredump == 0) && p->p_flag & P_SUGID) || do_coredump == 0)
		return (EFAULT);
	
	/*
	 * Note that the bulk of limit checking is done after
	 * the corefile is created.  The exception is if the limit
	 * for corefiles is 0, in which case we don't bother
	 * creating the corefile at all.  This layout means that
	 * a corefile is truncated instead of not being created,
	 * if it is larger than the limit.
	 */
	limit = p->p_rlimit[RLIMIT_CORE].rlim_cur;
	if (limit == 0)
		return EFBIG;

	name = expand_name(p->p_comm, p->p_ucred->cr_uid, p->p_pid);
	if (name == NULL)
		return (EINVAL);
	error = nlookup_init(&nd, name, UIO_SYSSPACE, NLC_LOCKVP);
	if (error == 0)
		error = vn_open(&nd, NULL, O_CREAT | FWRITE | O_NOFOLLOW, S_IRUSR | S_IWUSR);
	kfree(name, M_TEMP);
	if (error) {
		nlookup_done(&nd);
		return (error);
	}
	vp = nd.nl_open_vp;
	nd.nl_open_vp = NULL;
	nlookup_done(&nd);

	vn_unlock(vp);
	lf.l_whence = SEEK_SET;
	lf.l_start = 0;
	lf.l_len = 0;
	lf.l_type = F_WRLCK;
	error = VOP_ADVLOCK(vp, (caddr_t)p, F_SETLK, &lf, 0);
	if (error)
		goto out2;

	/* Don't dump to non-regular files or files with links. */
	if (vp->v_type != VREG ||
	    VOP_GETATTR(vp, &vattr) || vattr.va_nlink != 1) {
		error = EFAULT;
		goto out1;
	}

	VATTR_NULL(&vattr);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	vattr.va_size = 0;
	VOP_SETATTR(vp, &vattr, cred);
	p->p_acflag |= ACORE;
	vn_unlock(vp);

	error = p->p_sysent->sv_coredump ?
		  p->p_sysent->sv_coredump(p, vp, limit) : ENOSYS;

out1:
	lf.l_type = F_UNLCK;
	VOP_ADVLOCK(vp, (caddr_t)p, F_UNLCK, &lf, 0);
out2:
	error1 = vn_close(vp, FWRITE);
	if (error == 0)
		error = error1;
	return (error);
}

/*
 * Nonexistent system call-- signal process (may want to handle it).
 * Flag error in case process won't see signal immediately (blocked or ignored).
 */
/* ARGSUSED */
int
sys_nosys(struct nosys_args *args)
{
	ksignal(curproc, SIGSYS);
	return (EINVAL);
}

/*
 * Send a SIGIO or SIGURG signal to a process or process group using
 * stored credentials rather than those of the current process.
 */
void
pgsigio(struct sigio *sigio, int sig, int checkctty)
{
	if (sigio == NULL)
		return;
		
	if (sigio->sio_pgid > 0) {
		if (CANSIGIO(sigio->sio_ruid, sigio->sio_ucred,
		             sigio->sio_proc))
			ksignal(sigio->sio_proc, sig);
	} else if (sigio->sio_pgid < 0) {
		struct proc *p;

		lockmgr(&sigio->sio_pgrp->pg_lock, LK_EXCLUSIVE);
		LIST_FOREACH(p, &sigio->sio_pgrp->pg_members, p_pglist) {
			if (CANSIGIO(sigio->sio_ruid, sigio->sio_ucred, p) &&
			    (checkctty == 0 || (p->p_flag & P_CONTROLT)))
				ksignal(p, sig);
		}
		lockmgr(&sigio->sio_pgrp->pg_lock, LK_RELEASE);
	}
}

static int
filt_sigattach(struct knote *kn)
{
	struct proc *p = curproc;

	kn->kn_ptr.p_proc = p;
	kn->kn_flags |= EV_CLEAR;		/* automatically set */

	/* XXX lock the proc here while adding to the list? */
	SLIST_INSERT_HEAD(&p->p_klist, kn, kn_selnext);

	return (0);
}

static void
filt_sigdetach(struct knote *kn)
{
	struct proc *p = kn->kn_ptr.p_proc;

	SLIST_REMOVE(&p->p_klist, kn, knote, kn_selnext);
}

/*
 * signal knotes are shared with proc knotes, so we apply a mask to 
 * the hint in order to differentiate them from process hints.  This
 * could be avoided by using a signal-specific knote list, but probably
 * isn't worth the trouble.
 */
static int
filt_signal(struct knote *kn, long hint)
{
	if (hint & NOTE_SIGNAL) {
		hint &= ~NOTE_SIGNAL;

		if (kn->kn_id == hint)
			kn->kn_data++;
	}
	return (kn->kn_data != 0);
}
