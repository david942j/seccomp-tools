#include <errno.h>
#include <linux/filter.h>
#include <sys/ptrace.h>
#include <sys/signal.h>

#include "ruby.h"

static VALUE
ptrace_geteventmsg(VALUE _mod, VALUE pid) {
  unsigned long val;
  ptrace(PTRACE_GETEVENTMSG, NUM2LONG(pid), NULL, &val);
  return ULONG2NUM(val);  
}

static VALUE
ptrace_peekdata(VALUE _mod, VALUE pid, VALUE addr, VALUE _data) {
  long val = ptrace(PTRACE_PEEKDATA, NUM2LONG(pid), NUM2LONG(addr), NULL);
  return LONG2NUM(val);  
}

static VALUE
ptrace_peekuser(VALUE _mod, VALUE pid, VALUE off, VALUE _data) {
  long val = ptrace(PTRACE_PEEKUSER, NUM2LONG(pid), NUM2LONG(off), NULL);
  return LONG2NUM(val);  
}

static VALUE
ptrace_setoptions(VALUE _mod, VALUE pid, VALUE _addr, VALUE option) {
  if(ptrace(PTRACE_SETOPTIONS, NUM2LONG(pid), NULL, NUM2LONG(option)) != 0)
    perror("ptrace setoptions");
  return Qnil;
}

static VALUE
ptrace_syscall(VALUE _mod, VALUE pid, VALUE _addr, VALUE sig) {
  if(ptrace(PTRACE_SYSCALL, NUM2LONG(pid), NULL, NUM2LONG(sig)) != 0)
    perror("ptrace syscall");
  return Qnil;
}

static VALUE
ptrace_traceme(VALUE _mod) {
  if(ptrace(PTRACE_TRACEME, 0, 0, 0) != 0)
    perror("ptrace traceme");
  return Qnil;
}

static VALUE
ptrace_traceme_and_stop(VALUE mod) {
  ptrace_traceme(mod);
  kill(getpid(), SIGSTOP);
  return Qnil;
}

static VALUE
ptrace_attach(VALUE _mod, VALUE pid) {
  long val = ptrace(PTRACE_ATTACH, NUM2LONG(pid), 0, 0);
  if(val < 0)
    rb_sys_fail(0);
  return Qnil;
}

static VALUE
ptrace_seccomp_get_filter(VALUE _mod, VALUE pid, VALUE index) {
  long count = ptrace(PTRACE_SECCOMP_GET_FILTER, NUM2LONG(pid), NUM2LONG(index), NULL);
  struct sock_filter *filter;
  VALUE result;
  if(count < 0)
    rb_sys_fail(0);
  filter = ALLOC_N(struct sock_filter, count);
  if(ptrace(PTRACE_SECCOMP_GET_FILTER, NUM2LONG(pid), NUM2LONG(index), filter) != count) {
    xfree(filter);
    rb_sys_fail(0);
  }
  result = rb_str_new((const char *)filter, sizeof(struct sock_filter) * count);
  xfree(filter);
  return result;
}

static VALUE
ptrace_detach(VALUE _mod, VALUE pid) {
  long val = ptrace(PTRACE_DETACH, NUM2LONG(pid), 0, 0);
  if(val < 0)
    rb_sys_fail(0);
  return Qnil;
}


void Init_ptrace(void) {
  VALUE mSeccompTools = rb_define_module("SeccompTools");
  /* The module to wrap ptrace syscall */
  VALUE mPtrace = rb_define_module_under(mSeccompTools, "Ptrace");

  /* consts */
  rb_define_const(mPtrace, "EVENT_CLONE", UINT2NUM(PTRACE_EVENT_CLONE));
  rb_define_const(mPtrace, "EVENT_FORK", UINT2NUM(PTRACE_EVENT_FORK));
  rb_define_const(mPtrace, "EVENT_VFORK", UINT2NUM(PTRACE_EVENT_VFORK));
  rb_define_const(mPtrace, "O_TRACECLONE", UINT2NUM(PTRACE_O_TRACECLONE));
  rb_define_const(mPtrace, "O_TRACEFORK", UINT2NUM(PTRACE_O_TRACEFORK));
  rb_define_const(mPtrace, "O_TRACESYSGOOD", UINT2NUM(PTRACE_O_TRACESYSGOOD));
  rb_define_const(mPtrace, "O_TRACEVFORK", UINT2NUM(PTRACE_O_TRACEVFORK));

  /* geteventmsg */
  rb_define_module_function(mPtrace, "geteventmsg", ptrace_geteventmsg, 1);
  /* get data */
  rb_define_module_function(mPtrace, "peekdata", ptrace_peekdata, 3);
  /* get registers */
  rb_define_module_function(mPtrace, "peekuser", ptrace_peekuser, 3);
  /* set ptrace options */
  rb_define_module_function(mPtrace, "setoptions", ptrace_setoptions, 3);
  /* wait for syscall */
  rb_define_module_function(mPtrace, "syscall", ptrace_syscall, 3);
  /* wait for its parent to attach */
  rb_define_module_function(mPtrace, "traceme", ptrace_traceme, 0);
  /* stop itself before parent attaching */
  rb_define_module_function(mPtrace, "traceme_and_stop", ptrace_traceme_and_stop, 0);
  /* attach to an existing process */
  rb_define_module_function(mPtrace, "attach", ptrace_attach, 1);
  /* retrieve seccomp filter */
  rb_define_module_function(mPtrace, "seccomp_get_filter", ptrace_seccomp_get_filter, 2);
  /* detach from an existing process */
  rb_define_module_function(mPtrace, "detach", ptrace_detach, 1);
}

