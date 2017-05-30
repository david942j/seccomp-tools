#include <sys/ptrace.h>
#include <sys/signal.h>

#include "ruby.h"

static VALUE
ptrace_geteventmsg(VALUE _mod, VALUE pid) {
  unsigned long val;
  ptrace(PTRACE_GETEVENTMSG, NUM2LONG(pid), NULL, &val);
  return LONG2NUM(val);  
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


void Init_ptrace(void) {
  VALUE mSeccompTools = rb_define_module("SeccompTools");
  VALUE mPtrace = rb_define_module_under(mSeccompTools, "Ptrace");

  rb_define_module_function(mPtrace, "geteventmsg", ptrace_geteventmsg, 1);
  rb_define_module_function(mPtrace, "peekdata", ptrace_peekdata, 3);
  rb_define_module_function(mPtrace, "peekuser", ptrace_peekuser, 3);
  rb_define_module_function(mPtrace, "setoptions", ptrace_setoptions, 3);
  rb_define_module_function(mPtrace, "syscall", ptrace_syscall, 3);
  rb_define_module_function(mPtrace, "traceme", ptrace_traceme, 0);
  rb_define_module_function(mPtrace, "traceme_and_stop", ptrace_traceme_and_stop, 0);
}

