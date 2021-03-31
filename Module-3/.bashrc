# .bashrc

# User specific aliases and functions

alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'

# Alias for Storagegrid
sg_cmd() {
  CMD="aws ${@:1} --profile storagegridlab --endpoint-url http://192.168.0.170:10443"
  echo "Executing \"${CMD}\""
  eval ${CMD}
}
alias sg=sg_cmd

# Source global definitions
if [ -f /etc/bashrc ]; then
        . /etc/bashrc
fi
export JAVA_HOME="/usr/"