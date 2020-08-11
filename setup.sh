#!/usr/bin/env bash

set -e

USERID=$(whoami)
HOSTNAME=$(hostname | sed -e "s/\.torolab\.ibm\.com//")
RANDFILE=''; for i in {0..31}; do RANDFILE+=$(printf "%x" $(($RANDOM%16)) ); done;

cleanup() {
  RC=$?
  [ ! -z "$TEMP_FILES" ] && /bin/rm -f /tmp/cert.$USERID.$HOSTNAME.$RANDFILE.jcl*
  exit $RC
}

trap "cleanup" ERR EXIT INT TERM QUIT HUP

run_command()
{
  set +e
  COMMAND_OUTPUT=$(eval "$1" 2>&1)
  RC=$?
  if [ $RC -ne 0 ]; then
    echo "***CRITICAL: \"$1\" failed with RC=$RC and output:\n $COMMAND_OUTPUT"
    exit $RC
  fi
  set -e
}

submit_job() {
  JCLFILE=$1
  echo -n "> Submitting jcl ($JCLFILE) and waiting"
 
  JCL_COMMAND="/bin/submit -j ${JCLFILE}"
  run_command "$JCL_COMMAND"
  JOBID=$COMMAND_OUTPUT

  run_command "echo $JOBID | /bin/cut -c1-3"
  JOBNAME="${USERID}X"
 
  if [ $COMMAND_OUTPUT = "JOB" ]; then
    while [ true ]; do
      run_command "/bin/tsocmd \"status ${JOBNAME}($JOBID)\" 2>/dev/null | /bin/awk '{print \$NF}'"
      [ "$COMMAND_OUTPUT" = "EXECUTION" -o "$COMMAND_OUTPUT" = "EXECUTING" ] || break
      echo -n ".";
      sleep 2
    done
    echo "DONE."
  else
    echo "**CRITICAL: Invalid Job ID from command ($JCL_COMMAND)"
    exit 1
  fi
}

cp cert.jcl /tmp/cert.$USERID.$HOSTNAME.$RANDFILE.jcl
/bin/sed -e "s/USERID/$USERID/g" /tmp/cert.$USERID.$HOSTNAME.$RANDFILE.jcl > /tmp/cert.$USERID.$HOSTNAME.$RANDFILE.jcl.2
/bin/sed -e "s/HOSTNAME/$HOSTNAME/g" /tmp/cert.$USERID.$HOSTNAME.$RANDFILE.jcl.2 > /tmp/cert.$USERID.$HOSTNAME.$RANDFILE.jcl
submit_job /tmp/cert.$USERID.$HOSTNAME.$RANDFILE.jcl
