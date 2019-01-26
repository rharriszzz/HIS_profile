# (c) Copyright Rocket Software, Inc. 2018, 2019 All Rights Reserved.

import os
import os.path
import sys
import time
from datetime import datetime
import subprocess
from subprocess import PIPE

command_verbose = True
CONSOLE_NAME="%sC" % os.getenv('USER')
ISSUE_COMMAND='issue_command'
DEFAULT_COMMAND_TIMEOUT=2

HIS_PATHNAME='/tmp/HIS_%s' % os.getenv("USER")
if not os.path.exists(HIS_PATHNAME):
    os.makedirs(HIS_PATHNAME)
    os.chown(HIS_PATHNAME, -1, os.getgid()) # change only the group

def run_command(command, timeout=DEFAULT_COMMAND_TIMEOUT, asidx=None, log=sys.stdout):
    command = [ISSUE_COMMAND, '-console_name', CONSOLE_NAME, '-timeout', "%d" % timeout, '-command', command]
    if asidx:
        command.extend(['-asidx', asidx])
    if command_verbose:
        print("run_command: command=%r" % (command,), flush=True, file=log)
    proc = subprocess.run(command, check=True, stdout=PIPE, stderr=PIPE)
    out, err = (proc.stdout.decode('utf-8'), proc.stderr.decode('utf-8'))
    if command_verbose:
        print("run_command: out=%r" % (out,), flush=True, file=log)
        print("run_command: err=%r" % (err,), flush=True, file=log)
    return (out, err)

def get_his_status(display_results):
    return display_results.split('\n')[1].split()[-1]

def get_his_asidx(display_results):
    return display_results.split('\n')[1].split()[1]

def his_setup(log=sys.stdout):
    out, err = run_command("D HIS", log=log)
    status = get_his_status(out)
    if status == 'ACTIVE':
        raise Exception('HIS is currently active')
    if status == 'IDLE':
        his_asidx = get_his_asidx(out)
    else:
        out, err = run_command("S HIS", log=log)
        his_asidx = err.strip().split('=')[1]
    return his_asidx

his_prefix = None

def his_start(map_asids=None, map_jobnames=None, get_samples=True, path=HIS_PATHNAME, his_asidx=None, log=sys.stdout):
    global his_prefix
    his_prefix = None
    command = "F HIS,BEGIN,CNT=NO"
    if not get_samples:
        command += ",SMP=NO"
    if path:
        command += ",PATH='%s'" % path
    if map_asids:
        command += ",MAP=YES,MAPASID=(%s)" % ','.join(["%04X" % asid for asid in map_asids])
    if map_jobnames:
        command += ",MAP=YES,MAPJOB=(%s)" % ','.join(map_jobnames)
    out, err = run_command(command, asidx=his_asidx, log=log)
    out, err = run_command("D HIS", log=log)
    for line in out.split('\n'):
        if "FILE PREFIX:" in line:
            his_prefix = line.split()[-1]
            break

def his_stop(his_asidx=None, log=sys.stdout):
    global his_prefix
    while True:
        out, err = run_command("F HIS,END", asidx=his_asidx, log=log)
        if out != '': 
            break
        time.sleep(0.1) # one cause is "IEE342I MODIFY   REJECTED-TASK BUSY"
    return his_prefix

def run_his_test(fn, log=sys.stdout, jobnames=None):
    print("%s begin run_his_test %s" % (datetime.now().isoformat('-'), fn))
    his_asidx = his_setup(log=log)
    his_start(his_asidx=his_asidx, map_jobnames=jobnames, log=log)
    try:
        fn()
    except Exception as e:
        traceback.print_exc(file=log)
    result = his_stop(his_asidx=his_asidx, log=log)
    print("%s end run_his_test %s" % (datetime.now().isoformat('-'), fn))
    return result

def get_map_for_asids(asids, log=sys.stdout):
    print("%s begin get_map_for_asids (%s)" % (datetime.now().isoformat('-'), ', '.join(["0x%04X" % (asid,) for asid in asids]))) 
    his_asidx = his_setup(log=log)
    his_start(map_asids=asids, get_samples=False, his_asidx=his_asidx, log=log)
    time.sleep(0.1)
    result = his_stop(his_asidx=his_asidx, log=log)
    print("%s end get_map_for_asids (%s)" % (datetime.now().isoformat('-'), ', '.join(["0x%04X" % (asid,) for asid in asids]))) 
    return result
    
