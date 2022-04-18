import sys, os, argparse
import logging

import ctypes
import pefile
import subprocess
import time

from platform import uname


KUSER_SHARED_DATA = 0x7FFE0000
def check_kernel_mode_dbg():
    if ctypes.windll.kernel32.IsBadReadPtr(KUSER_SHARED_DATA, 0x3B8):
        logging.error("KUSER_SHARED_DATA is not available")
    else:
        val = ctypes.cast(KUSER_SHARED_DATA + 0x2D4, ctypes.POINTER(ctypes.c_int))
        print(val.values)


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s; %(name)s; %(levelname)s; %(message)s',
    handlers=[
        logging.StreamHandler()
    ])
log = logging.getLogger()


def follow_and_wait(fn, p):
    offset = 0

    while not os.path.exists(fn):
        try:
            p.wait(0.1)
            return
        except subprocess.TimeoutExpired:
            pass

    fp = open(fn, 'r')
    while True:
        line = fp.readline().strip()
        if not line:
            try:
                p.wait(0.1)
                return
            except subprocess.TimeoutExpired:
                pass
            continue

        yield line

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", dest="verbose_count",
                    action="count", default=0)
    parser.add_argument('-m','--module', default='PinUnpack')

    parser.add_argument('-a', '--arg')
    parser.add_argument('--dbg', action='store_true')
    parser.add_argument('filename')
    args = parser.parse_args()
    log.setLevel(max(2 - args.verbose_count, 1) * 10)

    pin_path = 'C:\\pin\\pin.exe'
    if 'Microsoft' in uname().release:
        pin_path = '/mnt/c/pin/pin.exe'

    script_path = os.path.dirname(os.path.abspath(__file__))

    target_fn = args.filename
    pe = pefile.PE(target_fn)

    print(f'{pe.FILE_HEADER.Machine:x}')
    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
        bit = '32'
    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
        bit = '64'
    else:
        raise Exception(f'Machine {pe.FILE_HEADER.Machine:x} is not supported')

    module = f'{args.module}{bit}.dll'
    log_fn = f'{target_fn}.log'

    # path to pin.exe
    cli = [pin_path, ]
    
    # Debug we setup pause_tool switch
    if args.dbg:
        cli += ['-pause_tool', '30']

    # Set tool module and options
    cli += ['-t', os.path.join(script_path, module), '-o', log_fn]

    # Finish pin.exe switch
    cli += ['--', ]

    # Target exe/argv
    if pe.is_dll():
        cli += [os.path.join(script_path, f'dll_load{bit}.exe'), target_fn]
    else:
        cli += [target_fn]

    if args.arg:
        cli += args.arg.split(' ')

    print(cli)
    p = subprocess.Popen(cli)
                         #stdin=subprocess.STDIN, 
                         #stdout=subprocess.STDOUT, 
                         #stderr=subprocess.STDOUT)
    p.communicate()

    for log in follow_and_wait(log_fn, p):
        print(log)

    #print(open(log_fn, 'r').read())