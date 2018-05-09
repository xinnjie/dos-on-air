import json
import pprint
import re
import time
import os
import select
import socket


import sys

from pty_process import PtyProcess


# HOST = 'localhost'
# PORT = 12346
#
# listen_sock =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# listen_sock.bind((HOST, PORT))
# listen_sock.listen(1)
# command_conn, addr = listen_sock.accept()

class DosOnAir:
    """
    调用 debug() 等方法可以对 dos进行相应操作，但是大部分函数本身并不没有返回值，无法直接得知操作引起的影响
    所有操作结果都会被保存在 command_out 中，
    程序本身的输出会保存在 result_out 中
    """
    trace_pat = re.compile(
        r'''
        (?P<regesters>  # registers
        AX=(?P<AX>\w{4}) \s+
        BX=(?P<BX>\w{4}) \s+
        CX=(?P<CX>\w{4}) \s+
        DX=(?P<DX>\w{4}) \s+
        SP=(?P<SP>\w{4}) \s+
        BP=(?P<BP>\w{4}) \s+
        SI=(?P<SI>\w{4}) \s+
        DI=(?P<DI>\w{4}) \s+
        DS=(?P<DS>\w{4}) \s+
        ES=(?P<ES>\w{4}) \s+
        SS=(?P<SS>\w{4}) \s+
        CS=(?P<CS>\w{4}) \s+
        IP=(?P<IP>\w{4})) \s+
        (?P<flags>\w{2}\s\w{2}\s\w{2}\s\w{2}\s\w{2}\s\w{2}\s\w{2}\s\w{2})\s+   #flags
        (?P<address>\w{4}:\w{4}) \s
        (?P<instruct_raw>\w+) \s+
        (?P<instruct>\w+\s+[\w,]+)\s*''',
        flags=re.DOTALL | re.VERBOSE)

    asm_pat = re.compile(
        r'''
        (?P<address>\w{4}:\w{4}) \s+ 
        (?P<instrcuct_raw>\w+)	\s+ # raw instruction in hex
        (?P<instruct>\w+\s+[\w,]+) \s*
        ''',
        flags=re.DOTALL | re.VERBOSE
    )

    def __init__(self, dos_files:str, dos_disk:str, delay=0.05) -> None:
        super().__init__()
        self.dos_files = dos_files
        self.dos_disk = dos_disk
        command = "qemu-system-i386 -hda {} -m 16 -k en-us -rtc base=localtime -drive file=fat:rw:{} -boot order=c -nographic".format(self.dos_disk, self.dos_files)
        self.dos = PtyProcess.spawn(command.split())
        self.fd = self.dos.fd
        self.delay = delay
        self.init_dos()

        self.debug_state = False
        self.command_out = []
        self.result_out = ''

    def init_dos(self):
        # 不能用 not self.dos.expect() 如果匹配到第一个 pattern，会返回0，零 在 not 0 返回的还是 True,会陷入死循环
        while self.dos.expect_exact('C:\>') is None:
            time.sleep(self.delay)
            self.dos.read()

        self.dos.send_one_by_one('d:\r')
        while self.dos.expect_exact('D:\>') is None:
            time.sleep(self.delay)
            self.dos.read()

    def debug(self, exe_file):
        assert not self.debug_state
        exe_file = os.path.split(exe_file)[1]
        if not os.path.exists(os.path.join(self.dos_files, exe_file)):
            raise FileNotFoundError(exe_file + ' not found in ', self.dos_files)
        self.dos.send_one_by_one('bin\debug.com {}\r'.format(exe_file))
        self.debug_state = True

    def step(self, n=None):
        assert self.debug_state
        if not n:
            n = ''
        else:
            assert n > 0
        self.dos.send_one_by_one('t {} \r'.format(n))
        # todo 假如 step 过程中汇编程序有要求输入并阻塞，会造成死锁（expect 过程中不读取键盘输入数据）

    def register(self):
        """
        show current registers state
        :return:
        """
        assert self.debug_state
        self.dos.send_one_by_one('r \r')

    # todo 可支持修改特定寄存器

    def display_data(self, from_=None, to=None):
        """
        display data in memery
        :param from_: hex
        :param to: hex
        :return:
        """
        assert self.debug_state
        if not from_:
            from_ = ''
        if not to:
            to = ''
        self.dos.send_one_by_one('d {} {}'.format(from_, to))

    def display_asm(self, from_=None, to=None):
        """
        display data in memery
        :param from_:
        :param to:
        :return:
        """
        assert self.debug_state
        if not from_:
            from_ = ''
        if not to:
            to = ''
        self.dos.send_one_by_one('u {} {}'.format(from_, to))

    def check_output(self):
        # 从 buffer 中找出所有的 trace 信息和 asm 信息，并把结果放到 self.command_out 中
        # 并将这些信息从 buffer 中删除
        while True:
            trace_match = re.search(self.trace_pat, self.dos.buff)
            asm_match = re.search(self.asm_pat, self.dos.buff)
            span = None
            if not trace_match and not asm_match:
                break
            elif not trace_match and asm_match :
                asm_dict = asm_match.groupdict()
                span = asm_match.span()
                self.command_out.append(asm_dict)
            else:
                # 因为 trace_pat 是包含 asm_pat 的，所以 trace_pat 匹配成功时 asm_pat 也一定匹配成功:
                trace_dict = trace_match.groupdict()
                span = trace_match.span()
                self.command_out.append(trace_dict)
            if span:
                self.dos.buff = self.dos.buff[0:span[0]] + self.dos.buff[span[1]:]
        self.result_out = self.dos.buff[:]
        if self.result_out.find('Program terminated') != -1:
            self.debug_state = False
        self.dos.buff = ""

    def check_commands(self, data:str or bytes):
        """
        command 结构；
        {"args": ["sample.exe"], "command": "debug"}
        :param data:
        :return:
        """
        if isinstance(data, bytes):
            data = data.decode()
        commands = re.findall('{.*?}', data)
        commands = [json.loads(command) for command in commands]
        for command in commands:
            func = getattr(self, command['command'])
            args = tuple(command['args'])
            func(*args)

    def import_file(self, file_path:str):
        with open(file_path) as inputf, open(os.path.join(self.dos_files, os.path.split(file_path)[1])) as outputf:
            for line in inputf:
                if line.endswith('\n') and not line.endswith('\r'):
                    outputf.write(line.replace('\n', '\r'))
                else:
                    outputf.write(line)

    def masm(self, asm_file:str):
        asm_file = os.path.split(asm_file)[1]
        if not os.path.exists(os.path.join(self.dos_files, asm_file)):
            raise FileNotFoundError(asm_file + ' not found in ', self.dos_files)
        self.dos.send_one_by_one('bin\masm.exe {}\r'.format(asm_file))
        self.dos.send_one_by_one('\r')
        self.dos.send_one_by_one('\r')
        self.dos.send_one_by_one('\r')
        self.dos.read()
        assert self.dos.expect_exact('D:\>') is not None
        return self.dos.before

    def link(self, obj_file:str):
        obj_file = os.path.split(obj_file)[1]
        if not os.path.exists(os.path.join(self.dos_files, obj_file)):
            raise FileNotFoundError(obj_file + ' not found in ', self.dos_files)
        self.dos.send_one_by_one('bin\link.exe {}\r'.format(obj_file))
        self.dos.send_one_by_one('\r')
        self.dos.send_one_by_one('\r')
        self.dos.send_one_by_one('\r')
        assert self.dos.expect_exact('D:\>') is not None
        return self.dos.before


def dos_loop(command_fd,  stdin_fd, dos_files:str, dos_disk:str):
    vir = DosOnAir(dos_files, dos_disk)
    print('dos started')
    # vir.debug('sample.exe')
    while True:
        # todo bug! 不挂起一小段时间的话 开机会阻塞一下， select 的 bug?
        time.sleep(0.05)
        # r, w, x = select.select([vir.fd, command_fd], [], [], None)
        r, w, x = select.select([stdin_fd, vir.fd, command_fd], [], [], None)

        if command_fd in r:
            data = os.read(command_fd, 1000)
            vir.check_commands(data)

        elif vir.fd in r:
            # todo bug! 开机第一个提示符总是读不出来 'C:\>', 加上 挂起 0.05 秒后可以解决
            vir.dos.read()
            vir.check_output()
            print(vir.result_out)
            pprint.pprint(vir.command_out)
            vir.result_out = ''
            vir.command_out = []
        elif stdin_fd in r:
            # todo bug! 运行时用 sys.stdin.read(1000)会阻塞，而 debug 时一步一步执行不会阻塞, os.read() 表现正常
            data = os.read(stdin_fd, 1000)
            data = data.replace(b'\n', b'\r')
            vir.dos.send_one_by_one(data)
        else:
            pass
            # data = command_conn.recv(1000)
            # data = data.replace(b'\n', b'\r')
            # # os.write(process.fd, data)
            # write_one_by_one(process.fd, data)

import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='running dos in background')
    parser.add_argument('host', type=str)
    parser.add_argument('command_port', type=int, help='command port')
    parser.add_argument('std_port', type=int, help='std_port represent the file descriptor used as std i/o')
    args = parser.parse_args()

    host = args.host
    command_sock = socket.socket()
    std_sock = socket.socket()
    command_sock.bind((host, args.command_port))
    std_sock.bind((host, args.std_port))
    command_sock.listen(1)
    std_sock.listen(1)

    command_conn, acommand_ddr = command_sock.accept()
    std_conn, std_addr = std_sock.accept()
    # todo stdin_fd 替换掉
    # stdin_fd = sys.stdin.fileno()
    # command_fd = stdin_fd
    dos_loop(command_conn.fileno(), std_conn.fileno(), 'dosfiles', 'dos.disk')



