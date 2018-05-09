import os
import tty

import errno
import pexpect
import select

from format_decorators import FormatDecorators

cwd = os.getcwd()


# enter dos, type: qemu-system-i386 -hda dos.disk -m 16 -k en-us -rtc base=localtime -drive file=fat:rw:dosfiles -boot order=c -nographic

class DosOnAirDebug:
    #  same as DosOnAir
    def __init__(self, dos_files:str, dos_disk:str, log_file=None) -> None:
        super().__init__()
        self.dos_files = dos_files
        self.dos_disk = dos_disk
        self.log_file = log_file
        command = "qemu-system-i386 -hda {} -m 16 -k en-us -rtc base=localtime -drive file=fat:rw:{} -boot order=c -nographic".format(self.dos_disk, self.dos_files)
        self.dos = pexpect.spawn(command, logfile=self.log_file, encoding='utf-8', timeout=10)
        self.init_dos()

        self.debug_state = False

    def init_dos(self):
        self.dos.expect_exact('C:\>', timeout=10)
        self.send('d:\r')
        self.dos.expect_exact('D:\>', timeout=1)

    def debug(self, exe_file):
        assert not self.debug_state
        exe_file = os.path.split(exe_file)[1]
        if not os.path.exists(os.path.join(self.dos_files, exe_file)):
            raise FileNotFoundError(exe_file + ' not found in ', self.dos_files)
        self.send('bin\debug.com {}\r'.format(exe_file))
        self.dos.expect_exact('-', timeout=1)  # -: debug prompt
        self.debug_state = True

    @FormatDecorators.trace_formatter
    def step(self, n=None):
        assert self.debug_state
        if not n:
            n = ''
        else:
            assert n > 0
        self.send('t {} \r'.format(n))
        # todo 假如 step 过程中汇编程序有要求输入并阻塞，会造成死锁（expect 过程中不读取键盘输入数据）
        self.dos.expect_exact('-')
        return self.dos.before

    def register(self):
        """
        show current registers state
        :return:
        """
        assert self.debug_state

        @FormatDecorators.trace_formatter
        def get_register_state():
            self.send('r \r')
            self.dos.expect_exact('-')
            return self.dos.before
        return get_register_state()[0]

    # todo 可支持修改特定寄存器,

    def display_data(self, from_=None, to=None):
        """
        display data in memery
        :param from_: hex
        :param to: hex
        :return:
        """
        if not from_:
            from_ = ''
        if not to:
            to = ''
        self.send('d {} {}'.format(from_, to))
        self.dos.expect_exact('-')
        return self.dos.before

    def display_asm(self, from_=None, to=None):
        """
        display data in memery
        :param from_:
        :param to:
        :return:
        """
        if not from_:
            from_ = ''
        if not to:
            to = ''
        self.send('u {} {}'.format(from_, to))
        self.dos.expect_exact('-')
        return self.dos.before


    # same as DosOnAir
    def close(self):
        self.dos.close()

    # same as DosOnAir
    def send(self, cmd):
        for alphabet in cmd:
            self.dos.send(alphabet)

class DosOnAir:
    def __init__(self, dos_files:str, dos_disk:str, log_file=None) -> None:
        super().__init__()
        self.dos_files = dos_files
        self.dos_disk = dos_disk
        self.log_file = log_file
        command = "qemu-system-i386 -hda {} -m 16 -k en-us -rtc base=localtime -drive file=fat:rw:{} -boot order=c -nographic".format(self.dos_disk, self.dos_files)
        self.dos = pexpect.spawn(command, logfile=self.log_file, encoding='utf-8', timeout=10)
        self.init_dos()
        self.old_buffer = self.dos.string_type()

    def init_dos(self):
        self.dos.expect_exact('C:\>', timeout=10)
        self.send('d:\r')
        self.dos.expect_exact('D:\>', timeout=1)

    def close(self):
        self.dos.close()

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
        self.send('bin\masm.exe {}\r'.format(asm_file))
        self.dos.expect_exact(':')
        self.send('\r')
        self.dos.expect_exact(':')
        self.send('\r')
        self.dos.expect_exact(':')
        self.send('\r')
        self.dos.expect_exact('D:\>')
        return self.dos.before

    def link(self, obj_file:str):
        obj_file = os.path.split(obj_file)[1]
        if not os.path.exists(os.path.join(self.dos_files, obj_file)):
            raise FileNotFoundError(obj_file + ' not found in ', self.dos_files)
        self.send('bin\link.exe {}\r'.format(obj_file))
        self.dos.expect_exact(':')
        self.send('\r')
        self.dos.expect_exact(':')
        self.send('\r')
        self.dos.expect_exact(':')
        self.send('\r')
        self.dos.expect_exact('D:\>')
        return self.dos.before

    # 命令式的
    def run(self, exe_file, timeout=10):
        exe_file = os.path.split(exe_file)[1]
        if not os.path.exists(os.path.join(self.dos_files, exe_file)):
            raise FileNotFoundError(exe_file + ' not found in ', self.dos_files)
        self.send('{}\r'.format(exe_file))
        # 最多 timeout 秒运行时间
        self.dos.expect_exact('D:\>', timeout=timeout)
        return self.dos.before

    def interact(self, exe_file, interval=0.05):
        exe_file = os.path.split(exe_file)[1]
        if not os.path.exists(os.path.join(self.dos_files, exe_file)):
            raise FileNotFoundError(exe_file + ' not found in ', self.dos_files)
        self.send('{}\r'.format(exe_file))

        # # 最快每 interval 输入一个字符
        sys.stdout.write(self.dos.buffer)
        self.old_buffer = self.dos.buffer[:]
        while self.dos.expect_exact(['D:\>', pexpect.TIMEOUT], timeout=interval) == 1:
            self.__interact_impl()

    def __interact_impl(self):
        sys.stdout.write(self.dos.buffer[len(self.old_buffer):])
        self.old_buffer = self.dos.buffer
        mode = tty.tcgetattr(self.dos.STDIN_FILENO)
        tty.setraw(self.dos.STDIN_FILENO)
        try:
            r, w, e = select.select([self.dos.child_fd, self.dos.STDIN_FILENO], [], [])
            if self.dos.child_fd in r:
                try:
                    data = os.read(self.dos.child_fd, 1000)
                    self.dos.buffer += data.decode()

                except OSError as err:
                    if err.args[0] == errno.EIO:
                        # Linux-style EOF
                        raise # raise作为跳转使用
                if data == b'':
                    # BSD-style EOF
                    return
                self.dos._log(data, 'read')
                os.write(self.dos.STDOUT_FILENO, data)
            if self.dos.STDIN_FILENO in r:
                data = os.read(self.dos.STDIN_FILENO, 1000)
                self._log(data, 'send')
                self.__interact_writen(self.dos.child_fd, data)
        finally:
            tty.tcsetattr(self.dos.STDIN_FILENO, tty.TCSAFLUSH, mode)
            # pass

    def _log(self, s, direction):
        # todo: 这边使我自己修改的
        if isinstance(s, bytes):
            s = s.decode()
        if self.dos.logfile is not None:
            self.dos.logfile.write(s)
            self.dos.logfile.flush()
        second_log = self.dos.logfile_send if (direction == 'send') else self.logfile_read
        if second_log is not None:
            second_log.write(s)
            second_log.flush()

    def __interact_writen(self, fd, data):
        '''This is used by the interact() method.
        '''
        while data != b'':
            n = os.write(fd, data)
            data = data[n:]

    def send(self, cmd):
        # print('send: ', cmd.encode())
        for alphabet in cmd:
            self.dos.send(alphabet)

#helper function getch(), from stackoverflow
if os.name == 'nt':
    import msvcrt
    def getch():
        return msvcrt.getch().decode()
else:
    import tty, sys, termios
    def getch():
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            return ch

if __name__ == '__main__':
    dos_files = os.path.join(cwd, 'dosfiles')
    dos_disk = os.path.join(cwd, 'dos.disk')
    with open(os.path.join(cwd, 'dos.log'), 'w') as log_file:
        # dos = DosOnAir(dos_files, dos_disk, log_file)
        # print(dos.masm('sample.asm'))
        # print(dos.link('sample.obj'))
        # dos.interact('sample.exe')
        dos = DosOnAirDebug(dos_files, dos_disk, log_file)
        dos.debug('sample.exe')
        print(dos.step(2))
        print(dos.register())
