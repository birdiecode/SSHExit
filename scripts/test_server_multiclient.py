#!/usr/bin/env python3
"""Run only inside a disposable Linux network/mount namespace, as network admin.

Exercises production-generated shell against real TUN, routing and nftables.
Uses raw IP/UDP packets through each TUN and a separate peer network namespace.
No Android or SSH transport is mocked into a successful integration result.
"""
import fcntl
import ipaddress
import os
from pathlib import Path
import queue
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
PEER = 'sshexit-integration-peer'
CLASS = 'ru.birdiecode.ssh2socks4android.ServerPlanFixture'

def run(*args, check=True, **kwargs):
    return subprocess.run(args, check=check, text=True, capture_output=True, **kwargs)

def checksum(data):
    if len(data) % 2: data += b'\0'
    value = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while value >> 16: value = (value & 65535) + (value >> 16)
    return (~value) & 65535

class Client:
    def __init__(self, classes, unit, env=None, lease_seconds=60):
        self.unit = unit
        self.name = 'tun' + str(unit)
        self.table = 'ssh2socks_' + format(unit, '012x')
        self.fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
        fcntl.ioctl(self.fd, 0x400454ca, struct.pack('16sH', self.name.encode(), 0x1001))
        self.script = run('java', '-cp', str(classes), CLASS, str(unit), self.table).stdout
        self.ip4 = self.script.split('# CLIENT4=')[1].splitlines()[0]
        self.ip6 = self.script.split('# CLIENT6=')[1].splitlines()[0]
        self.script = self.script.replace('timeout 60 ', 'timeout %d ' % lease_seconds)
        self.proc = subprocess.Popen(['sh', '-c', self.script], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, bufsize=1, env=env)
        self.events = queue.Queue(); self.log = []
        def reader():
            for line in self.proc.stdout:
                self.log.append(line.strip()); self.events.put(line.strip())
            self.events.put(None)
        self.reader = threading.Thread(target=reader, daemon=True)
        self.reader.start()
        self.last_beat = 0

    def ready(self):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            line = self.events.get(timeout=10)
            if line == 'SSH2SOCKS_TUN_READY': return
            if line is None:
                raise AssertionError('Setup failed: ' + '\n'.join(self.log) + self.proc.stderr.read())
        raise AssertionError('Setup timed out')

    def beat(self):
        try:
            self.proc.stdin.write('alive\n'); self.proc.stdin.flush()
        except BrokenPipeError:
            self.proc.wait(timeout=5); self.reader.join(timeout=1)
            raise AssertionError('Lease closed for %s: %s; stderr: %s' % (self.unit, self.log, self.proc.stderr.read()))

    def stop(self):
        if self.proc.poll() is None:
            self.proc.stdin.write('stop\n'); self.proc.stdin.flush()
        self.proc.wait(timeout=8)
        self.reader.join(timeout=1)
        assert 'SSHEXIT_CLEANUP_DONE' in self.log, self.log

    def exchange(self, v6=False):
        self.beat()
        src = socket.inet_pton(socket.AF_INET6 if v6 else socket.AF_INET, self.ip6 if v6 else self.ip4)
        dst = socket.inet_pton(socket.AF_INET6 if v6 else socket.AF_INET, 'fd00:200::2' if v6 else '10.200.0.2')
        payload = ('client-%d-%s' % (self.unit, v6)).encode()
        udp = struct.pack('!HHHH', 41000, 40000, 8+len(payload), 0) + payload
        if v6:
            pseudo = src + dst + struct.pack('!I3xB', len(udp), 17)
            csum = checksum(pseudo + udp) or 65535
            udp = udp[:6] + struct.pack('!H', csum) + udp[8:]
            header = struct.pack('!IHBB', 6<<28, len(udp), 17, 64) + src + dst
        else:
            header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(udp), 1, 0, 64, 17, 0, src, dst)
            header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
        os.write(self.fd, header + udp)
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if not select.select([self.fd], [], [], .1)[0]: continue
            packet = os.read(self.fd, 65536)
            if packet.endswith(payload):
                if v6: assert packet[24:40] == src
                else: assert packet[16:20] == src
                return
        raise AssertionError('No actual UDP reply for ' + str((self.unit, v6)))

def main():
    assert os.geteuid() == 0, 'Needs network administration inside an isolated namespace'
    for command in ['ip', 'nft', 'timeout', 'javac', 'java']: assert shutil.which(command), command
    source = ROOT/'app/src/main/java/ru/birdiecode/ssh2socks4android'
    clients = []; echo = None
    with tempfile.TemporaryDirectory() as tmp:
        classes = Path(tmp)/'classes'; classes.mkdir()
        run('javac', '-d', str(classes), *(str(source/n) for n in [
            'Profile.java','VpnRouteTable.java','TunAddressPlan.java','ServerTunConfiguration.java']),
            str(ROOT/'scripts/ServerPlanFixture.java'))
        try:
            run('ip','link','set','lo','up')
            run('ip','netns','add',PEER)
            run('ip','link','add','wan0','type','veth','peer','name','peer0')
            run('ip','link','set','peer0','netns',PEER)
            run('ip','addr','add','10.200.0.1/24','dev','wan0')
            run('ip','-6','addr','add','fd00:200::1/64','dev','wan0','nodad')
            run('ip','link','set','wan0','up')
            run('ip','-n',PEER,'link','set','lo','up')
            run('ip','-n',PEER,'addr','add','10.200.0.2/24','dev','peer0')
            run('ip','-n',PEER,'-6','addr','add','fd00:200::2/64','dev','peer0','nodad')
            run('ip','-n',PEER,'link','set','peer0','up')
            run('ip','-n',PEER,'route','add','default','via','10.200.0.1')
            run('ip','-n',PEER,'-6','route','add','default','via','fd00:200::1')
            run('nft','add','table','inet','foreign_sentinel')
            echo_code = '''import socket,select
s4=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s4.bind(('10.200.0.2',40000))
s6=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s6.bind(('fd00:200::2',40000))
print('READY',flush=True)
while True:
 for s in select.select([s4,s6],[],[])[0]:
  data,addr=s.recvfrom(65535);s.sendto(data,addr)
'''
            echo = subprocess.Popen(['ip','netns','exec',PEER,'python3','-u','-c',echo_code], stdout=subprocess.PIPE,text=True)
            assert echo.stdout.readline().strip() == 'READY'
            for unit in [1000001,1000002,1000003]:
                client=Client(classes,unit,lease_seconds=2 if unit==1000003 else 60)
                clients.append(client); client.ready()
            assert len({c.ip4 for c in clients}) == len({c.ip6 for c in clients}) == 3
            time.sleep(.2)
            for c in clients: c.exchange(); c.exchange(True)
            clients[0].stop()
            assert run('nft','list','table','inet',clients[0].table,check=False).returncode != 0
            assert Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() == '1'
            assert Path('/proc/sys/net/ipv6/conf/all/forwarding').read_text().strip() == '1'
            clients[1].exchange(); clients[1].exchange(True)
            # Leave the third control pipe open but send no heartbeats: server lease expires.
            clients[2].proc.wait(timeout=6)
            clients[2].reader.join(timeout=1)
            assert 'SSHEXIT_LEASE_EXPIRED' in clients[2].log
            assert 'SSHEXIT_CLEANUP_DONE' in clients[2].log
            clients[1].exchange(); clients[1].exchange(True)
            # Inject nft setup failure; real address/route rollback must preserve client 2.
            wrapper=Path(tmp)/'nft'; real_nft=shutil.which('nft')
            wrapper.write_text('#!/bin/sh\n[ "$1" = -f ] && exit 1\nexec '+real_nft+' "$@"\n');wrapper.chmod(0o755)
            env=dict(os.environ,PATH=tmp+os.pathsep+os.environ['PATH'])
            failed=Client(classes,1000004,env=env);clients.append(failed)
            failed.proc.wait(timeout=8);failed.reader.join(timeout=1)
            assert failed.proc.returncode != 0
            assert 'SSHEXIT_CLEANUP_DONE' in failed.log, failed.log
            assert failed.ip4 not in run('ip','-o','addr','show','dev',failed.name).stdout
            assert not run('ip','route','show','exact',failed.ip4+'/32').stdout.strip()
            clients[1].exchange(); clients[1].exchange(True)
            # Reconnect/reuse after cleanup: no duplicate app table or stale addresses.
            os.close(failed.fd); failed.fd=-1
            replacement=Client(classes,1000004);clients.append(replacement);replacement.ready()
            replacement.exchange();replacement.exchange(True);replacement.stop()
            # An existing foreign route must be rejected and left in place.
            conflict=Client(classes,1000005);clients.append(conflict)
            # The process above races setup, so use a separate reserved address before launch below.
            conflict.ready();conflict.stop();os.close(conflict.fd);conflict.fd=-1
            run('ip','route','add',conflict.ip4+'/32','dev','wan0','proto','static')
            denied=Client(classes,1000005);clients.append(denied)
            denied.proc.wait(timeout=8);denied.reader.join(timeout=1)
            assert denied.proc.returncode != 0 and 'SSHEXIT_ADDRESS_CONFLICT' in denied.log
            assert 'wan0' in run('ip','route','show','exact',denied.ip4+'/32').stdout
            clients[1].exchange();clients[1].exchange(True);clients[1].stop()
            run('nft','list','table','inet','foreign_sentinel')
            print('PASS: 3 real IPv4/IPv6 TUN clients, independent stop/expiry, rollback, reconnect and conflict isolation')
        finally:
            for c in clients:
                if c.proc.poll() is None:
                    try:c.stop()
                    except Exception:c.proc.terminate();c.proc.wait(timeout=5)
                if c.fd>=0:os.close(c.fd)
            if echo is not None:echo.terminate();echo.wait(timeout=5)
            run('ip','netns','del',PEER,check=False)

if __name__=='__main__':main()
