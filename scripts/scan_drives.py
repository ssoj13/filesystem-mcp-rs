#!/usr/bin/env python3
"""Index directories one after another through a real filesystem-mcp-rs server.

    python scripts/scan_drives.py D:\\ C:\\
    python scripts/scan_drives.py --state C:\\tmp\\probe-state C:\\some\\dir     # isolated test

Searching never scans, so this is how the index gets built: for each root it sends
`bgnd_scan_ctl start`, waits for the scan to finish while printing progress, then moves on.
Ctrl-C sends `bgnd_scan_ctl stop` for the running root: what was read is kept, and running the
same command again resumes it.

Refuses to run while a server started before the installed exe was replaced is still alive:
such a process may own the scan worker and would run the old code.
"""
import argparse, json, os, subprocess, sys, tempfile, threading, time

DEFAULT_EXE = os.path.expanduser(r'~\.cargo\bin\filesystem-mcp-rs.exe')


class Server:
    def __init__(self, exe, roots, state):
        env = dict(os.environ)
        if state:
            env['FS_MCP_STATE_DIR'] = state
        self.p = subprocess.Popen([exe, *roots], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, env=env, text=True, bufsize=1)
        self.replies, self.n = {}, 0
        threading.Thread(target=self._read, daemon=True).start()
        self.call('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {},
                                 'clientInfo': {'name': 'scan_drives', 'version': '1'}})
        self._send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})

    def _read(self):
        for line in self.p.stdout:
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if 'id' in m:
                self.replies[m['id']] = m

    def _send(self, m):
        self.p.stdin.write(json.dumps(m) + '\n')
        self.p.stdin.flush()

    def call(self, method, params, timeout=60):
        self.n += 1
        i = self.n
        self._send({'jsonrpc': '2.0', 'id': i, 'method': method, 'params': params})
        end = time.time() + timeout
        while i not in self.replies:
            if time.time() > end:
                raise TimeoutError(method)
            time.sleep(0.02)
        return self.replies[i]

    def ctl(self, action, path=None):
        args = {'action': action}
        if path:
            args['path'] = path
        r = self.call('tools/call', {'name': 'bgnd_scan_ctl', 'arguments': args})
        if 'error' in r or r.get('result', {}).get('isError'):
            raise RuntimeError(json.dumps(r.get('error') or r['result'])[:400])
        return r['result']['structuredContent']['scans']


def stale_servers(exe):
    """PIDs of servers that started before `exe` was last replaced."""
    ps = ("Get-Process filesystem-mcp-rs -ErrorAction SilentlyContinue | "
          "ForEach-Object { \"$($_.Id) $($_.StartTime.ToFileTimeUtc())\" }")
    out = subprocess.run(['powershell', '-NoProfile', '-Command', ps], capture_output=True, text=True).stdout
    # FILETIME (100 ns since 1601) of the exe's mtime
    mtime = int((os.path.getmtime(exe) + 11644473600) * 10_000_000)
    return [int(line.split()[0]) for line in out.splitlines() if line.strip() and int(line.split()[1]) < mtime]


def norm(path):
    return path.replace('\\\\?\\', '').rstrip('\\/').lower()


def find(scans, root):
    return next((s for s in scans if norm(s['path']) == norm(root)), None)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('roots', nargs='+', help='directories to index, in order')
    ap.add_argument('--exe', default=DEFAULT_EXE)
    ap.add_argument('--state', help='isolated state dir (a test run); default is the real ~/.filesystem-mcp-rs')
    ap.add_argument('--every', type=float, default=10, help='progress line every N seconds')
    ap.add_argument('--timeout-min', type=float, default=240, help='give up on one root after N minutes')
    args = ap.parse_args()

    if not args.state:
        old = stale_servers(args.exe)
        if old:
            sys.exit(f'refused: servers {old} started before {args.exe} was replaced and may own the scan '
                     'worker with the old code. Restart those sessions first (or pass --state for a test).')
    srv = Server(args.exe, args.roots, args.state)
    print(f'server pid {srv.p.pid}, {args.exe}', flush=True)
    results = []
    current = None
    try:
        for root in args.roots:
            current = root
            t0 = time.time()
            srv.ctl('start', root)
            print(f'\n== {root}: started', flush=True)
            last = 0
            while True:
                time.sleep(1)
                scan = find(srv.ctl('status'), root)
                if scan is None:
                    continue
                state, progress = scan['state'], scan.get('progress') or {}
                if time.time() - last >= args.every:
                    last = time.time()
                    print(f"   {time.time() - t0:6.0f}s {state:9} entries={progress.get('entriesSeen', 0):>9} "
                          f"dirs={progress.get('dirsSeen', 0):>8}  {str(progress.get('currentPath', ''))[-70:]}",
                          flush=True)
                if state in ('ready', 'partial'):
                    took = time.time() - t0
                    results.append((root, state, progress.get('entriesSeen', 0), took, scan.get('error')))
                    print(f"== {root}: {state} in {took:.0f}s, {progress.get('entriesSeen', 0)} entries"
                          + (f", {scan['error']}" if scan.get('error') else ''), flush=True)
                    break
                if time.time() - t0 > args.timeout_min * 60:
                    srv.ctl('stop', root)
                    results.append((root, 'timeout (stopped, resumable)', progress.get('entriesSeen', 0), time.time() - t0, None))
                    print(f'== {root}: timed out after {args.timeout_min} min; stopped, rows kept', flush=True)
                    break
    except KeyboardInterrupt:
        print('\nCtrl-C: stopping the running scan (rows are kept; run again to resume)', flush=True)
        if current:
            try:
                srv.ctl('stop', current)
            except Exception as error:
                print('stop failed:', error)
    finally:
        srv.p.kill()
    print('\nsummary')
    for root, state, entries, took, error in results:
        print(f'  {root:30} {state:28} {entries:>10} entries  {took:7.0f}s')


if __name__ == '__main__':
    main()
