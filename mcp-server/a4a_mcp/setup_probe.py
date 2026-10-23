"""Bounded local stdio diagnostics; no identity, socket or native-host claim."""
import json
from pathlib import Path
import queue
import subprocess
import threading
import uuid

from .setup_storage import child_environment


def probe_stdio(python, state_root):
    home = Path(state_root) / ('diagnostic-uncreated-' + uuid.uuid4().hex)
    # Windows asyncio uses loopback sockets for its internal wake-up pipe.
    # Allow that plumbing, reject external destinations and the test relay.
    bootstrap = '''import sys
def guard(event, arguments):
    if event in ('subprocess.Popen', 'os.system'):
        raise RuntimeError('subprocess denied in local diagnostic')
    if event in ('socket.connect', 'socket.bind', 'socket.sendto'):
        address = arguments[-1]
        if isinstance(address, tuple) and (address[0] not in ('127.0.0.1', '::1') or address[1] == 1):
            raise RuntimeError('external network and relay denied in local diagnostic')
    if event == 'socket.getaddrinfo' and arguments[0] not in ('127.0.0.1', '::1'):
        raise RuntimeError('external name resolution denied in local diagnostic')
sys.addaudithook(guard)
from a4a_mcp.__main__ import cli_main
sys.argv = ['a4a-mcp']
cli_main()
'''
    env = child_environment({'A4A_HOME': str(home), 'A4A_RELAY': 'ws://127.0.0.1:1',
        'A4A_MCP_TRANSPORT': 'stdio', 'A4A_MANDATE_AUTO': '0', 'A4A_MCP_CHANNEL': '',
        'A4A_PUBLIC_TEXT': 'deny', 'PYTHONDONTWRITEBYTECODE': '1'})
    responses = queue.Queue(maxsize=64)
    process = subprocess.Popen([str(python), '-I', '-c', bootstrap],
        cwd=state_root, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, encoding='utf-8', bufsize=1)

    def reader():
        try:
            while True:
                line = process.stdout.readline(1024 * 1024 + 1)
                if not line:
                    break
                if len(line) > 1024 * 1024:
                    raise ValueError('diagnostic output limit exceeded')
                responses.put_nowait(json.loads(line))
        except (ValueError, queue.Full, OSError):
            try:
                responses.put_nowait({'diagnostic_error': True})
            except queue.Full:
                pass
        finally:
            try:
                responses.put_nowait({'diagnostic_eof': True})
            except queue.Full:
                pass

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()

    def request(message):
        process.stdin.write(json.dumps(message) + '\n')
        process.stdin.flush()
        if 'id' not in message:
            return None
        for _ in range(64):
            response = responses.get(timeout=20)
            if not isinstance(response, dict) or response.get('diagnostic_error') or response.get('diagnostic_eof'):
                raise ValueError('local stdio diagnostic terminated or produced invalid output')
            if response.get('id') == message['id']:
                if 'error' in response or 'result' not in response:
                    raise ValueError('local stdio diagnostic request failed')
                return response['result']
        raise ValueError('local stdio diagnostic response limit exceeded')

    try:
        request({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
            'protocolVersion': '2025-11-25', 'capabilities': {},
            'clientInfo': {'name': 'a4a-local-doctor', 'version': '1'}}})
        request({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        tools = request({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}})
        names = {t['name'] for t in tools['tools']}
        if not {'a4a_my_address', 'a4a_inbox_status'} <= names:
            raise ValueError('expected A4A tools are missing')
        status = request({'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {
            'name': 'a4a_inbox_status', 'arguments': {}}})
        if status.get('isError'):
            raise ValueError('read-only local inbox status failed')
    except queue.Empty:
        raise ValueError('local stdio diagnostic timed out') from None
    finally:
        try:
            process.stdin.close()
        except OSError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        thread.join(timeout=2)
        process.stdout.close()
    if home.exists():
        raise ValueError('local diagnostic unexpectedly created profile state; retained for inspection')
    if process.returncode:
        raise ValueError('local stdio diagnostic server exited unsuccessfully')
    return {'transport': 'stdio', 'tool_count': len(names),
            'read_only_status_verified': True, 'identity_created': False,
            'network_access': 'external network and relay denied; asyncio loopback permitted',
            'native_host_verified': False}
