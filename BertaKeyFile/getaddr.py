from __future__ import absolute_import, print_function, division
import errno
import itertools
import logging
import os
import random
import re
import shutil
import socket
import time
import base64

import utils
import network_checks
import consts

from py2py3 import xmlrpclib, ensure_bytes, PY2, bytes2string


TIMEOUT = 5
PORT_OUT = 39333
PORT_IN = 39334
# TODO: ESXi doesn't seem to handle broadcasts well, need to reconsider this
# SRV_ADDR = ('10.102.23.100', PORT_OUT)
SRV_ADDR = ('<broadcast>', PORT_OUT)

BIND_SERVER_FILE = 'bind_server.txt'
ADDRESS_FILES = ['/etc/berta-server.txt', 'C:\\berta\\berta-server.txt', '/scratch/berta/berta-server.txt', 'berta-server.txt']

log = logging.getLogger(__name__)


def get_bind_file():
    agent_dir = os.environ.get("BERTA_AGENT_DIR", os.path.dirname(os.path.abspath(__file__)))
    var_dir = os.path.join(agent_dir, consts.AGENT_VAR_DIR)
    try:
        os.makedirs(var_dir)
    except OSError as exc:
        if exc.errno != errno.EEXIST or not os.path.isdir(var_dir):
            raise
    return os.path.join(var_dir, BIND_SERVER_FILE)


def init_bind_file(bind_file):
    for etc_file in ADDRESS_FILES:
        if os.path.exists(etc_file):
            shutil.copy2(etc_file, bind_file)
            break


def get_bind_data():
    bind_file = get_bind_file()
    init_bind_file(bind_file)
    if not os.path.isfile(bind_file):
        return {}
    f = open(bind_file)
    try:
        data = f.read()
        bind_data = {}
        for key, value in re.findall("(\w+):(.*)", data):
            bind_data[key.strip()] = value.strip()
    except:
        return {}
    finally:
        f.close()

    # CY: reset host ip
    host_ip = None
    with os.popen("ipconfig /all") as lines:
        ip_flag = False
        for line in lines:
            line = line.strip()
            if line.endswith("(Mgmt):"):
                ip_flag = True

            if ip_flag:
                if line.startswith("IPv4"):
                    host_ip = line.split(":")[1].strip().split("(")[0]
                    break

    bind_data["my_ip"] = host_ip
    f = open(bind_file, 'w')
    data = ""
    for item in bind_data:
        data += str(item) + ': ' + str(bind_data[item]) + '\n'
    f.write(data)
    f.close()

    return bind_data


def get_bind_server():
    bind_data = get_bind_data()
    serv = ''
    if 'ip' in bind_data:
        serv = bind_data['ip']
    return serv


def unbind_server():
    bind_file = get_bind_file()
    if not os.path.exists(bind_file):
        log.info("Bind file does not exist.")
        return False
    bind_data = get_bind_data()
    if 'ip' in bind_data:
        log.info('Removing ip from bind file...')
        #bind_data['ip'] = ''
        data = ""
        for item in bind_data:
            data += str(item) + ': ' + str(bind_data[item]) + '\n'
        f = open(bind_file, 'w')
        f.write(data)
        f.close()
        log.info('Bind ip address removed successfully')
        return True
    else:
        log.warning("Lack of ip address in bind file.")
        return False


def send_get_addr_packet(ip, mac, hostname, bind_server, srv_addr_bcast=SRV_ADDR):
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if bind_server:
            # if bind exist, send only to bind server, otherwise broadcast
            # we need to bind to specific ip: case with multiple interfaces
            # unicast is being sent for each interface over same outgoing port when no bind
            # that generates unwanted auto-discovery machines entries
            src_ip = ip
            dest_addr = (bind_server, PORT_OUT)
            dest_type = 'unicast'
        else:
            src_ip = ip
            dest_addr = srv_addr_bcast
            dest_type = 'broadcast'
            bind_server = ''
            send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # src port does not have to be specified, this is a sending socket, we care
        # only about dst port, additionally linux discards src port when socket is bind to ip
        src_addr = (src_ip, 0)
        send_sock.bind(src_addr)

        # request IP
        data = "give me ip;%s;%s;%s" % (mac, hostname, bind_server)
        data = ensure_bytes(data, "ascii")
        log.info("Sending %s request from %s (mac: %s) to %s.", dest_type, src_addr, mac, dest_addr)
        send_sock.sendto(data, dest_addr)
        log.info("Sending message '%s'..." % data)
    finally:
        send_sock.close()


def _query_potential_servers_over_udp(try_once=False):
    log.info("Searching for server's address over UDP...")
    recv_addr = ('', PORT_IN)
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    recv_sock.bind(recv_addr)
    recv_sock.settimeout(TIMEOUT)

    try:
        my_ip = ''
        t0 = 0
        cnt = 0
        data = None
        while not my_ip:
            ip_list = network_checks.get_ip_list()
            cnt += 1
            bind_server = get_bind_server()
            for ip in ip_list:
                mac = network_checks.get_hw_address(ip)
                if not mac:
                    log.info("No MAC address found for %s ip. (Returned %s)" % (ip, mac))
                    continue

                srv_addr_bcast = SRV_ADDR
                if cnt % 2 == 0 and ip.startswith("192.168"):
                    srv_addr_bcast = (".".join(ip.split('.')[:3] + ['255']), PORT_OUT)

                try:
                    send_get_addr_packet(ip, mac, socket.gethostname(), bind_server, srv_addr_bcast)

                    # receive IP
                    data, serv_addr = recv_sock.recvfrom(512)
                    data = data if PY2 else data.decode('ascii')
                    my_ip = ip
                    log.info("got response, responder address %s, data: '%s'", serv_addr, data[:25])
                    break
                except socket.timeout:
                    log.debug("Receive timeout. No server connection on %s ip. Retrying..." % ip)
                    continue
                except KeyboardInterrupt:
                    log.exception("Interrupted by user")
                    raise
                except:
                    log.exception("unexpected exception")
                    continue
                finally:
                    t0 += TIMEOUT

            if try_once:
                break

            # Broadcast after second unsuccessful try
            if not my_ip and cnt % 3 == 0:
                unbind_server()  # Delete ip from file if our old server do not respond
            if not my_ip and t0 > consts.NETWORK_TIMEOUT * 60:
                log.debug("Get server address timeout.")
                unbind_server()  # Delete ip from file if our old server do not respond
                return my_ip, None
            if not ip_list:
                time.sleep(1)
                t0 += 1
    finally:
        recv_sock.close()

    return my_ip, data


def _query_current_server_over_xmlrpc(bind_data):
    my_mac = bind_data['my_mac'].lower()

    # get bind data from server
    log.info("Searching for server's address over XML-RPC...")
    log.info('bind data from file: %s', bind_data)
    url = 'http://%s:%s' % (bind_data['ip'], bind_data['ctrl_port'])
    server = xmlrpclib.Server(url, allow_none=True)
    socket.setdefaulttimeout(20)
    try:
        data = server.get_bind_data(my_mac)
    except:
        log.exception('IGNORED EXCEPTION')
        data = None
    socket.setdefaulttimeout(None)

    if not data:
        log.info('no data received')

    # get my ip
    my_ip = None
    for net_info in network_checks.get_network_list():
        if net_info.mac_address.lower() == my_mac.lower():
            my_ip = net_info.address

    if not my_ip:
        log.info('my_ip not found for mac %s', my_mac)

    return data, my_ip


def _get_regexp_and_value(data, key):
    find_re = re.compile('\n{0}: (\S+)\n'.format(key))
    match = find_re.search(data)
    if not match:
        return data, False
    v = match.group(1)
    return find_re, v


def _decode_line(data, key):
    find_re, v = _get_regexp_and_value(data, key)
    return find_re.sub('\n{0}: {1}\n'.format(key, bytes2string(base64.b64decode(v))), data)


def get_addr(try_once=False):
    bind_file = get_bind_file()
    bind_data = get_bind_data()
    data = my_ip = None

    # Check if xml-rpc path is available.
    if 'ctrl_port' in bind_data and 'my_mac' in bind_data and 'ip' in bind_data:
        try:
            data, my_ip = _query_current_server_over_xmlrpc(bind_data)
        except:
            log.exception('xml rpc getaddr not supported on this system')

    if not data or not my_ip:
        my_ip, data = _query_potential_servers_over_udp(try_once)

    if not data:
        return None

    def file_lines():
        fragile_fields = ('smb_password', 'smb_user', 'db')  # security
        for key, value in (m.groups() for m in re.finditer('(\w+):(.*)', data)):
            if key in fragile_fields:
                continue
            yield '{0}: {1}'.format(key, value.strip())

    os.environ[consts.AGENT_BERTA_IP_ENV] = my_ip
    utils.fwrite(bind_file, '\n'.join(file_lines()))
    _, password_encoded = _get_regexp_and_value(data, 'encode_smb_pass')

    if password_encoded == "True":
        log.info("smb_pass encoded. Decoding")
        data = _decode_line(data, 'smb_password')

    return data


def get_my_ip_address(db_url):
    """
    Grabs IP from env var created by getaddr or
    connects a dummy socket to the database (which is
    expected to be most reliable and always up) to check which
    of our IPs we're seen as.
    """
    my_ip = os.environ.get(consts.AGENT_BERTA_IP_ENV, '')
    if my_ip:
        log.info('Got ip from file: %s' % my_ip)
        return my_ip

    m = re.search("mysql://.*@(.*)/", db_url)
    db_ip = m.group(1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((db_ip, 3306))
    except socket.error:
        log.exception("Cannot connect to database server (%s)", db_ip)
        raise
    my_ip = s.getsockname()[0]
    s.close()
    return my_ip


def get_srv_address():
    """
    This gets various addresses from the controller.
    IP:CTRL_PORT is controller's XML-RPC interface
    IP:PORT is the manager's  (not used here?)
    DB is database address that we use for own ip resolving only
    SMB - samba share path, e.g. \\123.45.56.78\share
    SMB_USER, SMB_PASSWORD - credentials for samba share
    LOGSTASH - ip of logstash logging service
    """
    data = get_addr()
    if data is None:
        raise utils.NetworkError("Network timeout")
    addr = {}
    for key, value in re.findall("(\w+):(.*)", data):
        addr[key.strip()] = value.strip()
    return addr


def setup_mng_iface():
    """Used to bring up management interface.

    Management interface is the one, target communicates over with berta
    server. This method will list all the interfaces in the system, create
    configuration file for each and bring it up with DHCP enabled. Then try
    communicate with berta. The correct interface is left up, all the other
    ones are brought down and configuration files deleted. This method do
    not touch configuration files that are already present.

    :return:
    """
    if_data = {}
    my_eth = ''
    t_end = time.time() + 600
    for count in itertools.count():
        # using exponential timeout increase to reduce network traffic
        exp_timeout = 2 ** count - 1
        log.debug('Waiting %s sec for next rotation...', exp_timeout)
        time.sleep(exp_timeout)
        ip_list = network_checks.get_network_list(True)
        random.shuffle(ip_list)
        for net_info in ip_list:
            eth = net_info.interface
            log.debug('Trying %s...', eth)
            data = get_addr(True)
            if not data:
                if not eth in if_data:
                    cfg_file = network_checks.create_iface_cfg_file(eth)
                    if cfg_file:
                        if_data[eth] = cfg_file
                log.debug('Enabling %s ...', eth)
                network_checks.up_iface(eth)
                time.sleep(2)
                data = get_addr(True)

            if data:
                for new_info in network_checks.get_network_list():
                    if new_info.address == os.environ[consts.AGENT_BERTA_IP_ENV]:
                        my_eth = new_info.interface
                        break
                for e, path in if_data.items():
                    # delete only cfg created by this method
                    if os.path.isfile(path) and e != my_eth:
                        network_checks.down_iface(e)
                        log.debug("Cleanup: deleting %s", path)
                        os.remove(path)
                break

        if my_eth:
            break

        log.debug('No connection - disabling interfaces...')
        for addr in ip_list:
            network_checks.down_iface(addr[4])
        if count == 1:
            unbind_server()
        if time.time() > t_end:
            return
    if if_data:
        network_checks.reset_iface(my_eth)
        while not get_addr(True):
            network_checks.reset_iface(my_eth)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(name)12s (%(lineno)4d): %(levelname)-8s %(message)s')
    # echo ip to stdout
    setup_mng_iface()
    addr_data = get_addr()
    print(addr_data)
