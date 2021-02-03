#!/usr/bin/python

from abc import ABCMeta, abstractstaticmethod
import time
import pexpect
import re
import json
from flask import Flask, jsonify
from flask_restplus import Api, Resource, fields
from ttp import ttp

app = Flask(__name__)

authorizations = {
    'Basic Auth': {
        'type': 'basic',
        'in': 'header',
        'name': 'Authorization'
    },
}

api = Api(app,
    doc='/',
    version='1.0',
    title='Backbone API',
    description='API de interação com Backbone',
    security='Basic Auth',
    authorizations=authorizations
)

class SystemProfile(object):
    PROMPTLINE = ''
    GET_VERSION = ''
    GET_SWITCH = ''
    GET_PORTS = ''
    GET_PORT = ''
    GET_PORT_BANDWITH = ''
    GET_EAPS = ''
    GET_VPLS = ''
    PAGINATES = False
    VERSION = ''
    DISABLE_PAGINATION = ''
    ESCALATE_COMMAND = ''

class ExtremeOS(SystemProfile):
    PROMPTLINE = '[0-9]+[ ]#'
    GET_VERSION = 'show version'
    GET_SWITCH = 'show switch'
    GET_PORTS = 'show ports no-refresh'
    GET_PORT = 'show ports {0} transceiver information detail'
    GET_EAPS = 'show eaps'
    GET_VPLS = 'show vpls detail'
    GET_PORT_BANDWITH = 'show ports {0} utilization bandwidth'
    PAGINATES = True
    VERSION = 'show version'
    DISABLE_PAGINATION = 'disable clipaging'
    ESCALATE_COMMAND = 'enable'

class JunOS(SystemProfile):
    PROMPTLINE = r'[-\w]+[ #]'
    GET_VERSION = 'show running-config'
    GET_SWITCH = ''
    GET_PORTS = 'show ports'
    GET_PORT = ''
    GET_PORT_BANDWITH = ''
    PAGINATES = True
    VERSION = 'show version'
    DISABLE_PAGINATION = 'terminal length 0'
    ESCALATE_COMMAND = 'enable'

ShowVersionList = {
    'ExtrmeNetworks': ExtremeOS,
    'JuniperNetworks': JunOS, }

HostsIPs = {
    '10.7.0.9': ShowVersionList['ExtrmeNetworks'],
    '10.7.0.8': ShowVersionList['ExtrmeNetworks'],
    '10.7.0.1': ShowVersionList['ExtrmeNetworks'],
}

class SessionError(Exception):
	pass

class SessionDevice:

    def __init__(self, host, port, proto, operatingsystem):
        self.host = host
        self.proto = proto
        self.port = port
        self.operatingsystem = operatingsystem
        self.connected = False

    def __str__(self):
        return self.host + ":" + str(self.port) + " via " + self.proto

    def __telnet_login__(self, connection_args):
        self.connection = pexpect.spawn(connection_args, timeout=15)  # spawns session
        # assigns int to match
        i = self.connection.expect(
            [r"(?i)(username|login)[\s:]+", pexpect.TIMEOUT, r"uthentication failed."])
        if i == 0:  # matched username
            self.connection.sendline(self.username)
            i = self.connection.expect(r"(?i)password[\s:]+")
        if i == 0:  # matched password
            self.connection.sendline(self.password)
            i = self.connection.expect(self.operatingsystem.PROMPTLINE)
            if i == 0:  # matched promptline
                if self.operatingsystem.PAGINATES:  # if OS paginates, disable it
                    self.connection.sendline(self.operatingsystem.DISABLE_PAGINATION)
                    i = self.connection.expect(self.operatingsystem.PROMPTLINE)
                if i == 0:
                    self.connected = True
                    return True
        else:
            self.connected = False
            return False

    def __ssh_login__(self, connection_args):
        self.connection = pexpect.spawn(connection_args, timeout=10)
        i = self.connection.expect(
            ["(?i)are you sure you want to continue connecting", "(?i)password", pexpect.TIMEOUT])

        if i == 0:  # matches the new key warning
            self.connection.sendline("yes")
            i = self.connection.expect(r"(?i)password[\s:]+")

        if i == 1:  # matches password prompt
            self.connection.sendline(self.password)
            i = self.connection.expect(self.operatingsystem.PROMPTLINE)
            if i == 0:  # we should be logged in.
                if self.operatingsystem.PAGINATES:
                    self.connection.sendline(self.operatingsystem.DISABLE_PAGINATION)
                    i = self.connection.expect(self.operatingsystem.PROMPTLINE)
                if i == 0:
                    self.connected = True
                    return True

        if i == 2:
            raise SessionError("Connection Timed out")
        else:
            pass
    def login(self, username, password):
        self.username = username
        self.password = password
        if self.proto == "telnet":
            connection_string = 'telnet -K %s %d' % (self.host, self.port)
            self.__telnet_login__(connection_string)
        elif self.proto == "ssh":
            connection_string = 'ssh -o Port=%d -l %s %s' % (self.port, self.username, self.host)
            self.__ssh_login__(connection_string)
        else:
            pass
        if self.connected:
            return True

    def logout(self):
        self.connection.sendline("exit")
        self.connection.close()
        self.connected = False

    def sendcommand(self, cmd):
        if self.connected:
            self.connection.sendline(cmd)
            escaped_cmd = re.escape(cmd)
            self.connection.expect(escaped_cmd)
            self.connection.expect(self.operatingsystem.PROMPTLINE)
            # print "***", self, cmd + " yielded: *** "
            #if len(self.connection.after) > 0:
            #    idx = self.connection.before.rfind("\r\n")
            #    self.connection.before = self.connection.before[:idx]

            return self.connection.before.strip()
        else:
            raise SessionError("***Not Connected***")

    def getconfig(self):
        if self.connected:
            self.sendcommand(self.operatingsystem.GET_CONFIG)
        else:
            raise SessionError("***Not Connected***")

    def getversion(self):
        if self.connected:
            self.sendcommand(self.operatingsystem.VERSION)
        else:
            raise SessionError("***Not Connected***")

    def escalateprivileges(self, escalated_password=None):
        escalated_password = escalated_password
        if self.connected:
            self.connection.sendline(self.operatingsystem.ESCALATE_COMMAND)
            i = self.connection.expect(r"(?i)password[\s:]+")
            if i == 0:
                self.connection.sendline(escalated_password)
                i = self.connection.expect(self.operatingsystem.PROMPTLINE)
                if i == 0:
                    if "denied" in self.connection.before:
                        print("***Escalation FAILED***")
                        print(self.connection.before)
                    else:
                        print("***Escalation Successful***")
        else:
            raise SessionError("***Not Connected***")

class ICommand(metaclass=ABCMeta):

    @abstractstaticmethod
    def execute(*args):
        pass

class IUndoRedo(metaclass=ABCMeta):

    @abstractstaticmethod
    def history():
        pass


    @abstractstaticmethod
    def undo():
        pass

    @abstractstaticmethod
    def redo():
        pass

class Invoker(IUndoRedo):
    def __init__(self):
        self._commands = {}
        self._history = [(0.0, "OFF", ())]  # A default setting of OFF
        self._history_position = 0  # The position that is used for UNDO/REDO

    @property
    def history(self):
        return self._history

    def register(self, command_name, command):
        self._commands[command_name] = command

    def execute(self, command_name, *args):
        if command_name in self._commands.keys():
            self._history_position += 1
            self._commands[command_name].execute(args)
            if len(self._history) == self._history_position:
                self._history.append((time.time(), command_name, args))
            else:
                self._history = self._history[:self._history_position+1]
                self._history[self._history_position] = {
                    time.time(): [command_name, args]
                }
        else:
            print("Command [{command_name}] not recognised")

    def undo(self):
        pass

    def redo(self):
        pass

class Device:

    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.dicionaryDevice = HostsIPs[self.host]
        self.sessionDevice = SessionDevice(self.host, 23, "telnet", self.dicionaryDevice)
        self.sessionDevice.login(self.username, self.password)

    def noautenticate(self):
        self.sessionDevice.logout()

    def show_version(self):
        return_command = self.sessionDevice.sendcommand(self.dicionaryDevice.GET_VERSION)
        self.noautenticate
        return return_command

    def show_switch(self):
        return_command = self.sessionDevice.sendcommand(self.dicionaryDevice.GET_SWITCH)
        self.noautenticate
        return return_command

    def show_ports(self):
        return_command = self.sessionDevice.sendcommand(self.dicionaryDevice.GET_PORTS)
        self.noautenticate
        return return_command

    def show_eaps(self):
        return_command = self.sessionDevice.sendcommand(self.dicionaryDevice.GET_EAPS)
        self.noautenticate
        return return_command

    def show_vpls(self):
        return_command = self.sessionDevice.sendcommand(self.dicionaryDevice.GET_VPLS)
        self.noautenticate
        return return_command


    def show_port(self, *args):
        a = args[0][0]
        return_command = self.sessionDevice.sendcommand(str(self.dicionaryDevice.GET_PORT).format(a))
        self.noautenticate
        return return_command

    def show_port_bandwith(self, *args):
        a = args[0][0]
        return_command = self.sessionDevice.sendcommand(str(self.dicionaryDevice.GET_PORT_BANDWITH).format(a))
        self.noautenticate
        return return_command

    def create_vlan(self):
        return_command = self.sessionDevice.sendcommand(self.dicionaryDevice.CREATE_VLAN)
        self.noautenticate
        return return_command

class ShowVersion(ICommand):
    def __init__(self, device):
        self._device = device
        self._return_command = ''

    def execute(self, *args):
        self._retun_command = self._device.show_version()

class ShowSwitch(ICommand):
    def __init__(self, device):
        self._device = device
        self._return_command = ''

    def execute(self, *args):
        self._retun_command = self._device.show_switch()

class ShowPorts(ICommand):
    def __init__(self, device):
        self._device = device
        self._return_command = ''

    def execute(self, *args):
        self._retun_command = self._device.show_ports()

class ShowPort(ICommand):
    def __init__(self, device):
        self._device = device
        self._return_command = ''

    def execute(self, *args):
        self._retun_command = self._device.show_port(args[0])

class ShowPortBandwith(ICommand):
    def __init__(self, device):
        self._device = device
        self._return_command = ''

    def execute(self, *args):
        self._retun_command = self._device.show_port_bandwith(args[0])

class ShowEAPS(ICommand):
    def __init__(self, device):
        self._device = device
        self._return_command = ''

    def execute(self, *args):
        self._return_command = self._device.show_eaps()

class ShowVPLS(ICommand):
    def __init__(self, device):
        self._device = device
        self._return_command = ''

    def execute(self, *args):
        self._return_command = self._device.show_vpls()

class CreatVlan(ICommand):
    def __init__(self, device, tag, description, ports):
        self._device = device
        self._return_command = ''

    def execute(self, *args):
        self._retun_command = self._device.create_vlan()

###  API  #################################################################

namespace = api.namespace('devices', description='Operações relacionadas a dispositivos de rede')

@namespace.route('/showversion/<string:host>/', methods=['GET'])
#@namespace.header('Authorization: Bearer', 'JWT TOKEN', required=True)
@namespace.response(404, 'categoria não encontrada.')
class route_show_version_data(Resource):
    def get(self, host):
        """
        Retorna informações de versão do dispositivo: {host}
        """
        DEVICE = Device(host, '********', '***********')
        SHOW_VERSION = ShowVersion(DEVICE)
        INVOKER = Invoker()
        INVOKER.register("DEVICE_VERSION", SHOW_VERSION)
        INVOKER.execute("DEVICE_VERSION")

        ttp_template = """
Switch      : {{ switch }} {{ switch_id }} Rev {{ switch_rev }} BootROM: {{ bootrom }}    IMG: {{ img }}
PSU-1       : {{ psu1 }} A-S6 800386-00-03 {{ psu1_serial }}
Image   : {{ image }} version {{ version }} v1572b9 by release-manager
BootROM : {{ bootrom2 }}
Diagnostics : {{ diagnostics }}
{{ sw }}.
"""
        result_terminal = SHOW_VERSION._retun_command.decode('utf-8')
        result_terminal = "\n".join(result_terminal.split("\r\n"))
        #esult_terminal = result_terminal.split(":")

        parser = ttp(data=result_terminal, template=ttp_template)
        parser.parse()
        results = parser.result(format='json')[0]
        return eval(results), 200

@namespace.route('/showswitch/<string:host>/', methods=['GET'])
class route_show_switch_data(Resource):
    def get(self, host):
        """
        Retorna informações básicas sobre o sobre o elemento: {host}
        """
        DEVICE = Device(host, '*********', '**********')
        SHOW_SWITCH = ShowSwitch(DEVICE)
        INVOKER = Invoker()
        INVOKER.register("DEVICE_SWITCH", SHOW_SWITCH)
        INVOKER.execute("DEVICE_SWITCH")

        result_terminal = SHOW_SWITCH._retun_command.decode('utf-8')
        result_terminal = result_terminal.split("\r\n")

        return result_terminal,  200

@namespace.route('/showports/<string:host>/', methods=['GET'])
class route_show_ports_data(Resource):
    def get(self, host):
        """
        Retorna a listagem de interfaces dos elemento: {host}
        """
        DEVICE = Device(host, '**********', '**********')
        SHOW_PORTS = ShowPorts(DEVICE)
        INVOKER = Invoker()
        INVOKER.register("DEVICE_PORTS", SHOW_PORTS)
        INVOKER.execute("DEVICE_PORTS")

        result_terminal = SHOW_PORTS._retun_command.decode('utf-8')
        result_terminal = result_terminal.split("\r\n")

        return result_terminal, 200

@namespace.route('/showport/<string:host>/<string:port>', methods=['GET'])
class route_show_port_data(Resource):
    def get(self, host, port):
        """
        Retorna detalhes sobre uma porta específica do elemento: {host} {port}
        """
        DEVICE = Device(host, '********', '*********')
        SHOW_PORT = ShowPort(DEVICE)
        INVOKER = Invoker()
        INVOKER.register("DEVICE_PORT", SHOW_PORT)
        INVOKER.execute("DEVICE_PORT", port)

        result_terminal = SHOW_PORT._retun_command.decode('utf-8')
        result_terminal = result_terminal.split("\r\n")

        return result_terminal,  200

@namespace.route('/showportbandwith/<string:host>/<string:port>', methods=['GET'])
class route_show_port_bandwith_data(Resource):
    def get(self, host, port):
        """
        Retorna informações sobre o tráfego na interface - Parâmetros: {host} {port}
        """
        DEVICE = Device(host, '********', '************')
        SHOW_PORT_BANDWITH = ShowPortBandwith(DEVICE)
        INVOKER = Invoker()
        INVOKER.register("DEVICE_PORT_BANDWITH", SHOW_PORT_BANDWITH)
        INVOKER.execute("DEVICE_PORT_BANDWITH", port)

        result_terminal = SHOW_PORT_BANDWITH._retun_command.decode('utf-8')
        result_terminal = result_terminal.split("\r\n")

        return result_terminal,  200

namespace = api.namespace('commands', description='Operações relacionadas a lista de comandos que objetiva executar uma função')

@namespace.route('/description/<string:host>/')
class route_description(Resource):
    def post(self, host):
        return {'teste':'teste'}

@namespace.route('/createvlan/<string:host>/')
class route_create_vlan(Resource):
    def put(self, host):
        return {'teste':'teste'}

@namespace.route('/deletevlan/<string:host>/')
class route_delete_vlan(Resource):
    def delete(self, host):
        return {'teste':'teste'}

namespace = api.namespace('protocols', description='Operações relacionadas a protocolo')

@namespace.route('/eaps/<string:host>/', methods=['GET'])
class route_show_eaps(Resource):
    def get(self, host):
        DEVICE = Device(host, '*********', '**********')
        SHOW_EAPS = ShowEAPS(DEVICE)
        INVOKER = Invoker()
        INVOKER.register("PROTOCOL_EAPS", SHOW_EAPS)
        INVOKER.execute("PROTOCOL_EAPS")

        result_terminal = SHOW_EAPS._return_command.decode('utf-8')
        result_terminal = result_terminal.replace("\r\n", "")
        result_terminal = result_terminal.split(":")

        return result_terminal, 200

@namespace.route('/showvplsstatus/<string:host>/', methods=['GET'])
class route_show_vpls(Resource):
    def get(self, host):
        DEVICE = Device(host, '*********', '*********')
        SHOW_VPLS = ShowVPLS(DEVICE)
        INVOKER = Invoker()
        INVOKER.register("PROTOCOL_VPLS", SHOW_VPLS)
        INVOKER.execute("PROTOCOL_VPLS")

        result_terminal = SHOW_VPLS._return_command.decode('utf-8')
        result_terminal = result_terminal.replace("\r\n", "")
        result_terminal = result_terminal.split(":")

        return result_terminal, 200


if __name__ == "__main__":
    app.run(host="192.168.1.9", port=5000, debug=True)
