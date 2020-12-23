import argparse
import hashlib
import os
import re
import smtplib
import socket
import sys
import logging
import json
from json import JSONDecodeError
from os import path
from subprocess import Popen, PIPE, STDOUT
from typing import Dict, List


class RegexValidator(object):
    EMAIL = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    HOSTNAME_OR_IP: str = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$"

    def __init__(self, pattern, lowercase):
        self._pattern = pattern
        self._lowercase = lowercase

    def __call__(self, value: str):
        if self._lowercase:
            value = value.lower()
        pattern = re.compile(self._pattern)
        if not pattern.match(value):
            raise argparse.ArgumentTypeError(
                "'{}' is not valid - expected pattern: {}".format(value, self._pattern))
        return value


class NonZeroPositiveInt(object):

    def __call__(self, value: str):
        err = "'{}' is not valid - expected non zero, positive integer".format(value)
        try:
            value = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(err)

        if not value > 0:
            raise argparse.ArgumentTypeError(err)
        return value


class JsonFileValidator(object):

    def __call__(self, value: str):
        try:
            with open(value) as json_file:
                data = json.load(json_file)
                return data
        except OSError as e:
            raise argparse.ArgumentTypeError(
                "'{}' cannot be opened to read. error: {}".format(value, e))

        except JSONDecodeError as e:
            raise argparse.ArgumentTypeError(
                "'{}' is not a valid json file. error: {}".format(value, e))


class DataObject(object):

    @staticmethod
    def dict_to_args(data: Dict):
        args = []
        for key, value in data.items():
            if isinstance(value, list) or isinstance(value, Dict):
                continue
            args.append("--" + key)
            args.append(str(value))
        return args

    def assign(self, data: Dict):
        for key, value in data.items():
            self.__dict__[key] = value

    def __str__(self):
        return json.dumps(self.__dict__)


class Smtp(DataObject):

    @staticmethod
    def create_from_dict(data: Dict):
        parser = argparse.ArgumentParser()
        parser.add_argument("--smtp_host", type=RegexValidator(RegexValidator.HOSTNAME_OR_IP, True), required=True)
        parser.add_argument("--smtp_username", type=str, required=True)
        parser.add_argument("--smtp_password", type=str, required=True)
        parser.add_argument("--smtp_port", type=NonZeroPositiveInt(), required=True)
        parser.add_argument("--smtp_from_address", type=RegexValidator(RegexValidator.EMAIL, True), required=True)
        args = DataObject.dict_to_args(data)
        object_data = parser.parse_args(args)
        return Smtp(object_data.__dict__)

    def __init__(self, data: Dict):
        self.smtp_host = None
        self.smtp_username = None
        self.smtp_password = None
        self.smtp_port = None
        self.smtp_from_address = None
        self.assign(data)

    def send_mail(self, to_addrs, subject, text):
        server_addr = self.smtp_host

        # Concatenate addresses and text
        message = ("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n"
                   % (self.smtp_from_address, to_addrs, subject))
        message = message + text

        # Configure the SMTP_SSL protocol and communicate with the server
        server = smtplib.SMTP_SSL(server_addr, self.smtp_port)
        # server.set_debuglevel(1)
        server.ehlo()
        server.login(self.smtp_username, self.smtp_password)
        server.sendmail(self.smtp_from_address, to_addrs, message)
        server.quit()


class Service(DataObject):

    @staticmethod
    def create_from_dict(data: Dict):
        parser = argparse.ArgumentParser()
        parser.add_argument("--name", type=str, required=True)
        parser.add_argument("--enabled", type=bool, required=True)
        parser.add_argument("--address", type=RegexValidator(RegexValidator.HOSTNAME_OR_IP, True), required=True)
        parser.add_argument("--port", type=NonZeroPositiveInt(), required=True)
        parser.add_argument("--message_recipient", type=RegexValidator(RegexValidator.EMAIL, True), required=True)
        args = DataObject.dict_to_args(data)
        object_data = parser.parse_args(args)
        return Service(object_data.__dict__)

    def __init__(self, data: Dict):
        self.name = ""  # type: str
        self.enabled = False  # type: bool
        self.address = ""  # type: str
        self.port = -1  # type: int
        self.message_recipient = ""  # type: str
        self.assign(data)

    def check_and_create_message(self):
        logger = logging.getLogger(__name__)
        if not self.enabled:
            return None, self.message_recipient
        status_file = self._status_file_path()
        was_offline = os.path.exists(status_file)
        was_online = not was_offline
        is_now_online = self._is_online()
        is_now_offline = not is_now_online
        status_changed = (is_now_online and was_offline) or (is_now_offline and was_online)
        message = None
        if status_changed:
            message = "Service '" + self.name + "' on host:port '" + str(self.address) + ":" + str(
                self.port) + "' is {}".format("*ONLINE* again" if is_now_online else "*OFFLINE*")
            if is_now_online:
                os.remove(status_file)
            else:
                with open(status_file, 'a'):
                    os.utime(status_file, None)

            logger.info(message)

        return message, self.message_recipient

    def _is_online(self):
        logger = logging.getLogger(__name__)
        cmd = "nmap -Pn -p %s %s" % (str(self.port), self.address)
        search_term = r"" + str(self.port) + "/tcp open"
        if os.name == 'nt':
            cmd = "powershell -command \"Test-NetConnection -ComputerName %s -Port %s\"" % (
                self.address, str(self.port))
            search_term = r"TcpTestSucceeded\s*?:\s*?True"
        logger.info("command: %s, searchterm: %s" % (cmd, str(search_term)))

        output = App.run_cmd(cmd)
        service_reachable = re.search(search_term, output, re.I) is not None
        logger.debug("output: %s, service_reachable: %s" % (output, str(service_reachable)))
        return service_reachable

    def _status_file_path(self):
        file_basename = hashlib.md5(self.name.encode('utf-8')).hexdigest()
        return os.path.join(App.detect_data_dir(), file_basename)


class Services(object):

    @staticmethod
    def create_from_list(data: Dict):
        if "services" not in data or not isinstance(data["services"], List):
            raise ValueError("services definition not found or not a valid list")

        services = []
        for service_data in data["services"]:
            services.append(Service.create_from_dict(service_data))
        return Services(services)

    def __init__(self, services: List[Service]):
        self.items = services  # type: List[Service]

    def __str__(self):
        data = [i.__dict__ for i in self.items]
        return json.dumps(data)


class App:
    data_dir = None

    @staticmethod
    def run_cmd(cmd):
        close_fds = True
        if os.name == 'nt':
            close_fds = False
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=close_fds)
        output = p.stdout.read()
        return str(output).strip()

    @staticmethod
    def detect_data_dir():
        if App.data_dir is not None:
            return App.data_dir

        app_name = os.path.basename("PyServiceChecker")
        if sys.platform == 'darwin':
            import AppKit
            # http://developer.apple.com/DOCUMENTATION/Cocoa/Reference/Foundation/Miscellaneous/Foundation_Functions/Reference/reference.html#//apple_ref/c/func/NSSearchPathForDirectoriesInDomains
            # NSApplicationSupportDirectory = 14
            # NSUserDomainMask = 1
            # True for expanding the tilde into a fully qualified path
            App.data_dir = path.join(AppKit.NSSearchPathForDirectoriesInDomains(14, 1, True)[0], app_name)
        elif sys.platform == 'win32':
            App.data_dir = path.join(os.environ['APPDATA'], app_name)
        else:
            App.data_dir = path.expanduser(path.join("~", "." + app_name))
        if not os.path.exists(App.data_dir):
            os.makedirs(App.data_dir, 0o777)
        return App.data_dir

    def run(self):
        default_command = "check_services"
        valid_commands = default_command + "|send_mail"
        parser = argparse.ArgumentParser(description='A Service Checker written in python.')
        parser.add_argument('--command', type=RegexValidator(r"^(" + valid_commands + ")$", True),
                            help='command to be executed: {}'.format(valid_commands), default="check_services")
        parser.add_argument('--log_level', type=int, default=logging.INFO,
                            help='CRITICAL = 50, ERROR = 40, WARNING = 30, INFO = 20, DEBUG = 10, NOTSET = 0')
        parser.add_argument('--log_file', type=str, default=None, help='log file')

        known_args = parser.parse_known_args()[0]
        App.setup_logging(known_args.log_level, known_args.log_file)
        logger = logging.getLogger(__name__)
        logger.info("running command {}".format(known_args.command))
        getattr(self, known_args.command)()

    @staticmethod
    def check_services():
        logger = logging.getLogger(__name__)
        parser = argparse.ArgumentParser()
        parser.add_argument('--config', type=JsonFileValidator(), default="PyServiceCheckerConfig.json",
                            help="The configuration file: Sample provided in the project directory")

        known_args = parser.parse_known_args()[0]
        config = known_args.config
        logger.debug("data: {}".format(config))
        smtp = Smtp.create_from_dict(config)
        logger.debug("smtp settings: {}".format(str(smtp)))
        services = Services.create_from_list(config)
        logger.debug("services: {}".format(services))
        recipient_messages = {}
        for service in services.items:
            message, message_recipient = service.check_and_create_message()
            if message:
                if message_recipient not in recipient_messages.keys():
                    recipient_messages[message_recipient] = []
                recipient_messages[message_recipient].append(message)

        if len(recipient_messages) > 0:
            subject = "Messages from mbits service check on host " + socket.gethostname().lower().strip()
            for mail_addr, messages in recipient_messages.items():
                smtp.send_mail(mail_addr, subject, "\n\n  -".join(messages))

    @staticmethod
    def send_mail():
        logger = logging.getLogger(__name__)
        parser = argparse.ArgumentParser()
        parser.add_argument('--config', type=JsonFileValidator(), default="PyServiceCheckerConfig.json",
                            help="The configuration file: Sample provided in the project directory")
        parser.add_argument('--subject', type=str, required=True, help="message subject")
        parser.add_argument('--text', type=str, required=True, help="message text")
        parser.add_argument('--recipient', type=str, required=True, help="message recipient")

        known_args = parser.parse_known_args()[0]
        config = known_args.config
        logger.debug("data: {}".format(config))
        smtp = Smtp.create_from_dict(config)
        smtp.send_mail(known_args.recipient, known_args.subject, known_args.text)

    @staticmethod
    def setup_logging(log_level=logging.INFO, log_file=None):
        class InfoFilter(logging.Filter):
            def filter(self, rec):
                return rec.levelno in (logging.DEBUG, logging.INFO, logging.WARNING)

        h1 = logging.StreamHandler(sys.stdout)
        h1.flush = sys.stdout.flush
        h1.setLevel(logging.DEBUG)
        h1.addFilter(InfoFilter())
        h2 = logging.StreamHandler(sys.stderr)
        h2.flush = sys.stderr.flush
        h2.setLevel(logging.ERROR)

        handlers = [h1, h2]
        kwargs = {"format": "%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s",
                  "datefmt": '%Y-%m-%d:%H:%M:%S', "level": log_level}

        if log_file:
            h1 = logging.FileHandler(filename=log_file)
            h1.setLevel(logging.DEBUG)
            handlers = [h1]

        kwargs["handlers"] = handlers
        logging.basicConfig(**kwargs)


if __name__ == "__main__":
    app = App()
    app.run()
