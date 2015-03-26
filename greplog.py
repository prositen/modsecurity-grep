#!/usr/bin/env python

"""
Parse apache mod_security logs to find interesting log rows.

"""
import argparse
import fileinput
import json
import re
import subprocess
import sys
import urlparse
from collections import defaultdict
from enum import Enum
try:
    from termcolor import colored
except ImportError:
    # noinspection PyUnusedLocal
    def colored(text, *args, **kwargs):
        return text


class LogParts(Enum):
    STARTED = 1
    REQUEST_HEADERS = 2
    CONTENT = 3
    IGNORE = 4
    STOPPED = 5


class Methods(Enum):
    GET = 1
    POST = 2
    PUT = 3

    def __str__(self):
        return self.name


class Parameters(object):

    def __init__(self):
        self.param = defaultdict(list)

    def add(self, key, value):
        self.param[key].extend(value)

    def update(self, params):
        try:
            self.param.update(params.param)
        except AttributeError:
            self.param.update(params)

    def __iter__(self):
        for k, v in self.param.iteritems():
            yield colored(k, 'red', attrs=['bold']) + '=' + colored(v, 'green')

    def iteritems(self):
        return self.param.iteritems()

    def len(self):
        return len(self.param)

    def matches(self, regex_name, regex_value):
        for k, v in self.param.iteritems():
            if re.search(regex_name, k):
                if regex_value:
                    if any(re.search(regex_value, value) for value in v):
                        return True
                else:
                    return True
        return False


class Part(object):
    """ Base class for mod_security log parts """
    def __init__(self):
        self.raw_data = []
        self.line_count = 0
        self.parameters = Parameters()

    def add(self, line, line_count):
        if not self.raw_data:
            self.line_count = line_count
        self.raw_data.append(line)

    def add_parameter(self, line):
        for k, v in urlparse.parse_qs(line).iteritems():
            self.parameters.add(k, v)

    def add_json(self, line):
        parameters = json.loads(line)
        self.parameters.update(parameters)

    def get_parameters(self):
        return self.parameters

    def extend(self, content):
        self.raw_data.extend(content)

    def matches(self, regex):
        return any([re.search(regex, line) for line in self.raw_data])

    def __str__(self):
        return "\n".join(self.raw_data)

    def __len__(self):
        return len(self.raw_data)

    def __iter__(self):
        return self.raw_data.__iter__()


class RequestHeaders(Part):
    """ Contains all request headers.

     Query parameters are parsed and accessible through get_parameters.
    """
    QS = re.compile("(GET|POST|PUT) ([^\s\?]+)(\??(\S*)) .*")

    def __init__(self):
        Part.__init__(self)
        self._method = None
        self.request_url = ""

    def __str__(self):
        return '{method:s} {url:s}{query_parameters:s}'.format(method=colored(self.request_url[0], 'yellow'),
                                                               url=colored(self.request_url[1], 'cyan'),
                                                               query_parameters=colored('?%s' % self.request_url[2],
                                                                                        'yellow') if self.request_url[2] else "")

    def add(self, line, line_count):
        Part.add(self, line, line_count)
        result = re.match(self.QS, line)
        if result:
            if line.startswith('GET'):
                self._method = Methods.GET
            elif line.startswith('POST'):
                self._method = Methods.POST
            elif line.startswith('PUT'):
                self._method = Methods.PUT
            self.parameters.update(urlparse.parse_qs(result.group(4)).iteritems())
            self.request_url = (result.group(1), result.group(2), result.group(4))

    def get_method(self):
        return self._method


class Content(Part):
    def add(self, line, line_count):
        Part.add(self, line, line_count)
        try:
            self.add_json(line)
        except ValueError:
            self.add_parameter(line)


class Ignore(Part):
    def add(self, line, line_count):
        pass


class Message():
    def __init__(self, line_count, args):
        self.line_count = line_count
        self.args = args
        self.parts = dict()
        self.parts[LogParts.STARTED] = Ignore()
        self.parts[LogParts.REQUEST_HEADERS] = RequestHeaders()
        self.parts[LogParts.CONTENT] = Content()
        self.parts[LogParts.IGNORE] = Ignore()
        self.parts[LogParts.STOPPED] = Ignore()
        self.parts[None] = Ignore()

    def method(self):
        return self.parts[LogParts.REQUEST_HEADERS].get_method()

    def add(self, state, line, line_count):
        if line:
            self.parts[state].add(line, line_count)

    def show(self):
        if self.args.with_headers:
            if not any([self.parts[LogParts.REQUEST_HEADERS].matches(h) for h in self.args.with_headers]):
                return False
        if self.args.without_headers:
            if any([self.parts[LogParts.REQUEST_HEADERS].matches(h) for h in self.args.without_headers]):
                return False

        if self.args.with_method:
            if not any([str(self.method()) == m for m in self.args.with_method]):
                return False
        if self.args.with_parameters:
            for param in self.args.with_parameters:
                try:
                    key, value = param.split('=', 2)
                except ValueError:
                    key = param
                    value = None
                if not self.parts[LogParts.CONTENT].get_parameters().matches(key, value):
                    return False
        if self.args.without_parameters:
            if any([self.parts[LogParts.CONTENT].matches(param) for param in self.args.without_parameters]):
                return False

        return True

    def request_url(self):
        """
        Colorized string representation of the request URL
        """
        return "%s%s" % (
            colored("%d: " % self.line_count, 'yellow', attrs=['bold']) if self.args.n else "",
            self.parts[LogParts.REQUEST_HEADERS]
            )

    def headers(self):
        if self.args.show_headers:
            for x in iter(self.parts[LogParts.REQUEST_HEADERS]):
                if any([re.search(regexp, x) for regexp in self.args.show_headers]):
                    yield x

    def parameters(self):
        for x in self.parts[LogParts.CONTENT].get_parameters():
            yield colored(x, 'red')

    def content(self):
        for x in iter(self.parts[LogParts.CONTENT]):
            yield x

    @staticmethod
    def footer():
        return '---'

    def handle(self):
        """
        Show the message if the filters match.
        Yields output, one line at a time
        """

        self.parts[LogParts.CONTENT].get_parameters().update(self.parts[LogParts.REQUEST_HEADERS].get_parameters())

        if self.show():
            yield self.request_url()
            for x in self.headers():
                yield x
            if self.args.show_raw_content:
                for x in self.content():
                    yield x
            for x in self.parameters():
                yield x

            yield self.footer()


class GrepLog():
    DELIMITER_PATTERN = re.compile("--(\w+)-(\w)--")

    def __init__(self, args):
        self.args = self.get_arg_parser().parse_args(args)
        self.state = None
        self.message = Message(0, args)

    @staticmethod
    def get_arg_parser():
        parser = argparse.ArgumentParser(description='Parse mod_security logs')
        parser.add_argument('--with-headers',
                            help='Show only logs where request headers match HEADER',
                            metavar='HEADER',
                            nargs='+')
        parser.add_argument('--without-headers',
                            help='Don\'t show logs where request headers match HEADER. '
                                 + 'Overrides --with-headers on conflicts',
                            metavar='HEADER',
                            nargs='+')
        parser.add_argument('--with-parameters',
                            help='Show only logs where URL parameters (GET, POST or PUT) match PARAM',
                            metavar='PARAM',
                            nargs='+')
        parser.add_argument('--without-parameters',
                            help='Don\'t show logs where URL parameters match PARAM. '
                                 + 'Overrides --with-parameters on conflicts',
                            metavar='PARAM',
                            nargs='+')
        parser.add_argument('--show-headers',
                            help='Show request headers SHOW_HEADERS. '
                                 + 'Normally only the GET/POST/PUT string is displayed',
                            nargs='+')
        parser.add_argument('-n',
                            help='Show line number',
                            action='store_true')
        parser.add_argument('--show-raw-content',
                            help='Show raw content. Normally only parsed post-data is displayed.',
                            action='store_true')
        parser.add_argument('--with-method',
                            help='Show only logs where request method is METHOD',
                            metavar='METHOD',
                            nargs='+')
        parser.add_argument('file', help='Logfile(s)',
                            nargs='+')
        return parser

    def parse_state(self, result, line_count):
        log_part = result.group(2)
        if log_part == 'A':
            self.message = Message(line_count, self.args)
            self.state = LogParts.STARTED
        elif log_part == 'B':
            self.state = LogParts.REQUEST_HEADERS
        elif log_part == 'C' or log_part == 'I':
            self.state = LogParts.CONTENT
        elif log_part == 'Z':
            self.state = LogParts.STOPPED
        else:
            self.state = LogParts.IGNORE

    def parse_line(self, line, line_count):
        """
        Parse log line, handle depending on current state.

        yields output, one line at a time.
        """

        result = self.DELIMITER_PATTERN.match(line)

        if result:
            self.parse_state(result, line_count)
        elif line:
            self.message.add(self.state, line, line_count)

        if self.state == LogParts.STOPPED:
            for x in self.message.handle():
                yield x
            self.state = LogParts.IGNORE


def header(header_text):
    """
    Generate a colorized header with nice underline
    :param header_text:
    :return: string
    """
    l = len(header_text)
    return "%s\n%s\n" % (colored(header_text, 'green', attrs=['bold']),
                         colored(l * '=', 'green', attrs=['bold']))


def main(args):
    greplog = GrepLog(args)

    # Pipe output through less. Hackish, but better than writing my own pager.
    p = subprocess.Popen(['less', '-F', '-R', '-S', '-X', '-K'],
                         stdin=subprocess.PIPE,
                         stdout=sys.stdout)
    filename = None
    try:
        for line in fileinput.input(greplog.args.file):
            if filename != fileinput.filename():
                filename = fileinput.filename()
                p.stdin.write(header(filename))
            for x in greplog.parse_line(line.strip(), fileinput.filelineno()):
                p.stdin.write("%s\n" % x)
        p.stdin.close()
        p.wait()
    except (KeyboardInterrupt, IOError):
        pass


if __name__ == '__main__':
    main(sys.argv[1:])