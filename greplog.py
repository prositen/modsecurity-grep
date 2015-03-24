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


class Part(object):
    """ Base class for mod_security log parts """
    def __init__(self):
        self.content = []
        self.line_count = 0
        self.parameters = []

    def add(self, line, line_count):
        if not self.content:
            self.line_count = line_count
        self.content.append(line)

    def add_parameter(self, line):
        parameters = ['%s=%s' % (key, item[0]) for key, item in urlparse.parse_qs(line).iteritems()]
        if parameters:
            self.content.extend(parameters)

    def add_json(self, line):
        parameters = json.loads(line)
        for k, v in parameters.iteritems():
            self.content.append('%s=%s' % (k, json.dumps(v)))

    def extend(self, content):
        self.content.extend(content)

    def matches(self, regex):
        return any([re.search(regex, line) for line in self.content])

    def __str__(self):
        return "\n".join(self.content) + "\n"

    def __len__(self):
        return len(self.content)

    def __iter__(self):
        return self.content.__iter__()


class RequestHeaders(Part):
    """ Contains all request headers.

     Query parameters are parsed and accessible through get_parameters.
    """
    QS = re.compile("(GET|POST|PUT) ([^\s\?]+)(\??(\S*)) .*")

    def __init__(self):
        Part.__init__(self)
        self._method = None
        self.request_url = ""

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
            self.parameters = ['%s=%s' % (key, item[0]) for key, item in urlparse.parse_qs(result.group(4)).iteritems()]
            self.request_url = result

    def __str__(self):
        return '%s %s%s\n' % (colored(self.request_url.group(1), 'yellow'),
                              colored(self.request_url.group(2), 'cyan'),
                              colored("?%s" % self.request_url.group(4), 'yellow') if self.request_url.group(4) else "")

    def method(self):
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
        return self.parts[LogParts.REQUEST_HEADERS].method()

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

        if self.args.with_parameters:
            if not any([self.parts[LogParts.CONTENT].matches(param) for param in self.args.with_parameters]):
                return False
        if self.args.without_parameters:
            if any([self.parts[LogParts.CONTENT].matches(param) for param in self.args.without_parameters]):
                return False

        return True

    def request_headers(self):
        return ("%s%s" % (
                colored("%d: " % self.line_count, 'yellow', attrs=['bold']) if self.args.n else "",
                self.parts[LogParts.REQUEST_HEADERS])
                ).strip()

    def content(self):
        for x in iter(self.parts[LogParts.CONTENT]):
            yield x.strip()

    @staticmethod
    def footer():
        return '---'

    def handle(self):
        # Add query parameters to content
        self.parts[LogParts.CONTENT].extend(self.parts[LogParts.REQUEST_HEADERS].parameters)
        if self.show():
            yield self.request_headers()
            for x in self.content():
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
        parser.add_argument('--with_headers',
                            help='Show only logs where request headers match HEADER',
                            metavar='HEADER',
                            nargs='+')
        parser.add_argument('--without_headers',
                            help='Don\'t show logs where request headers match HEADER. '
                                 + 'Overrides --with_headers on conflicts',
                            metavar='HEADER',
                            nargs='+')
        parser.add_argument('--with_parameters',
                            help='Show only logs where URL parameters (GET, POST or PUT) match PARAM',
                            metavar='PARAM',
                            nargs='+')
        parser.add_argument('--without_parameters',
                            help='Don\'t show logs where URL parameters match PARAM. '
                                 + 'Overrides --with_parameters on conflicts',
                            metavar='PARAM',
                            nargs='+')
        parser.add_argument('--show_headers',
                            help='Display request headers SHOW_HEADERS. '
                                 + 'Normally only the GET/POST/PUT string is displayed',
                            nargs='+')
        parser.add_argument('-n',
                            help='Display line number',
                            action='store_true')
        parser.add_argument('file', nargs='+')
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
        """ Parse log line, handle depending on current state """
        result = self.DELIMITER_PATTERN.match(line)

        if result:
            self.parse_state(result, line_count)
        elif line:
            self.message.add(self.state, line, line_count)

        if self.state == LogParts.STOPPED:
            for x in self.message.handle():
                yield x
            self.state = LogParts.IGNORE


def header(filename):
    l = len(filename)
    return "%s\n%s\n" % (colored(filename, 'green', attrs=['bold']),
                         colored(l * '=', 'green', attrs=['bold']))


def main(args):
    greplog = GrepLog(args)
    p = subprocess.Popen(['less', '-F', '-R', '-S', '-X', '-K'],
                         stdin=subprocess.PIPE,
                         stdout=sys.stdout)
    filename = None
    try:
        for line in fileinput.input(greplog.args.file):
            if filename != fileinput.filename():
                filename = fileinput.filename()
                p.stdin.write(header(filename))
            for x in greplog.parse_line(line, fileinput.filelineno()):
                p.stdin.write("%s\n" % x)
        p.stdin.close()
        p.wait()
    except (KeyboardInterrupt, IOError):
        pass


if __name__ == '__main__':
    main(sys.argv[1:])