#!/usr/bin/env python

"""
Parse apache mod_security logs to find interesting log rows.

"""
import argparse
import fileinput
import json
import re
import sys
import urlparse


# Or I could rewrite the script for Python 3 which has enums
def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    enums['reverse_mapping'] = reverse
    return type('Enum', (), enums)

LogParts = enum('STARTED',
                'REQUEST_HEADERS',
                'CONTENT',
                'IGNORE',
                'STOPPED')

Methods = enum('GET', 'POST', 'PUT')

class Part(object):
    """ Base class for mod_security log parts """
    def __init__(self):
        self.content = []
        self.line_count = 0
        self.parameters = []

    def add(self, line, line_count):
        if not self.content:
            self.line_count =  line_count
        self.content.append(line)

    def addParameter(self, line, line_count):
        parameters = ['%s=%s' % (key,item[0]) for key,item in urlparse.parse_qs(line).iteritems()]
        if parameters:
            self.content.extend(parameters)

    def addJson(self, line, line_count):
        parameters = json.loads(line)
        for k,v in parameters.iteritems():
            self.content.append('%s=%s' % (k, json.dumps(v)))

    def extend(self, content):
        self.content.extend(content)

    def matches(self, regex):
        return any([re.search(regex, line) for line in self.content])

    def __str__(self):
        return "\n".join(self.content) + "\n"

    def __len__(self):
        return len(self.content)

class RequestHeaders(Part):
    data = None
    QS = re.compile("(GET|POST|PUT) ([^\s\?]+)(\??(\S*)) .*")
    request_url = ""

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
            self.parameters = [ '%s=%s' % (key,item[0]) for key,item in urlparse.parse_qs(result.group(4)).iteritems()]
            self.request_url = '%s %s\n' % (result.group(1), result.group(2))

    def show(self, regex):
        return ""

    def __str__(self):
        return str(self.request_url)

    def method(self):
        return self._method

class Content(Part):
    def add(self, line, line_count):
        Part.add(self, line, line_count)
        try:
            self.addJson(line, line_count)
        except ValueError:
            self.addParameter(line, line_count)


class Ignore(Part):
    def add(self, line, line_count):
        pass

class Message():
    def __init__(self, line_count, args):
        self.line_count = line_count
        self.parts = dict()
        self.parts[LogParts.STARTED] = Ignore()
        self.parts[LogParts.REQUEST_HEADERS] = RequestHeaders()
        self.parts[LogParts.CONTENT] =  Content()
        self.parts[LogParts.IGNORE] = Ignore()
        self.parts[LogParts.STOPPED] = Ignore()
        self.parts[None] = Ignore()

        self.include_headers = args.with_headers
        self.exclude_headers = args.without_headers
        self.include_parameters = args.with_parameters
        self.exclude_parameters = args.without_parameters
        self.show_headers = args.show_headers
        self.lineno = args.n

    def method(self):
        return self.parts[LogParts.REQUEST_HEADERS].method()


    def add(self, state, line, line_count):
        if line:
            self.parts[state].add(line, line_count)

    def __str__(self):
        return ("%s%s%s%s---" % (
            "%d: " % self.line_count if self.lineno else "",
            str(self.parts[LogParts.REQUEST_HEADERS]),
            self.parts[LogParts.REQUEST_HEADERS].show(self.show_headers),
            str(self.parts[LogParts.CONTENT])))

    def show(self):
        if self.include_headers:
            if not any([self.parts[LogParts.REQUEST_HEADERS].matches(header) for header in self.include_headers]):
                return False
        if self.exclude_headers:
            if any([self.parts[LogParts.REQUEST_HEADERS].matches(header) for header in self.exclude_headers]):
                return False

        if self.include_parameters:
            if not any([self.parts[LogParts.CONTENT].matches(param) for param in self.include_parameters]):
                return False
        if self.exclude_parameters:
            if any([self.parts[LogParts.CONTENT].matches(param) for param in self.exclude_parameters]):
                return False

        return True

    def handle(self):
        # Add query parameters to content
        self.parts[LogParts.CONTENT].extend(self.parts[LogParts.REQUEST_HEADERS].parameters)
        if self.show():
            print self

class GrepLog():
    DELIMITER_PATTERN = re.compile("--(\w+)-(\w)--")

    def __init__(self, args):
        self.args = args
        self.state = None
        self.message = Message(0, args)

    def parseState(self, result, line_count):
        logPart = result.group(2)
        if logPart == 'A':
            self.message = Message(line_count, self.args)
            self.state = LogParts.STARTED
        elif logPart == 'B':
            self.state = LogParts.REQUEST_HEADERS
        elif logPart == 'C' or logPart == 'I':
            self.state = LogParts.CONTENT
        elif logPart == 'Z':
            self.state = LogParts.STOPPED
        else:
            self.state = LogParts.IGNORE

    def parseLine(self, line, line_count):
        """ Parse log line, handle depending on current state """
        result = self.DELIMITER_PATTERN.match(line)
        if result:
            self.parseState(result, line_count)
        elif line:
            self.message.add(self.state, line, line_count)

        if self.state == LogParts.STOPPED:
            self.message.handle()
            self.state = LogParts.IGNORE

def main(args):
    parser = argparse.ArgumentParser(description = 'Parse mod_security logs')
    parser.add_argument('--with_headers',
        help='Show only logs where request headers match HEADER',
        metavar='HEADER',
        nargs='+')
    parser.add_argument('--without_headers',
        help='Don\'t show logs where request headers match HEADER. Overrides --with_headers on conflicts',
        metavar='HEADER',
        nargs='+')
    parser.add_argument('--with_parameters',
        help='Show only logs where URL parameters (GET, POST or PUT) match PARAM',
        metavar='PARAM',
        nargs='+')
    parser.add_argument('--without_parameters',
        help='Don\'t show logs where URL parameters match PARAM. Overrides --with_parameters on conflicts',
        metavar='PARAM',
        nargs='+')
    parser.add_argument('--show_headers',
        help='Display request headers SHOW_HEADERS. Normally only the GET/POST/PUT string is displayed',
        nargs='+')
    parser.add_argument('-n',
        help='Display line number',
        action='store_true')
    parser.add_argument('file', nargs='+')

    args = parser.parse_args(args)
    greplog = GrepLog(args)
    for line in fileinput.input(args.file):
        greplog.parseLine(line, fileinput.filelineno())

if __name__ == '__main__':
    main(sys.argv[1:])