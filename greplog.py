#!/usr/bin/env python

"""
Parse apache mod_security logs to find interesting log rows.

"""
import argparse
import datetime
import fileinput
import gzip
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
        """
        Dummy 'colored' function used when termcolor isn't installed.
        :param text: Text to display
        :param args: Ignored
        :param kwargs:  Ignored
        :return: The input text, unchanged
        """
        return text


def split_re(text, patterns):
    """ Split 'text' according to the regular expressions in 'pattern'
    :param text: Text to split
    :param patterns: Regular expressions to tokenize on
    :returns list of (text, matching)

    Example:
    >>> split_re("http://dummy.com/?param=a", ["param"])
    [('http://dummy.com/?', False), ('param', True), ('=a', False)]
    >>> split_re("The quick brown fox jumps over the lazy dog", ["[Tt]he", "e"])
    [('The', True), (' quick brown fox jumps ov', False), ('e', True), ('r ', False), ('the', True), (' lazy dog', False)]
    >>> split_re(None, ["derp"]) is None
    True
    >>> split_re("The quick brown fox jumps over the lazy dog", None)
    [('The quick brown fox jumps over the lazy dog', False)]
    >>> split_re("http://dummy.com/?param=a", [ None ])
    [('http://dummy.com/?param=a', False)]
    """
    if not text:
        return None
    parts = [(text, False)]
    if not patterns:
        return parts

    for pattern in patterns:
        if not pattern:
            continue
        new_parts = list()
        for (text, matching) in parts:
            if matching:
                new_parts.append((text, True))
            else:
                res = re.finditer(pattern, text)
                if res:
                    positions = list()
                    for r in res:
                        positions.append((r.start(), r.end()))
                    prev_end = 0
                    for (start, end) in positions:
                        if start > prev_end:
                            new_parts.append((text[prev_end:start], False))
                        new_parts.append((text[start:end], True))
                        prev_end = end
                    if prev_end < len(text):
                        new_parts.append((text[prev_end:], False))
            parts = new_parts
    return parts


def split_to_dict(list_to_split, separator='='):
    """
    Split the strings in a list, and insert into a dictionary.
    Duplicate keys overwrites the previous entries.
    :param list_to_split: list of string
    :param separator: default =
    :return: Dictionary with keys & values from list

    >>> split_to_dict(["a:1", "b:2"], ':')
    {'a': '1', 'b': '2'}
    >>> split_to_dict(["a=1", "b=2"])
    {'a': '1', 'b': '2'}
    >>> split_to_dict(["a=1", "b=2", "a=3"])
    {'a': '3', 'b': '2'}
    >>> split_to_dict(None)
    {}
    >>> split_to_dict(["a=1", "b", "c=3"])
    {'a': '1', 'c': '3', 'b': None}
    """
    ret_val = dict()
    if list_to_split:
        for x in list_to_split:
            try:
                key, value = x.split(separator, 1)
            except ValueError:
                key, value = x, None
            ret_val[key] = value
    return ret_val


def format_split(parts, colors):
    """
    Create a color-formatted string from the output of 'split_re'.
    :param parts: Output from split_re
    :param color: text color
    :param on_color: background color for text matching patterns
    :param attrs: Extra text attributes used by colored
    :return: Color-formatted string
    """
    return ''.join(
        [colored(text, color=colors.color, on_color=colors.on_color if match else None, attrs=colors.attrs) for
         (text, match) in parts])


class Color(object):
    def __init__(self, color, on_color, attrs=None):
        self.color = color
        self.on_color = on_color
        self.attrs = attrs


class Colors(object):
    LINE_COUNT = Color('yellow', None, ['bold'])
    HEADER_NAME = Color(None, 'on_white')
    HEADER_VALUE = Color(None, 'on_white')
    PARAM_NAME = Color('red', 'on_white', ['bold'])
    PARAM_VALUE = Color('green', 'on_white')
    QUERY_PARAMETER = Color('yellow', 'on_white')
    URL = Color('cyan', 'on_white')
    METHOD = Color('yellow', 'on_white')
    IP = Color(None, 'on_white')


class LogParts(Enum):
    """
    The different parts of an audit log that we care about.
    """
    STARTED = 1
    REQUEST_HEADERS = 2
    CONTENT = 3
    IGNORE = 4
    STOPPED = 5


class Methods(Enum):
    """
    HTTP methods
    """
    GET = 1
    POST = 2
    PUT = 3
    HEAD = 4
    DELETE = 5
    OPTIONS = 6

    def __str__(self):
        return self.name


class Parameters(object):
    """
    Contains name-value pairs and a means to regex search in them.
    Used for e.g. HTTP parameters and request headers.
    """

    def __init__(self):
        self.param = defaultdict(list)

    def add(self, key, value):
        """
        Add a key-value pair to the collection. The value is added to the existing
         values.
        :param key:
        :param value:
        :return:
        """
        self.param[key].extend(value)

    def update(self, params):
        """
        Adds a dictionary or Parameters instance to the collection. Overwrites existing values.
        :param params:
        :return:
        """
        try:
            self.param.update(params.param)
        except AttributeError:
            self.param.update(params)

    def iteritems(self):
        return self.param.iteritems()

    def len(self):
        """
        :return: Number of parameter name-values
        """
        return len(self.param)

    def matches(self, names_values):
        """
        All name-value pairs in 'name_values' must match
        :param names_values Regular expressions to match keys & values with
        """
        if not names_values:
            return True
        for re_k, re_v in names_values.iteritems():
            for k, v in self.param.iteritems():
                if re.search(re_k, k):
                    if re_v:
                        if not any(re.search(re_v, value) for value in v):
                            return False
                    break
            else:  # no break
                return False
        return True


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


class Start(Part):
    """ [day/month/year:hour:minute:second timezone] random_string ip whatever
    """
    PATTERN = re.compile(r"""\[
                             (\d+/\w+/\d+): # Date as d/b/Y
                             (\d+:\d+:\d+)  # Time
                             \s
                             \S+            # Timezone (ignored)
                             \]
                             \s
                             \S+            # Random string (ignored)
                             \s([\d{1,3}\.]+) # IP
                             .*             # Ignore the rest of the string
                             """,
                         re.X)

    def __init__(self):
        Part.__init__(self)
        self.ip = None
        self.timestamp = None
        self.date = None

    def add(self, line, line_count):
        result = re.match(self.PATTERN, line)
        if result:
            self.date = datetime.datetime.strptime(result.group(1), '%d/%b/%Y')
            self.timestamp = datetime.datetime.strptime(result.group(2), '%H:%M:%S')
            self.ip = result.group(3)
        else:
            print "No time match for", line

    def __str__(self):
        return '{timestamp:s} : {ip:s}'.format(timestamp=self.format_timestamp(),
                                               ip=self.ip)

    def get_time(self):
        return self.timestamp

    def format_ip(self, ips):
        return format_split(split_re(self.ip, ips), colors=Colors.IP)

    def format_timestamp(self):
        return '{date:s} {timestamp:s}'.format(date=self.date.strftime('%Y-%m-%d'),
                                               timestamp=self.timestamp.strftime('%H:%M:%S'))

    def get_date(self):
        return self.date

    def ip_matches(self, ip):
        return re.match(ip, self.ip)

    def time_matches(self, timestamp):
        if not timestamp:
            return True
        return self.timestamp == timestamp

    def time_between(self, between):
        if not between:
            return True
        start, end = between
        return start <= self.timestamp <= end


class RequestHeaders(Part):
    """ Contains all request headers.

     Query parameters are parsed and accessible through get_parameters.
    """
    QS = re.compile("(GET|POST|PUT|DELETE|HEAD|OPTIONS) ([^\s\?]+)(\??(\S*))")

    def __init__(self):
        Part.__init__(self)
        self._method = None
        self.request_url = ""
        self.headers = Parameters()

    def __str__(self):
        return self.format_request(None, None)

    def format_request(self, methods, headers, params):
        query_params = dict()
        if headers:
            query_params.update(headers)
        if params:
            query_params.update(params)
        return '{method:s} {url:s}{query_parameters:s}'.format(method=self.format_method(methods),
                                                               url=self.format_url(headers),
                                                               query_parameters=self.format_query_parameters(
                                                                   query_params))

    def format_method(self, methods):
        return format_split(split_re(self.request_url[0], methods), colors=Colors.METHOD)

    def format_url(self, urls):
        return format_split(split_re(self.request_url[1], urls), colors=Colors.URL)

    def format_query_parameters(self, headers):
        parts = split_re(self.request_url[2], headers)
        return ('?' + format_split(parts, colors=Colors.QUERY_PARAMETER)) if parts else ''

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
            elif line.startswith('DELETE'):
                self._method = Methods.DELETE
            elif line.startswith('HEAD'):
                self._method = Methods.HEAD
            elif line.startswith('OPTIONS'):
                self._method = Methods.OPTIONS
            self.parameters.update(urlparse.parse_qs(result.group(4)).iteritems())
            self.request_url = (result.group(1), result.group(2), result.group(4))
            self.headers.add(line, [])
        else:
            key, value = line.split(':', 1)
            self.headers.add(key, [value.strip()])

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
        self.parts[LogParts.STARTED] = Start()
        self.parts[LogParts.REQUEST_HEADERS] = RequestHeaders()
        self.parts[LogParts.CONTENT] = Content()
        self.parts[LogParts.IGNORE] = Ignore()
        self.parts[LogParts.STOPPED] = Ignore()
        self.parts[None] = Ignore()

    def method(self):
        return self.parts[LogParts.REQUEST_HEADERS].get_method()

    def time(self):
        return self.parts[LogParts.STARTED].get_time()

    def add(self, state, line, line_count):
        if line:
            self.parts[state].add(line, line_count)

    def show(self):
        if not self.parts[LogParts.REQUEST_HEADERS].headers.matches(self.args.with_headers):
            return False
        if self.args.without_headers and any(
                [self.parts[LogParts.REQUEST_HEADERS].matches(h) for h in self.args.without_headers]):
            return False

        if self.args.with_method and not any([str(self.method()) == m for m in self.args.with_method]):
            return False

        if not self.parts[LogParts.CONTENT].get_parameters().matches(self.args.with_parameters):
            return False
        if self.args.without_parameters and any(
                [self.parts[LogParts.CONTENT].matches(param) for param in self.args.without_parameters]):
            return False

        if not self.parts[LogParts.STARTED].time_matches(self.args.timestamp):
            return False
        if not self.parts[LogParts.STARTED].time_between(self.args.timestamp_between):
            return False

        if self.args.with_ip and not any([self.parts[LogParts.STARTED].ip_matches(ip) for ip in self.args.with_ip]):
            return False
        if self.args.without_ip and any([self.parts[LogParts.STARTED].ip_matches(ip) for ip in self.args.without_ip]):
            return False

        return True

    def request_url(self):
        """
        Colorized string representation of the request URL
        """
        return "%s%s" % (
            colored("%d: " % self.line_count, Colors.LINE_COUNT.color, on_color=Colors.LINE_COUNT.on_color,
                    attrs=Colors.LINE_COUNT.attrs) if self.args.n else "",
            self.parts[LogParts.REQUEST_HEADERS].format_request(self.args.with_method,
                                                                self.args.with_headers,
                                                                self.args.with_parameters)
        )

    def headers(self):
        if self.args.show_headers:
            for name, value in self.parts[LogParts.REQUEST_HEADERS].headers.iteritems():
                if len(value):
                    value = value[0]
                else:
                    value = ''
                if any([re.search(x, name) for x in self.args.show_headers]):
                    yield ('{name:s}{colon:s}{value:s}'.format(
                        name=format_split(split_re(name, self.args.with_headers.iterkeys()),
                                          colors=Colors.HEADER_NAME),
                        colon=': ' if value else '',
                        value=format_split(split_re(value, self.args.with_headers.itervalues()),
                                           colors=Colors.HEADER_VALUE) if value else ''
                    ))

    def parameters(self):
        for name, value in self.parts[LogParts.CONTENT].get_parameters().iteritems():
            yield ('{name:s}={value:s}'.format(
                name=format_split(split_re(name, self.args.with_parameters.iterkeys()),
                                  colors=Colors.PARAM_NAME),
                value=format_split(split_re(value[0], self.args.with_parameters.itervalues()),
                                   colors=Colors.PARAM_VALUE)
            ))

            # yield colored(x, 'red')

    def content(self):
        for x in iter(self.parts[LogParts.CONTENT]):
            yield x

    def start(self):
        return '{timestamp:s}{ip:s}'.format(
            timestamp=self.parts[LogParts.STARTED].format_timestamp() if self.args.show_timestamp else "",
            ip=self.parts[LogParts.STARTED].format_ip(self.args.with_ip) if self.args.show_ip else ""
        )

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
            yield self.start()
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

    @staticmethod
    def parse_time(timestamp):
        return datetime.datetime.strptime(timestamp, '%H:%M:%S')

    def __init__(self, args):
        self.args = self.get_arg_parser().parse_args(args)
        self.state = None
        self.message = Message(0, args)

        if self.args.timestamp or self.args.timestamp_between:
            self.args.show_timestamp = True
        if self.args.timestamp:
            self.args.timestamp = self.parse_time(self.args.timestamp)
        if self.args.timestamp_between:
            self.args.timestamp_between = [self.parse_time(x) for x in self.args.timestamp_between]

        if self.args.with_ip or self.args.without_ip:
            self.args.show_ip = True

        if self.args.with_headers:
            self.args.with_headers = split_to_dict(self.args.with_headers, '=')
            if not self.args.show_headers:
                self.args.show_headers = list()
            self.args.show_headers.extend(self.args.with_headers.keys())

        self.args.with_parameters = split_to_dict(self.args.with_parameters, '=')

    @staticmethod
    def get_arg_parser():
        parser = argparse.ArgumentParser(description='Parse mod_security logs')
        parser.add_argument('--with-headers',
                            help='Show only logs where request headers match HEADER.'
                                 + 'Also enables --show-header HEADER',
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
                            action='store_true'),
        parser.add_argument('--show-ip',
                            help='Show IP.',
                            action='store_true')
        parser.add_argument('--show-timestamp',
                            help='Show timestamp',
                            action='store_true')
        parser.add_argument('--show-raw-content',
                            help='Show raw content. Normally only parsed post-data is displayed.',
                            action='store_true')
        parser.add_argument('--with-method',
                            help='Show only logs where request method is METHOD',
                            metavar='METHOD',
                            nargs='+')
        parser.add_argument('--with-ip',
                            help='Show only logs where ip matches IP. Also enables --show-ip',
                            metavar='IP',
                            nargs='+')
        parser.add_argument('--without-ip',
                            help='Don\'t show logs where ip matches IP. Also enables --show-ip',
                            metavar='IP',
                            nargs='+')
        parser.add_argument('--timestamp',
                            help='Show only logs with timestamp TIMESTAMP. Also enables --show-timestamp',
                            metavar='TIMESTAMP')
        parser.add_argument('--timestamp-between',
                            help='Show only logs with timestamp between START and END. Also enables --show-timestamp',
                            metavar=('START', 'END'),
                            nargs=2)
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
        for line in fileinput.input(greplog.args.file, openhook=fileinput.hook_compressed):
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