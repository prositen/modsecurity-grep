#!/usr/bin/env python

"""
Parse apache mod_security logs to find interesting log rows.

"""
import argparse
import datetime
import fileinput
import re
import subprocess
import sys
from mod_security import FormattedMessage, ModSecurityLog
from utils import split_to_dict, split_re


# noinspection PyUnusedLocal
def no_color(text, *args, **kwargs):
    """
    Dummy 'colored' function used when termcolor isn't installed.
    :param text: Text to display
    :param args: Ignored
    :param kwargs:  Ignored
    :return: The input text, unchanged
    """
    return text

try:
    from termcolor import colored
except ImportError:
    def colored(text, *args, **kwargs):
        return no_color(text, args, kwargs)


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


class ColorMessage(FormattedMessage):
    def format_ip(self, ips):
        return format_split(split_re(self.start().ip, ips), colors=Colors.IP)

    def format_start(self):
        return '{timestamp:s}{ip:s}'.format(
            timestamp=self.start().format_timestamp() if self.args.show_timestamp else "",
            ip=self.format_ip(self.args.with_ip) if self.args.show_ip else ""
        )

    def format_query_parameters(self, headers):
        parts = split_re(self.request_headers().get_query_string(), headers)
        return ('?' + format_split(parts, colors=Colors.QUERY_PARAMETER)) if parts else ''

    def format_method(self, methods):
        return format_split(split_re(self.request_headers().get_method(), methods), colors=Colors.METHOD)

    def format_url(self, urls):
        return format_split(split_re(self.request_headers().get_path(), urls), colors=Colors.URL)

    def format_request_headers(self):
        headers = self.request_headers().headers
        if self.args.show_headers:
            for name, value in headers.iteritems():
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

    def format_request(self, with_methods, with_headers, with_params):
        query_params = dict()
        if with_headers:
            query_params.update(with_headers)
        if with_params:
            query_params.update(with_params)
        return '{method:s} {url:s}{query_parameters:s}'.format(
            method=self.format_method(with_methods),
            url=self.format_url(with_headers),
            query_parameters=self.format_query_parameters(query_params))

    def format_request_url(self):
        """
        Colorized string representation of the request URL
        """
        return "%s%s" % (
            colored("%d: " % self.line_count, Colors.LINE_COUNT.color, on_color=Colors.LINE_COUNT.on_color,
                    attrs=Colors.LINE_COUNT.attrs) if self.args.n else "",
            self.format_request(self.args.with_method,
                                self.args.with_headers,
                                self.args.with_parameters)
        )

    def format_parameters(self):
        """
        Colorized string representation of the parameters from the message payload.
        """
        for name, value in self.content().get_parameters().iteritems():
            yield ('{name:s}={value:s}'.format(
                name=format_split(split_re(name, self.args.with_parameters.iterkeys()),
                                  colors=Colors.PARAM_NAME),
                value=format_split(split_re(value[0], self.args.with_parameters.itervalues()),
                                   colors=Colors.PARAM_VALUE)
            ))

    def format_content(self):
        for x in iter(self.content()):
            yield x

    @staticmethod
    def format_footer():
        return '---'

    def show(self):
        headers = self.request_headers().headers
        if not headers.matches(self.args.with_headers):
            return False
        if self.args.without_headers and any(
                [headers.matches(h) for h in self.args.without_headers]):
            return False

        if self.args.with_method and not any([str(self.method()) == m for m in self.args.with_method]):
            return False

        content = self.content()
        if not content.get_parameters().matches(self.args.with_parameters):
            return False
        if self.args.without_parameters and any(
                [content.matches(param) for param in self.args.without_parameters]):
            return False

        if not self.start().time_matches(self.args.timestamp):
            return False
        if not self.start().time_between(self.args.timestamp_between):
            return False

        if self.args.with_ip and not any([self.start().ip_matches(ip) for ip in self.args.with_ip]):
            return False
        if self.args.without_ip and any([self.start().ip_matches(ip) for ip in self.args.without_ip]):
            return False

        return True

    @staticmethod
    def message_handler_factory(stream):
        def handle(message):
            """
            Show the message if the filters match.
            Yields output, one line at a time
            """
            request_params = message.request_headers().get_parameters()
            content_params = message.content().get_parameters()
            content_params.update(request_params)

            if message.show():
                stream.write(message.format_start() + '\n')
                stream.write(message.format_request_url() + '\n')
                for x in message.format_request_headers():
                    stream.write(x + '\n')
                if message.args.show_raw_content:
                    for x in message.format_content():
                        stream.write(x + '\n')
                for x in message.format_parameters():
                    stream.write(x + '\n')

                stream.write(message.format_footer() + '\n')

        return handle


class GrepLog(ModSecurityLog):
    @staticmethod
    def parse_time(timestamp):
        return datetime.datetime.strptime(timestamp, '%H:%M:%S')

    def __init__(self, args):
        super(GrepLog, self).__init__(args, message_class=ColorMessage)
        self.args = GrepLog.get_arg_parser().parse_args(args)
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
    p = subprocess.Popen(['less', '-F', '-R', '-K'],
                         stdin=subprocess.PIPE,
                         stdout=sys.stdout)
    filename = None
    message_handler = ColorMessage.message_handler_factory(p.stdin)
    try:
        for line in fileinput.input(greplog.args.file, openhook=fileinput.hook_compressed):

            if filename != fileinput.filename():
                filename = fileinput.filename()
                p.stdin.write(header(filename))
            greplog.parse_line(line.strip(), fileinput.filelineno(), callback=message_handler)
    except (KeyboardInterrupt, IOError):
        pass
    finally:
        p.stdin.close()
        p.wait()


if __name__ == '__main__':
    main(sys.argv[1:])
