import json
import re
import urlparse
import datetime

__author__ = 'anna'
from enum import Enum
from collections import defaultdict


class LogParts(Enum):
    """
    The different parts of an audit log that we care about.
    """
    STARTED = 1
    REQUEST_HEADERS = 2
    CONTENT = 3
    IGNORE = 4
    STOPPED = 5
    RESPONSE_HEADERS = 6


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

    def __repr__(self):
        return self.param.__repr__()


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
        if regex is None:
            return True
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
                             (\d+/\w+/\d+):   # Date as d/b/Y
                             (\d+:\d+:\d+)    # Time
                             \s
                             (\S+)            # Timezone
                             \]
                             \s
                             (\S+)            # Random string
                             \s([\d{1,3}\.]+) # IP
                             .*               # Ignore the rest of the string
                             """,
                         re.X)

    EPOCH = datetime.datetime(1970, 1, 1)

    def __init__(self):
        Part.__init__(self)
        self.ip = None
        self.datetime = None
        self.timestamp = None
        self.date = None
        self.id = None
        self.timezone = None

    def add(self, line, line_count):
        result = re.match(self.PATTERN, line)
        if result:

            self.date = datetime.datetime.strptime(result.group(1), '%d/%b/%Y')
            dt = datetime.datetime.strptime(result.group(2), '%H:%M:%S')

            self.timestamp = datetime.time(dt.hour, dt.minute, dt.second, dt.microsecond)
            self.datetime = int((datetime.datetime.combine(self.date, self.timestamp) - self.EPOCH).total_seconds())

            self.timezone = result.group(3)  # but assuming UTC for now
            self.id = result.group(4)
            self.ip = result.group(5)
        else:
            print "No time match for", line

    def __str__(self):
        return '{timestamp:s} : {ip:s}'.format(timestamp=self.format_timestamp(),
                                               ip=self.ip)

    def get_id(self):
        return self.id

    def get_ip(self):
        return self.ip

    def get_time(self):
        return self.timestamp

    def format_date(self):
        return self.date.strftime('%Y-%m-%d')

    def format_time(self):
        return self.timestamp.strftime('%H:%M:%S')

    def format_timestamp(self):
        return '{date:s} {timestamp:s}'.format(date=self.format_date(),
                                               timestamp=self.format_time())

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


class Headers(Part):

    def __init__(self):
        Part.__init__(self)
        self.headers = Parameters()

    def add(self, line, line_count):
        key, value = line.split(':', 1)
        self.headers.add(key, [value.strip()])

    def get_headers(self):
        return self.headers


class RequestHeaders(Headers):
    """ Contains all request headers.

     Query parameters are parsed and accessible through get_parameters.
    """
    QS = re.compile("(GET|POST|PUT|DELETE|HEAD|OPTIONS) ([^\s\?]+)(\??(\S*))")

    def __init__(self):
        super(RequestHeaders, self).__init__()
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
            elif line.startswith('DELETE'):
                self._method = Methods.DELETE
            elif line.startswith('HEAD'):
                self._method = Methods.HEAD
            elif line.startswith('OPTIONS'):
                self._method = Methods.OPTIONS
            self.parameters.update(urlparse.parse_qs(result.group(4)).iteritems())
            self.request_url = (result.group(2), result.group(4))
        else:
            Headers.add(self, line, line_count)

    def get_method(self):
        return self._method

    def get_path(self):
        return self.request_url[0]

    def get_query_string(self):
        return self.request_url[1]

    def get_url(self):
        return "{}{}{}".format(self.request_url[0], '?' if self.request_url[1] else '', self.request_url[1])


class ResponseHeaders(Headers):
    RS = re.compile("(\w+)/(.*) (\d\d\d) (.*)")

    def __init__(self):
        super(ResponseHeaders, self).__init__()
        self.response_code = 0
        self.response = None

    def add(self, line, line_count):
        result = self.RS.match(line)
        if result:
            self.response_code = int(result.group(3))
            self.response = result.group(4)
        else:
            Headers.add(self, line, line_count)


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


class Message(object):
    def __init__(self, line_count, args):
        self.line_count = line_count
        self.args = args
        self.parts = dict()
        self.parts[LogParts.STARTED] = Start()
        self.parts[LogParts.REQUEST_HEADERS] = RequestHeaders()
        self.parts[LogParts.CONTENT] = Content()
        self.parts[LogParts.IGNORE] = Ignore()
        self.parts[LogParts.STOPPED] = Ignore()
        self.parts[LogParts.RESPONSE_HEADERS] = ResponseHeaders()
        self.parts[None] = Ignore()

    def method(self):
        return self.request_headers().get_method()

    def time(self):
        return self.start().get_time()

    def add(self, state, line, line_count):
        if line:
            self.parts[state].add(line, line_count)

    def request_headers(self):
        return self.parts[LogParts.REQUEST_HEADERS]

    def response_headers(self):
        return self.parts[LogParts.RESPONSE_HEADERS]

    def content(self):
        return self.parts[LogParts.CONTENT]

    def start(self):
        return self.parts[LogParts.STARTED]


class FormattedMessage(Message):
    def format_start(self):
        pass

    def format_headers(self):
        pass

    def format_content(self):
        pass

    def format_footer(self):
        pass

    def format_request_headers(self):
        pass


class ModSecurityLog(object):

    DELIMITER_PATTERN = re.compile("--(\w+)-(\w)--")

    def __init__(self, args, message_class=Message):
        self.state = LogParts.IGNORE
        self.message_class = message_class
        self.args = args
        self.message = self.message_class(0, self.args)
        self.state = None

    def parse_state(self, result, line_count):
        log_part = result.group(2)
        if log_part == 'A':
            self.message = self.message_class(line_count, self.args)
            self.state = LogParts.STARTED
        elif log_part == 'B':
            self.state = LogParts.REQUEST_HEADERS
        elif log_part == 'C' or log_part == 'I':
            self.state = LogParts.CONTENT
        elif log_part == 'F':
            self.state = LogParts.RESPONSE_HEADERS
        elif log_part == 'Z':
            self.state = LogParts.STOPPED
        else:
            self.state = LogParts.IGNORE

    def parse_line(self, line, line_count, callback=None):
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
            if callback is not None:
                callback(self.message)
            self.state = LogParts.IGNORE
