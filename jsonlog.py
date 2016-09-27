#!/usr/bin/env python
__author__ = 'Anna Holmgren'
import argparse
import fileinput
import json
import sys
from mod_security import ModSecurityLog, FormattedMessage


def parameter_to_dict(parameters):
    ret = dict()
    for name, value in parameters.iteritems():
        if len(value) == 1:
            ret[name] = value[0]
        else:
            ret[name] = value
    return ret


class JsonMessage(FormattedMessage):
    def format_start(self):
        ret = dict()

        ret['timestamp'] = self.start().datetime
        ret['ip'] = self.start().get_ip()
        ret['request_id'] = self.start().get_id()
        return ret

    def format_request_headers(self):
        req = self.request_headers()
        ret = dict()

        ret['method'] = str(req.get_method())
        ret['url'] = req.get_url()
        if len(req.get_query_string()):
            ret['query_string'] = req.get_query_string()

        parameters = parameter_to_dict(req.parameters)
        if parameters:
            ret['parameters'] = parameters
            
        headers = parameter_to_dict(req.get_headers())
        if headers:
            ret['headers'] = headers

        return ret

    def format_response_headers(self):
        return parameter_to_dict(self.response_headers().get_headers())

    def format_content(self):
        return parameter_to_dict(self.content().get_parameters())

    @staticmethod
    def message_handler_factory(stream):
        def handle(message):

            jsonmessage = dict()

            jsonmessage['request'] = message.format_request_headers()
            jsonmessage['request'].update(message.format_start())

            content = message.format_content()
            if content:
                jsonmessage['request']['payload'] = content

            jsonmessage['response'] = dict()
            jsonmessage['response']['headers'] = message.format_response_headers()

            jsonobject = json.dumps(jsonmessage)

            stream.write(jsonobject + '\n')

        return handle


class JsonLog(ModSecurityLog):

    def __init__(self, args):
        super(JsonLog, self).__init__(args, message_class=JsonMessage)
        self.args = self.get_arg_parser().parse_args(args)

    @staticmethod
    def get_arg_parser():
        parser = argparse.ArgumentParser(description='Parse mod_security logs')
        parser.add_argument('file', help='Logfile(s)',
                            nargs='+')
        return parser


def main(args):
    greplog = JsonLog(args)

    filename = None
    fp = None
    message_handler = JsonMessage.message_handler_factory(sys.stdout)
    try:
        for line in fileinput.input(greplog.args.file, openhook=fileinput.hook_compressed):
            if filename != fileinput.filename():
                filename = fileinput.filename()
                if fp:
                    fp.close()
                fp = open(filename + '.json', 'w')
                message_handler = JsonMessage.message_handler_factory(fp)
            greplog.parse_line(line.strip(), fileinput.filelineno(), callback=message_handler)
    except (KeyboardInterrupt, IOError):
        pass
    finally:
        if fp:
            fp.close()


if __name__ == '__main__':
    main(sys.argv[1:])

