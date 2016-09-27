import re

__author__ = 'anna'

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



