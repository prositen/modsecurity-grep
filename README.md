# modsecurity-grep

Search through audit logs created by [modsecurity](https://www.modsecurity.org/)

## Features

- Include/exclude request headers
- Include/exclude query parameters & post content
- Include/exclude IP addresses
- Timestamps - exact or range
- Request method

Displays query parameters and post content as name-value pairs. Json content is also parsed to name-value pairs.

Glorios color output optimized for dark terminals.


Request methods, query parameters and post content supports a 'name regex=value regex' search.

e.g. 

`--with-headers Language=en`

would match 

`Accept-language: en-us`

but not

`Accept-language: da`

or

`Cookie: en`


## Requirements 

Needs Python 3 enums and optionally termcolor

`pip install enum34 termcolor` 


