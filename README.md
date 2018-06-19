# pyreceived

This is a python 3 library for parsing Received fields in email headers. Email headers are defined by [RFC5322](https://tools.ietf.org/html/rfc5322) but the format of the Received field is not defined and each email server basically decides what to put in it how.

This library basically uses lot of different regular expressions to parse this field and extract interesting information. As you may guess, it is not always reliable, so this code is **not ready for production**, it should work 75% of the cases but be ready to write some regex if you want to use it. One important limitation of this code is that it crashed if it does not recognize the format of the received field.

## How to use it

You can extract the Received field of an email with the [email.parser](https://docs.python.org/3/library/email.parser.html) library in python 3, then you can use pyreceived to analyze this field.

```py
from pyreceived import ReceivedParser, ReceivedParserError
from email.parser import HeaderParser

with open(args.FILE, 'r') as f:
    email = HeaderParser().parse(f)
relays = email.get_all('Received')

for relay in relays:
    print(relay)
    try:
	parsed_relay = ReceivedParser.parse(relay)
    except ReceivedParserError:
	print("Badly Parsed: %s" % last_relay)
    else:
	for i in parsed_relay:
	    print("%s : %s" % (i, parsed_relay[i]))
```

## How to improve it

The developement of pyreceived was done based on tests, so there is an extensive list of tests in `test.py`. For instance :
```py
    def test_header1_exchange(self):
        header = "from relay.email.com (192.168.10.10) by\n EXCHANGE.email.local (192.168.100.51) with Microsoft SMTP Server id\n 14.3.123.3; Sat, 6 Jun 2015 05:34:59 +0200"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'relay.email.com')
        self.assertEqual(data['from_ip'], '192.168.10.10')
        self.assertEqual(data['by_hostname'], 'EXCHANGE.email.local')
        self.assertEqual(data['by_ip'], '192.168.100.51')
        self.assertEqual(data['id'], '14.3.123.3')
        self.assertEqual(data['server'], 'MS SMTP Server')
```

To improve pyreceived, you should :
* Add a new unsuported header in `test.py`
* Confirm that it crashes by running `python test.py`
* Identify which regex should handle it in `parser.py`
* Improve this regex ([pythex](https://pythex.org/) may be a good help)

## Other solutions

* [mail-parser](https://github.com/SpamScope/mail-parser) manage to parse some fields but it is not reliable
* The perl [Email](http://search.cpan.org/~simon/Email-Received-1.00/lib/Email/Received.pm) library is apparently pretty reliable as it is used by spamassassin. I have not tested it personally

## License

This code is released under MIT license
