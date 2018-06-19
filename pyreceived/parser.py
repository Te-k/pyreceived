import re
from dateutil.parser import parse


class ReceivedParserError(Exception):
    def __init__(self, message):
        self.message = message
        Exception.__init__(self, message)


class ReceivedParser(object):
    regexes = [
        ("from\s+(mail\s+pickup\s+service|(?P<from_name>[\[\]\w\.\-]*))\s*(\(\s*\[?(?P<from_ip>[a-f\d\.\:]+)(\%\d+|)\]?\s*\)|)\s*by\s*(?P<by_hostname>[\w\.\-]+)\s*(\(\s*\[?(?P<by_ip>[\d\.\:a-f]+)(\%\d+|)\]?\)|)\s*(over\s+TLS\s+secured\s+channel|)\s*with\s*(mapi|Microsoft\s+SMTP\s+Server|Microsoft\s+SMTPSVC(\((?P<server_version>[\d\.]+)\)|))\s*(\((TLS|version=(?P<tls>[\w\.]+)|)\,?\s*(cipher=(?P<cipher>[\w\_]+)|)\)|)\s*(id\s+(?P<id>[\d\.]+)|)", "MS SMTP Server"), #exchange
        ("(from\s+(?P<from_name>[\[\S\]]+)\s+\(((?P<from_hostname>[\S]*)|)\s*\[(IPv6\:(?P<from_ipv6>[a-f\d\:]+)\:|)((?P<from_ip>[\d\.\:]+)|)\]\s*(\(may\s+be\s+forged\)|)\)\s*(\(using\s+(?P<tls>[\w\.]+)\s+with\s+cipher\s+(?P<cipher>[\w\-]+)\s+\([\w\/\s]+\)\)\s+(\(No\s+client\s+certificate\s+requested\)|)|)|)\s*(\(Authenticated\s+sender\:\s+(?P<authenticated_sender>[\w\.\-\@]+)\)|)\s*by\s+(?P<by_hostname>[\S]+)\s*(\((?P<by_hostname2>[\S]*)\s*\[((?P<by_ipv6>[a-f\:\d]+)|)(?P<by_ip>[\d\.]+)\]\)|)\s*(\([^\)]*\)|)\s*(\(Postfix\)|)\s*(with\s+(?P<protocol>\w*)|)\s*id\s+(?P<id>[\w\-]+)\s*(for\s+\<(?P<envelope_for>[\w\.\@]+)\>|)", "postfix"), #postfix
        ("(from\s+(?P<from_name>[\[\S\]]+)\s+\(((?P<from_hostname>[\S]*)|)\s*\[(IPv6\:(?P<from_ipv6>[a-f\d\:]+)|)\]\)\s*(\(using\s+(?P<tls>[\w\.]+)\s+with\s+cipher\s+(?P<cipher>[\w\-]+)\s+\([\w\/\s]+\)\)\s+(\(No\s+client\s+certificate\s+requested\)|)|)|)\s*(\(Authenticated\s+sender\:\s+(?P<authenticated_sender>[\w\.\-\@]+)\)|)\s*by\s+(?P<by_hostname>[\S]+)\s*(\((?P<by_hostname2>[\S]*)\s*\[((?P<by_ipv6>[a-f\:\d]+)|)(?P<by_ip>[\d\.]+)\]\)|)\s*(\([^\)]*\)|)\s*(\(Postfix\)|)\s*(with\s+(?P<protocol>\w+)|)\s*id\s+(?P<id>[\w\-]+)\s*(for\s+\<(?P<envelope_for>[\w\.\@]+)\>|)", "postfix"),#POSTFIX
        ("\s*from\s+\[?(?P<from_ip>[\d\.\:]+)\]?\s*(\((port=\d+|)\s*helo=(?P<from_name>[\[\]\w\.\:\-]+)\)|)\s+by\s+(?P<by_hostname>[\w\-\.]+)\s+with\s+(?P<protocol>\w+)\s*(\((?P<cipher>[\w\.\:\_\-]+)\)|)\s*(\(Exim\s+(?P<exim_version>[\d\.\_]+)\)|)\s*\(envelope-from\s+<?(?P<envelope_from>[\w\@\-\.]*)>?\s*\)\s*id\s+(?P<id>[\w\-]+)\s*\s*(for\s+<?(?P<envelope_for>[\w\.\@]+)>?|)", "exim"), #exim
        ("\s*from\s+(?P<from_hostname>[\w\.]+)\s+\(\[?(?P<from_ip>[\d\.\:a-f]+)\]?(\:\d+|)\s*(helo\=\[?(?P<from_name>[\w\.\:\-]+)|)\]?\)\s+by\s+(?P<by_hostname>[\w\-\.]+)\s+with\s+(?P<protocol>\w+)\s+(\((?P<cipher>[\w\.\:\_]+)\)|)\s*\(Exim\s+(?P<exim_version>[\d\.\_]+)\)\s*\(envelope-from\s+\<(?P<envelope_from>[\w\@\-\.]+)\>\s*\)\s*id\s+(?P<id>[\w\-]+)\s*(for\s+(?P<envelope_for>[\w\.\@]+)|)", "exim"),# exim
        ("from\s+(?P<from_name>[\w\.\-]+)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\s+\(Exim\s+(?P<version>[\d\.]+)\)\s+\(envelope-from\s+<*(?P<envelope_from>[\w\.\-\@]+)>*\)\s+id\s+(?P<id>[\w\.\-]+)\s+for\s+<?(?P<envelope_for>[\w\.\-\@]+)>?", "exim"), #exim
        ("from\s+(?P<from_name>[\[\]\w\-\.]+)\s+\(((?P<from_hostname>[\w\.\-]+)|)\s*\[(?P<from_ip>[\da-f\.\:]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(Oracle\s+Communications\s+Messaging\s+Server\s+(?P<oracle_version>[\w\.\-]+)(\([\d\.]+\)|)\s+(32bit|64bit|)\s*(\([^\)]+\)|)\)\s*with\s+(?P<protocol>\w+)\s+id\s+\<?(?P<id>[\w\@\.\-]+)\>?", "Oracle Communication Messaging Server"), #Oracle
        ("from\s+(?P<from_hostname>[\w\-\.]+)\s+\(\[(?P<from_ip>[\d\.\:a-f]+)\]\s+helo=(?P<from_name>[\w\.\-]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\s+\(ASSP\s+(?P<assp_version>[\d\.]+)\s*\)", "ASSP"), #ASSP
        ("from\s+(?P<from_hostname>[\[\]\d\w\.\-]+)\s+\(\[\[?(?P<from_ip>[\d\.]+)(\:\d+|)\]\s*(helo=(?P<from_name>[\w\.\-]+)|)\s*\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(envelope-from\s+\<?(?P<envelope_from>[^>]+)\>?\)\s+\(ecelerity\s+(?P<version>[\d\.]+)\s+r\([\w\-\:\.]+\)\)\s+with\s+(?P<protocol>\w+)\s*(\(cipher=(?P<cipher>[\w\-\_]+)\)|)\s*id\s+(?P<id>[\.\-\w\/]+)", "ecelerity"), #ecelerity
        ("from\s+(?P<from_name>[\[\]\w\.\-]+)\s+\(((?P<from_hostname>[\w\.\-]+)|)\s*(\[(?P<from_ip>[\d\.\:a-f]+)\]|)\)\s*by\s+(?P<by_hostname>[\w\.\-]+)\s+(\([\w\.\-\=]+\)|)\s+with\s+(?P<protocol>\w+)\s+\(Nemesis\)\s+id\s+(?P<id>[\w\.\-]+)\s*(for\s+\<?(?P<envelope_for>[\w\.\@\-]+)\>?|)", "nemesis"), #nemesis
        ("\(qmail\s+\d+\s+invoked\s+(from\s+network|)(by\s+uid\s+\d+|)\)", "qmail"), #WTF qmail
        ("from\s+\[?(?P<from_ip>[\d\.a-f\:]+)\]?\s+\(account\s+<?(?P<envelope_from>[\w\.\@\-]+)>?\s+HELO\s+(?P<from_name>[\w\.\-]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]*)\s+\(CommuniGate\s+Pro\s+SMTP\s+(?P<version>[\d\.]+)\)\s+with\s+(?P<protocol>\w+)\s+id\s+(?P<id>[\w\-\.]+)\s+for\s+<?(?P<envelope_for>[\w\.\-\@]+)>?", "CommuniGate"), #CommuniGate
        ("from\s+(?P<from_ip>[\d\.\:a-f]+)\s+\(SquirrelMail\s+authenticated\s+user\s+(?P<envelope_from>[\w\@\.\-]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)", "SquirrelMail"),
        ("by\s+(?P<by_hostname>[\w\.\-]+)\s+\((?P<protocol>\w+)\s+sendmail\s*(emulation|)\)", "sendmail"), #sendmail
        ("from\s+(?P<from_name>[\[\]\w\.\-]+)\s+\(\[(?P<from_hostname>[\w\.\-]+)\]\s+\[(?P<from_ip>[\d\.a-f\:]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(Sun\s+Java\(tm\)\s+System\s+Messaging\s+Server\s+(?P<version>[\w\.\-]+)\s+\d+bit\s+\(built\s+\w+\s+\d+\s+\d+\)\)\s+with\s+(?P<protocol>\w+)\s+id\s+<?(?P<id>[\w\.\-\@]+)>?", "Sun Java System Messaging Server"), # Sun Java System Messaging Server
        ("from\s+(?P<from_name>[\w\.\-\[\]]+)\s+\((?P<from_ip>[\d\.a-f\:]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(Axigen\)\s+with\s+(?P<protocol>\w+)\s+id\s+(?P<id>[\w\.\-]+)", "Axigen"), #axigen
        ("from\s+(?P<from_name>[\w\.\-]+)\s+\((?P<from_hostname>[\w\.\-]+)\s+\[(?P<from_ip>[\d\.a-f\:]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(Horde\s+MIME\s+library\)\s+with\s+(?P<protocol>\w+)", "Horde MIME library"), #Horde
        ("from\s+(?P<from_name>[\w\.\-\[\]]+)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(PGP\s+Universal\s+Service\)", "PGP Universal Service", "local"), # PGP Universal Service
        ("from\s+(?P<from_name>[\w\.\-]+)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\s+\(Sophos\s+PureMessage\s+Version\s+(?P<version>[\d\.\-]+)\)\s+id\s+(?P<id>[\w\.\-]+)\s+for\s+(?P<envelope_for>[\w\.\-\@]+)", "Sophos PureMessage"), #Sophos PureMessage
        ("by\s+(?P<by_ip>[\d\.\:a-f]+)\s+with\s+(?P<protocol>\w+)", "unknown"), # other
        ("from\s+(?P<from_name>[\w\.\-]+)\s+\#?\s*(\(|\[|\(\[)\s*(?P<from_ip>[\d\.\:a-f]+)\s*(\]|\)|\]\))\s+by\s+(?P<by_hostname>[\w\.\-]+)(\s+\([\w\.\s\/]+\)|)\s*(with\s+(?P<protocol>\w+)|)\s*(id\s+(?P<id>[\w]+)|)(\(\-\)|)\s*(for\s+\<(?P<envelope_for>[\w\@\.]+)\>?|)", "unknown"), #unknown
        ("from\s+(?P<from_hostname>[\w\.\-]+)\s*\(HELO\s+(?P<from_name>[\w\.\-]+)\)\s*\(\[?(?P<from_ip>[\d\.\:a-f]+)\]?\)\s+by\s+(?P<by_hostname>[\w\.\-]+)(\s+\([\d\.]+\)|)\s*(with\s+(?P<protocol>\w+)|)\s*(id\s+(?P<id>[\w]+)|)(\(\-\)|)", "unknown"), #other other
        ("from\s+([\(\[](?P<from_ip>[\d\.\:a-f]+)[\)\]]|)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+id\s+(?P<id>\w+)\s*(with\s+(?P<protocol>\w+)|)\s*\s*(for\s+\<(?P<envelope_for>[\w\@\.\-]+)\>|)", "unknown"),#other
        ("from\s+(?P<from_hostname>[\w\.]+)\s+(\(HELO\s+(?P<from_name>[\w\.\-]+)\)|)\s*(\((?P<from_ip>[\da-f\.\:]+)\)|)\s*by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<cipher>[\w\-]+)\s+encrypted\s+SMTP", "unknown"), #unknown
        ("from\s+(?P<from_hostname>[\w\.\-]+)\s+(\(HELO\s+(?P<from_name>[\w\.\-]+)\)|)\s+\((?P<envelope_from>[\w\.]+\@[\w\.]+)\@(?P<from_ip>[\da-d\.\:]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)", "unknown"), #unknown
        ("from\s+(?P<from_hostname>[\w\.\-]+)\s+\(HELO\s+(?P<from_name>[\w\.\-\?]+)\)\s+\(\w+\@[\w\.]+\@(?P<from_ip>[\d\.a-f\-]+)_\w+\)\s+by\s+(?P<by_hostname>[\w\.\-\:]+)\s+with\s+(?P<protocol>\w+)", "unknown"), #unknown
        ("from\s+(?P<from_name>[\w\.\-\[\]]+)\s+\(\[(?P<from_ip>[\da-f\.\:]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(\[(?P<by_ip>[\d\.a-f\:]+)\]\)\s+with\s+(?P<protocol>\w+)", "unknown"), #unknown
        ]
    @staticmethod
    def parse(header):
        # TODO : objects and precompile regex
        # TODO : add server types (local, webmail, relay...)
        # Separate timestamp after the ;
        parts = header.split(";")
        if len(parts) != 2:
            raise ReceivedParserError("Invalid format, no timestamp")

        # Parse the timestamp first
        # Some headers avec envelop from after the ; :(
        if "envelope" in parts[1]:
            p = parts[1].split('(')[0].replace('\n', '')
            data = {'timestamp': parse(p)}
        else:
            data = {'timestamp': parse(parts[1].replace('\n', ''))}

        # parse the hard part
        found = False
        for regex in ReceivedParser.regexes:
            match = re.match(regex[0], parts[0], re.IGNORECASE)
            if match:
                data['server'] = regex[1]
                found = True
                break

        if not found:
            raise ReceivedParserError("Unknown header format")
        return {**data, **match.groupdict()}


