import unittest
from pyreceived import ReceivedParser, ReceivedParserError


class TestReceivedParser(unittest.TestCase):
    def test_header1_exchange(self):
        header = "from relay.email.com (192.168.10.10) by\n EXCHANGE.email.local (192.168.100.51) with Microsoft SMTP Server id\n 14.3.123.3; Sat, 6 Jun 2015 05:34:59 +0200"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'relay.email.com')
        self.assertEqual(data['from_ip'], '192.168.10.10')
        self.assertEqual(data['by_hostname'], 'EXCHANGE.email.local')
        self.assertEqual(data['by_ip'], '192.168.100.51')
        self.assertEqual(data['id'], '14.3.123.3')
        self.assertEqual(data['server'], 'MS SMTP Server')

    def test_exchange2(self):
        header = "from EXCHANGE.example.local ([fe80::755c:1705:6a98:dcff]) by\n EXCHANGE.example.local ([fe80::755c:1705:6a98:dcff%11]) with mapi id\n 14.03.0123.003; Mon, 1 Jun 2015 09:59:24 +0200"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'EXCHANGE.example.local')
        self.assertEqual(data['from_ip'], 'fe80::755c:1705:6a98:dcff')
        self.assertEqual(data['by_hostname'], 'EXCHANGE.example.local')
        self.assertEqual(data['by_ip'], 'fe80::755c:1705:6a98:dcff')
        self.assertEqual(data['id'], '14.03.0123.003')

    def test_exchange3(self):
        header = "from VE1EUR02FT025.eop-EUR02.prod.protection.outlook.com\n\t(10.152.12.54) by VE1EUR02HT051.eop-EUR02.prod.protection.outlook.com\n\t(10.152.13.18) with Microsoft SMTP Server (version=TLS1_2,\n\tcipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384) id 15.20.735.16; Mon, 7\n\tMay 2018 09:58:55 +0000"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'VE1EUR02FT025.eop-EUR02.prod.protection.outlook.com')
        self.assertEqual(data['from_ip'], '10.152.12.54')
        self.assertEqual(data['by_hostname'], 'VE1EUR02HT051.eop-EUR02.prod.protection.outlook.com')
        self.assertEqual(data['by_ip'], '10.152.13.18')
        self.assertEqual(data['cipher'], 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384')
        self.assertEqual(data['tls'], 'TLS1_2')

    def test_exchange4(self):
        header = "from EUR03-VE1-obe.outbound.protection.outlook.com ([65.54.190.201]) by BAY004-OMC4S3.hotmail.com over TLS secured channel with Microsoft SMTPSVC(7.5.7601.23008);\n\tMon, 5 Dec 2016 04:36:38 -0800"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'EUR03-VE1-obe.outbound.protection.outlook.com')
        self.assertEqual(data['from_ip'], '65.54.190.201')
        self.assertEqual(data['by_hostname'], 'BAY004-OMC4S3.hotmail.com')

    def test_exchange5(self):
        header = "from 486006-USEXCH02.CMP.LOCAL ([fe80::250:56ff:fe85:5095%11]) by\n\t486006-USEXCH02.CMP.LOCAL ([fe80::250:56ff:fe85:5095%11]) with Microsoft SMTP\n\tServer id 14.03.0123.003; Tue, 24 Jun 2014 10:16:07 -0500"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], '486006-USEXCH02.CMP.LOCAL')
        self.assertEqual(data['from_ip'], 'fe80::250:56ff:fe85:5095')
        self.assertEqual(data['by_hostname'], '486006-USEXCH02.CMP.LOCAL')
        self.assertEqual(data['by_ip'], 'fe80::250:56ff:fe85:5095')

    def test_exchange6(self):
        header = "from mail pickup service by REG10APP02TTN.regus.local with Microsoft\n\tSMTPSVC;   Mon, 26 Jan 2015 10:18:41 +0000"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['by_hostname'], 'REG10APP02TTN.regus.local')

    def test_exchange7(self):
        header = "from [1.2.3.4] (1.2.3.4) by EXCHANGE.example.org\n\t(192.168.100.51) with Microsoft SMTP Server (TLS) id 14.3.123.3; Tue, 25 Feb\n\t2014 18:39:45 +0100"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], '[1.2.3.4]')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'EXCHANGE.example.org')

    def test_exchange8(self):
        header = "from (1.2.3.4) by exchange.example.org (192.168.100.80) with\n\tMicrosoft SMTP Server id 14.3.195.1; Wed, 15 Oct 2014 11:18:39 +0200"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], '')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'exchange.example.org')
        self.assertEqual(data['by_ip'], '192.168.100.80')

    def test_oracle1(self):
        header = "from imac.home ([1.2.3.4]) by vms173023.example.net\n (Oracle Communications Messaging Server 7.0.5.32.0 64bit (built Jul 16 2014))\n with ESMTPA id <0NOT00G7OC3ASW70@vms173023.example.net>; Sat, 23 May 2015\n 12:18:52 -0500 (CDT)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'imac.home')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'vms173023.example.net')
        self.assertEqual(data['id'], '0NOT00G7OC3ASW70@vms173023.example.net')

    def test_oracle2(self):
        header = "from [172.20.10.2] (222.example.com [1.2.3.4]) by\n\tnk11p04mm-asmtp001.mac.com (Oracle Communications Messaging Server\n\t7u4-27.10(7.0.4.27.9) 64bit (built Jun  6 2014)) with ESMTPSA id\n\t<0NAO00IYBQIH6O60@nk11p04mm-asmtp001.mac.com>; Fri, 22 Aug 2014 01:52:13\n\t +0000 (GMT)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], '[172.20.10.2]')
        self.assertEqual(data['from_hostname'], '222.example.com')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'nk11p04mm-asmtp001.mac.com')

    def test_postfix1(self):
        header = "from [192.168.50.50] (128-144.email.example.com\n [1.2.3.4])       (using TLSv1 with cipher ECDHE-RSA-AES256-SHA (256/256\n bits)) (No client certificate requested)       by mail.example44.it (Postfix)\n with ESMTPSA id E333C4440493;  Sat,  6 Jun 2015 05:34:06 +0200 (CEST)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], '[192.168.50.50]')
        self.assertEqual(data['from_hostname'], '128-144.email.example.com')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['cipher'], 'ECDHE-RSA-AES256-SHA')
        self.assertEqual(data['by_hostname'], 'mail.example44.it')
        self.assertEqual(data['id'], 'E333C4440493')
        self.assertEqual(data['server'], 'postfix')

    def test_postfix2(self):
        header = "by mail.example.org (Postfix)      id E6F0C4440B28; Sat,  6 Jun 2015\n 05:34:06 +0200 (CEST)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['by_hostname'], 'mail.example.org')
        self.assertEqual(data['id'], 'E6F0C4440B28')

    def test_postfix3(self):
        header = "from mail.example.org (unknown [192.168.100.50])   by\n relay.example.com (Postfix) with ESMTP id 78121621DE;      Sat,  6 Jun 2015\n 04:10:45 +0100 (BST)'"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'mail.example.org')
        self.assertEqual(data['from_hostname'], 'unknown')
        self.assertEqual(data['from_ip'], '192.168.100.50')
        self.assertEqual(data['by_hostname'], 'relay.example.com')
        self.assertEqual(data['id'], '78121621DE')
        self.assertEqual(data['protocol'], 'ESMTP')

    def test_postfix4(self):
        header = "from spool.mail.gandi.net (spool4.mail.gandi.net [1.2.3.4])\n\tby d000.example.org (Postfix) with ESMTP id 8A5FB20292\n\tfor <user@example.org>; Thu, 24 May 2018 15:32:35 +0000 (UTC)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'spool.mail.gandi.net')
        self.assertEqual(data['from_hostname'], 'spool4.mail.gandi.net')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'd000.example.org')
        self.assertEqual(data['protocol'], 'ESMTP')
        self.assertEqual(data['id'], '8A5FB20292')
        self.assertEqual(data['envelope_for'], 'user@example.org')

    def test_postfix5(self):
        header = "from smtp5-g21.free.fr (smtp5-g21.free.fr [1.2.3.4])\n\tby spool.mail.gandi.net (Postfix) with ESMTPS id 8FA42780640\n\tfor <user@example.org>; Thu, 24 May 2018 17:31:58 +0200 (CEST)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'smtp5-g21.free.fr')
        self.assertEqual(data['from_hostname'], 'smtp5-g21.free.fr')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'spool.mail.gandi.net')
        self.assertEqual(data['id'], '8FA42780640')
        self.assertEqual(data['envelope_for'], 'user@example.org')

    def test_postfix6(self):
        header = "from [1.2.3.4] (unknown [4.5.6.7])\t(using TLSv1 with cipher\n ECDHE-RSA-AES256-SHA (256/256 bits))\t(No client certificate requested)\tby\n mail.example.it (Postfix) with ESMTPSA id BA5D84440493;\tSat,  6 Jun 2015\n 05:18:42 +0200 (CEST)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], '[1.2.3.4]')
        self.assertEqual(data['from_hostname'], 'unknown')
        self.assertEqual(data['from_ip'], '4.5.6.7')
        self.assertEqual(data['by_hostname'], 'mail.example.it')
        self.assertEqual(data['id'], 'BA5D84440493')

    def test_postfix7(self):
        header = "from [192.168.13.10] (unknown.it\n [12.34.56.78])\t(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256\n (128/128 bits))\t(No client certificate requested)\tby mail.example.org\n (Postfix) with ESMTPSA id 6C5D94440493\tfor <user@example.org>; Fri,  5 Jun\n 2015 21:58:25 +0200 (CEST)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], '[192.168.13.10]')
        self.assertEqual(data['from_hostname'], 'unknown.it')
        self.assertEqual(data['from_ip'], '12.34.56.78')
        self.assertEqual(data['by_hostname'], 'mail.example.org')
        self.assertEqual(data['id'], '6C5D94440493')

    def test_postfix8(self):
        header = "from mail.user.it (mail.user.it [10.2.2.2]) by\n manta.example.org with ESMTP id zd3xinp0NwYvANyH for\n <vt@example.org>; Fri, 05 Jun 2015 18:47:29 +0200 (CEST)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'mail.user.it')
        self.assertEqual(data['from_hostname'], 'mail.user.it')
        self.assertEqual(data['from_ip'], '10.2.2.2')
        self.assertEqual(data['by_hostname'], 'manta.example.org')

    def test_postfix9(self):
        header = "from mail.lab.it ([127.0.0.1])\tby localhost (mail.lab.it\n [127.0.0.1]) (server, port 10024)\twith ESMTP id Czb9AlcNsGzC; Fri,  5\n Jun 2015 18:47:27 +0200 (CEST)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'mail.lab.it')
        self.assertEqual(data['from_hostname'], '')
        self.assertEqual(data['from_ip'], '127.0.0.1')
        self.assertEqual(data['by_hostname'], 'localhost')

    def test_postfix10(self):
        header = "from MacBook-di-Alessandro.local (unknown [192.168.1.211])\t(using\n TLSv1.2 with cipher ECDHE-RSA-AES256-SHA384 (256/256 bits))\t(No client\n certificate requested)\tby mail.example.org (Postfix) with ESMTPSA id\n CB7764440B4C;\tWed,  3 Jun 2015 17:38:29 +0200 (CEST)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'MacBook-di-Alessandro.local')
        self.assertEqual(data['from_hostname'], 'unknown')
        self.assertEqual(data['from_ip'], '192.168.1.211')
        self.assertEqual(data['by_hostname'], 'mail.example.org')

    def test_postfix11(self):
        header = "from spool.mail.gandi.net ([IPv6:::ffff:10.0.21.133])\n\tby mfilter29-d.gandi.net (mfilter29-d.gandi.net [::ffff:10.0.15.180]) (amavisd-new, port 10024)\n\twith ESMTP id hNIzmcVXx3-V for <user@example.com>;\n\tSat, 31 Dec 2016 21:18:12 +0100 (CET)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'spool.mail.gandi.net')
        self.assertEqual(data['from_ip'], '10.0.21.133')
        self.assertEqual(data['by_hostname'], 'mfilter29-d.gandi.net')

    def test_postfix12(self):
        header = "from mail-wm0-x22c.google.com (mail-wm0-x22c.google.com [IPv6:2a00:1450:400c:c09::22c])\n\tby spool.mail.gandi.net (Postfix) with ESMTPS id AB7EE17803E\n\tfor <user@example.org>; Sat, 31 Dec 2016 21:18:12 +0100 (CET)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'mail-wm0-x22c.google.com')
        self.assertEqual(data['from_ipv6'], '2a00:1450:400c:c09::22c')
        self.assertEqual(data['by_hostname'], 'spool.mail.gandi.net')

    def test_postfix13(self):
        header = "from [192.168.1.22] (ip.44.rev.sfr.net [1.2.3.4])\n\t(Authenticated sender: user@example.org)\n\tby relay4-d.mail.gandi.net (Postfix) with ESMTPSA id 8763417209D\n\tfor <user@example.org>; Mon, 28 Mar 2016 10:31:43 +0200 (CEST)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], '[192.168.1.22]')
        self.assertEqual(data['from_hostname'], 'ip.44.rev.sfr.net')
        self.assertEqual(data['by_hostname'], 'relay4-d.mail.gandi.net')

    def test_postfix14(self):
        header = "from servername (server.example.org [1.2.3.4] (may be\n\tforged))   by server2.example.com with ESMTP id 1qv2xty0hs-7082   for\n\t<USER@EXAMPLE.ORG>; Fri, 09 Jan 2015 11:40:33 +0000"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'servername')
        self.assertEqual(data['from_hostname'], 'server.example.org')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'server2.example.com')

    def test_postfix15(self):
        header = "from [10.0.1.11] ([1.2.3.4])    by\n\tp3plsmtp.example.com with     id 4KyS1p00T4yQ7hw01KyTCQ;\n\tFri, 17 Oct 2014 12:58:31 -0700"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], '[10.0.1.11]')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'p3plsmtp.example.com')
        self.assertEqual(data['server'], 'postfix')

    def test_exim1(self):
        header = "from [1.2.3.4] (helo=[4.5.6.7])\n\tby mail-serveur with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)\n\t(Exim 4.84_2)\n\t(envelope-from <lol@example.org>)\n\tid 1fLsDO-0006c5-UC; Thu, 24 May 2018 17:31:43 +0200"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['from_name'], '[4.5.6.7]')
        self.assertEqual(data['by_hostname'], 'mail-serveur')
        self.assertEqual(data['protocol'], 'esmtpsa')
        self.assertEqual(data['cipher'], 'TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128')
        self.assertEqual(data['envelope_from'], 'lol@example.org')

    def test_exim2(self):
        header = "from localhost ([127.0.0.1]:46248 helo=server1.example)\tby\n server1.example with esmtpa (Exim 4.85)\t(envelope-from\n <user@example.org>)\tid 1Yhufq-0004Mt-6z; Tue, 14 Apr 2015 14:50:18\n +0800"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_ip'], '127.0.0.1')
        self.assertEqual(data['from_hostname'], 'localhost')
        self.assertEqual(data['from_name'], 'server1.example')
        self.assertEqual(data['by_hostname'], 'server1.example')
        self.assertEqual(data['protocol'], 'esmtpa')
        self.assertEqual(data['envelope_from'], 'user@example.org')

    def test_exim3(self):
        header = "from 254.253.2.109.rev.sfr.net ([109.2.253.254])\tby\n grb212uploads.mooo.com with smtp (Exim 4.82)\t(envelope-from\n <recipient@example.org>)\tid 1XxTav-0002JM-P9\tfor user@example.org; Sun,\n 07 Dec 2014 04:37:18 +0000"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_ip'], '109.2.253.254')
        self.assertEqual(data['from_name'], None)
        self.assertEqual(data['from_hostname'], '254.253.2.109.rev.sfr.net')
        self.assertEqual(data['by_hostname'], 'grb212uploads.mooo.com')

    def test_exim4(self):
        header = "from [1.2.3.4] (port=52853 helo=[192.168.1.100])    by\n\tgator4129.hostgator.com with esmtpsa (UNKNOWN:DHE-RSA-AES256-GCM-SHA384:256)\n\t(Exim 4.82) (envelope-from <user2l@example.org>) id 1Yaixf-0004rk-UE for\n\tuser@example.org; Wed, 25 Mar 2015 05:55:00 -0500"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['from_name'], '[192.168.1.100]')
        self.assertEqual(data['by_hostname'], 'gator4129.hostgator.com')
        self.assertEqual(data['server'], 'exim')

    def test_exim5(self):
        header = "from apache by example.com with local (Exim 4.67)    (envelope-from\n\t<sender@example.com>)   id S3E9AW-L5D4OI-CH for <recipient@example.org>;\n\tWed, 28 May 2014 16:49:20 +1000"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'apache')
        self.assertEqual(data['by_hostname'], 'example.com')
        self.assertEqual(data['envelope_from'], 'sender@example.com')
        self.assertEqual(data['envelope_for'], 'recipient@example.org')
        self.assertEqual(data['server'], 'exim')

    def test_exim6(self):
        header = "from 1.2.3.4(helo=example.org)   by example.com with\n\tesmtpa (Exim 4.69) (envelope-from )    id 1MMY77-8710lz-RW for\n\t<staff@example.com>; Mon, 30 Sep 2013 03:37:21 +0100"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'example.org')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'example.com')
        self.assertEqual(data['envelope_from'], '')
        self.assertEqual(data['envelope_for'], 'staff@example.com')
        self.assertEqual(data['server'], 'exim')

    def test_exim7(self):
        header = "from [1.2.3.4] (port=51157 helo=BLK) by BLK with esmtp\n\t(envelope-from <Q8-HXba-dgfQi-v5W2E-xUqle@BLK>) id vmweDN-00001e-dE for\n\t user@example.org; Tue, 05 Nov 2013 09:10:39 +0000"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'BLK')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'BLK')
        self.assertEqual(data['envelope_from'], 'Q8-HXba-dgfQi-v5W2E-xUqle@BLK')
        self.assertEqual(data['envelope_for'], 'user@example.org')
        self.assertEqual(data['server'], 'exim')

    def test_exim8(self):
        header = "from [1.2.3.4] (helo=1-2-3-4.example.org) by\n\thades.example.org with esmtp (Exim 4.72)  (envelope-from\n\t<from@example.org>)  id 1XcKum-0003So-L1 for\n\tto@example.org; Thu, 09 Oct 2014 23:06:25 +0200"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], '1-2-3-4.example.org')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'hades.example.org')
        self.assertEqual(data['envelope_from'], 'from@example.org')
        self.assertEqual(data['envelope_for'], 'to@example.org')
        self.assertEqual(data['server'], 'exim')

    def test_assp1(self):
        header = "from server1 ([1.2.3.4] helo=server1) by\n\texample.org with ESMTP (ASSP 1.9.9); 14 Apr 2015 14:50:17 +0800"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['from_hostname'], 'server1')
        self.assertEqual(data['from_name'], 'server1')
        self.assertEqual(data['by_hostname'], 'example.org')
        self.assertEqual(data['protocol'], 'ESMTP')

    def test_ecelerity1(self):
        header = "from [10.1.8.1] ([10.1.8.1:41412] helo=abmas01.marketo.org)\tby\n abmta03.marketo.org (envelope-from <user@example.org>)\t(ecelerity\n 3.6.4.44580 r(Platform:3.6.4.1)) with ESMTP\tid 43/97-60201-DE17D155; Thu, 02\n Apr 2015 11:44:29 -0500"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_ip'], '10.1.8.1')
        self.assertEqual(data['from_hostname'], '[10.1.8.1]')
        self.assertEqual(data['from_name'], 'abmas01.marketo.org')
        self.assertEqual(data['by_hostname'], 'abmta03.marketo.org')
        self.assertEqual(data['protocol'], 'ESMTP')

    def test_ecelerity2(self):
        header = "from [10.0.0.51] ([10.0.0.51:0996]\n helo=1234.example.org)\tby FDC7270 (envelope-from\n <user@example.org>)\t(ecelerity 3.5.1.37854 r(Momo-dev:3.5.1.0))\n with ESMTP\tid 9F/B3-489A4-1A4FB098; Mon, 23 Feb 2015 09:30:58 -0500"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_ip'], '10.0.0.51')
        self.assertEqual(data['from_hostname'], '[10.0.0.51]')
        self.assertEqual(data['from_name'], '1234.example.org')
        self.assertEqual(data['by_hostname'], 'FDC7270')
        self.assertEqual(data['protocol'], 'ESMTP')

    def test_ecelerity3(self):
        header = "from [10.220.136.203] ([10.220.136.203:60938] helo=na47-app2-11-dfw.ops.sfdc.net)\n\tby mx4-dfw-sp3.mta.salesforce.com (envelope-from <support@twitter.com>)\n\t(ecelerity 3.6.25.56547 r(Core:3.6.25.0)) with ESMTPS (cipher=ECDHE-RSA-AES256-GCM-SHA384) \n\tid BD/7B-10868-A85F2CA5; Tue, 03 Apr 2018 03:31:22 +0000"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_ip'], '10.220.136.203')
        self.assertEqual(data['from_hostname'], '[10.220.136.203]')
        self.assertEqual(data['from_name'], 'na47-app2-11-dfw.ops.sfdc.net')
        self.assertEqual(data['by_hostname'], 'mx4-dfw-sp3.mta.salesforce.com')
        self.assertEqual(data['protocol'], 'ESMTPS')

    def test_ecelerity4(self):
        header = "from [1.2.3.4] ([1.2.3.4:11527] helo=localhost.localdomain) by\n\treturnpath.example.org (envelope-from\n\t<bounce-use=M=28052037815=echo4=ABAD51E2652A00D5A4C7882624EFBC5B@returnpath.example.com>)\n\t(ecelerity 3.5.3.37097 r(Platform:3.5.3.0)) with ESMTP  id\n\t52/34-40305-20E54345; Tue, 07 Oct 2014 14:41:22 -0700"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['from_hostname'], '[1.2.3.4]')
        self.assertEqual(data['from_name'], 'localhost.localdomain')
        self.assertEqual(data['by_hostname'], 'returnpath.example.org')

    def test_ecelerity5(self):
        header = "from [1.2.3.4] ([[1.2.3.4:12140]) by\n\thosting.example.org (envelope-from\n\t<update+wgfFpLIXcrhi@hosting.example.org>) (ecelerity 2.2.2.45 r(34222M))\n\twith ECSTREAM id xS/71-64990-83274771; Fri, 07 Nov 2014 12:03:25 +0100"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['from_hostname'], '[1.2.3.4]')
        self.assertEqual(data['by_hostname'], 'hosting.example.org')
        self.assertEqual(data['server'], 'ecelerity')

    def test_nemesis(self):
        header = "from [192.168.1.132] ([1.2.3.4]) by mail.server.example.org\n\t(server1) with ESMTPA (Nemesis) id 0M9GoA-1Yx9783qd4-00ChEw for\n\t<a.b.c@example.org>; Wed, 06 May 2015 17:15:53 +0200"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['from_name'], '[192.168.1.132]')
        self.assertEqual(data['by_hostname'], 'mail.server.example.org')
        self.assertEqual(data['envelope_for'], 'a.b.c@example.org')

    def test_nemesis2(self):
        header = "from [10.0.1.2] (server.fastwebnet.it [1.2.3.4])  by\n\trelay.server.example.org (node=server104) with ESMTP (Nemesis)  id\n\t0LvAna-1WRMgI2ZYg-010POX; Wed, 23 Jul 2014 10:55:24 +0200"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['from_name'], '[10.0.1.2]')
        self.assertEqual(data['from_hostname'], 'server.fastwebnet.it')
        self.assertEqual(data['by_hostname'], 'relay.server.example.org')
        self.assertEqual(data['server'], 'nemesis')

    def test_squirrelmail(self):
        header = "from 1.2.3.4        (SquirrelMail authenticated user\n\t       user@example.com)        by webmail.example.org with HTTP;        Thu, 27\n          Feb 2014 14:41:31 +0100 (CET)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'webmail.example.org')
        self.assertEqual(data['envelope_from'], 'user@example.com')
        self.assertEqual(data['server'], 'SquirrelMail')

    def test_communigate1(self):
        header = "from [1.2.3.4] (account user@google.com HELO\n\tserver.example.com) by sender.example.org\n\t(CommuniGate Pro SMTP 5.2.3)  with ESMTPA id 960713191 for\n\tuser@example.org; Mon, 14 Oct 2013 21:43:21 -0600"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['from_name'], 'server.example.com')
        self.assertEqual(data['by_hostname'], 'sender.example.org')
        self.assertEqual(data['envelope_from'], 'user@google.com')
        self.assertEqual(data['server'], 'CommuniGate')

    def test_communigate2(self):
        header = "from [4.5.6.7] (account user@google.com HELO\n\tserver.example.org)   by  (CommuniGate Pro SMTP 5.2.3)    with ESMTPA id\n\t192459198 for staff@example.com; Mon, 30 Sep 2013 15:12:33 +0700"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_ip'], '4.5.6.7')
        self.assertEqual(data['from_name'], 'server.example.org')
        self.assertEqual(data['by_hostname'], '')
        self.assertEqual(data['envelope_from'], 'user@google.com')
        self.assertEqual(data['server'], 'CommuniGate')

    def test_communigate3(self):
        header = "from  4.5.6.7 (account <staff@example.org> HELO\n\texample.org)   by example.com (CommuniGate Pro SMTP 5.2.3)  with ESMTPA id\n\t 557936202 for <staff@example.org>; Sat, 14 Sep 2013 19:19:52 +0700"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_ip'], '4.5.6.7')
        self.assertEqual(data['from_name'], 'example.org')
        self.assertEqual(data['by_hostname'], 'example.com')
        self.assertEqual(data['envelope_from'], 'staff@example.org')
        self.assertEqual(data['server'], 'CommuniGate')

    def test_sendmail(self):
        header = "by mobile (sSMTP sendmail emulation); Thu, 30 Jan 2014 15:01:23\n\t+0100"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['by_hostname'], 'mobile')
        self.assertEqual(data['server'], 'sendmail')

    def test_javasms(self):
        header = "from imac-27.home ([unknown] [1.2.3.4]) by\n\tvms173019.mailsrvcs.net (Sun Java(tm) System Messaging Server 7u2-7.02 32bit\n\t(built Apr 16 2009)) with ESMTPA id\n\t<0NAK0041N80S4K20@vms173019.mailsrvcs.net>; Tue, 19 Aug 2014 10:22:07 -0500 (CDT)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'imac-27.home')
        self.assertEqual(data['from_hostname'], 'unknown')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'vms173019.mailsrvcs.net')
        self.assertEqual(data['server'], 'Sun Java System Messaging Server')

    def test_javasms2(self):
        header = "from [192.168.1.27] ([unknown] [1.2.3.4]) by vms173023.mailsrvcs.net (Sun Java(tm) System Messaging Server 7u2-7.02 32bit (built Apr 16 2009)) with ESMTPA id \n\t <0MU300G1XGS72E30@vms173023.mailsrvcs.net>; Thu, 03 Oct 2013 08:14:37 -0500\n\t(CDT)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], '[192.168.1.27]')
        self.assertEqual(data['from_hostname'], 'unknown')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'vms173023.mailsrvcs.net')
        self.assertEqual(data['server'], 'Sun Java System Messaging Server')

    def test_axigen(self):
        header = "from [192.168.0.101] (1.2.3.4) by mx1 (Axigen) with ESMTPA id\n\t0FB2FB; Sat, 28 Dec 2013 16:04:57 +0100"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], '[192.168.0.101]')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'mx1')

    def test_horde(self):
        header = "from sender.example.com\n\t(sender.example.com [1.2.3.4]) by\n\trelay.example.org (Horde MIME library) with HTTP; Tue, 07 Apr 2009\n\t12:35:05 +0200"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'sender.example.com')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'relay.example.org')

    def test_pgp_service(self):
        header = "from [127.0.0.1]\n\tby MacBook-Pro.local (PGP Universal service);\n\tThu, 27 May 2010 16:31:50 +0200"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], '[127.0.0.1]')
        self.assertEqual(data['by_hostname'], 'MacBook-Pro.local')
        self.assertEqual(data['server'], 'PGP Universal Service')

    def test_sophos1(self):
        header = "from unknown-host\n\tby mail with queue (Sophos PureMessage Version 5.403) id 1040109-1\n\tfor user@example.org; Tue, 04 Nov 2008 08:20:44 GMT"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'unknown-host')
        self.assertEqual(data['by_hostname'], 'mail')
        self.assertEqual(data['server'], 'Sophos PureMessage')

    def test_other1(self):
        header = "by 10.27.97.72 with HTTP; Fri, 13 Feb 2015 04:57:11 -0800 (PST)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['by_ip'], '10.27.97.72')

    def test_other2(self):
        header = "from Monkeys-MacBook-Air.local (1.2.3.4) by example.org\n (8.6.060.43)        id 54100E9911F376EF; Fri, 6 Feb 2015 08:16:33 +0100"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['by_hostname'], 'example.org')
        self.assertEqual(data['from_name'], 'Monkeys-MacBook-Air.local')

    def test_other3(self):
        header = "from [212.247.11.153] by bran2.branneriet.se id MgPxU0vtURrs with\n SMTP; Sun, 28 Dec 2014 23:15:43 +0100"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['by_hostname'], 'bran2.branneriet.se')
        self.assertEqual(data['from_ip'], '212.247.11.153')

    def test_other4(self):
        header = "from [1.2.3.4] by vps.hosting.com id\n WxKUmx1L3trkk1e; Wed, 10 Dec 2014 06:31:53 +1100"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['by_hostname'], 'vps.hosting.com')
        self.assertEqual(data['from_ip'], '1.2.3.4')

    def test_other5(self):
        header = "from unknown (HELO USER-PC) ([1.2.3.4])  by\n\tserver.example.org with ESMTP; 31 May 2015 03:03:33 +0800"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['by_hostname'], 'server.example.org')
        self.assertEqual(data['from_ip'], '1.2.3.4')

    def test_other6(self):
        header = "from (127.0.0.1) by mail146.example.net id ho9h0i2ddl4g for <user@example.org>; Mon, 2 Apr 2018 17:01:57 +0000 (envelope-from <bounce-mc.us4_8849809.302417-user=example.org@mail146.example.net>)"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['envelope_for'], 'user@example.org')
        self.assertEqual(data['from_ip'], '127.0.0.1')
        self.assertEqual(data['by_hostname'], 'mail146.example.net')

    def test_other7(self):
        header = "from localhost ([127.0.0.1])  by mail146.example.net\n\t(-); Wed, 31 Dec 2014 04:34:04 -0800"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'localhost')
        self.assertEqual(data['from_ip'], '127.0.0.1')
        self.assertEqual(data['by_hostname'], 'mail146.example.net')

    def test_other8(self):
        header = "from UnknownHost [1.2.3.4] by ip38.example.com with SMTP;\n\tWed, 4 Jun 2014 18:30:01 +0800"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], 'UnknownHost')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'ip38.example.com')

    def test_wtf_qmail(self):
        header = "(qmail 29507 invoked from network); 28 Apr 2016 14:58:18 -0000"
        data = ReceivedParser.parse(header)

    def test_unknown(self):
        header = "from smtp.example.net (HELO outlook.example.net) (1.2.3.4)\n\tby server-16.example.com with AES256-SHA encrypted SMTP; 28 Apr 2016 14:58:18 -0000"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_hostname'], 'smtp.example.net')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'server-16.example.com')

    def test_unknown2(self):
        header = "from fbx.proxad.net (HELO MACHINE)\n\t(user@example.com@1.2.3.4)  by ns0.ovh.net with SMTP; 2 Oct 2013\n\t16:46:22 +0200"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_hostname'], 'fbx.proxad.net')
        self.assertEqual(data['from_name'], 'MACHINE')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'ns0.ovh.net')
        self.assertEqual(data['envelope_from'], 'user@example.com')

    def test_unknown3(self):
        header = "from 127.0.0.1 ( 127.0.0.1 )  by example.com\n\t(8.14.4/8.12.10/SuSE Linux 0.7) with ESMTP id s7KNbFEw000308   for\n\t<user@example.org>; Thu, 21 Aug 2014 03:37:15 +0400"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], '127.0.0.1')
        self.assertEqual(data['from_ip'], '127.0.0.1')

    def test_unknown4(self):
        header = "from unknown (HELO ?10.4.3.2?)\n\t(recidjvo@phaseit.com@1.2.3.4_trustedrelay)  by 192.168.0.240 with\n\tESMTPA; 9 Sep 2013 09:10:33 -0000"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], '?10.4.3.2?')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['from_hostname'], 'unknown')
        self.assertEqual(data['by_hostname'], '192.168.0.240')

    def test_unknown5(self):
        header = "from [1.2.3.4] ([1.2.3.4]) by\n\tserver.example.org ([4.5.6.7]) with SMTP;      Sun, 19 Oct 2014\n\t02:55:55 GMT"
        data = ReceivedParser.parse(header)
        self.assertEqual(data['from_name'], '[1.2.3.4]')
        self.assertEqual(data['from_ip'], '1.2.3.4')
        self.assertEqual(data['by_hostname'], 'server.example.org')
        self.assertEqual(data['by_ip'], '4.5.6.7')


if __name__ == '__main__':
    unittest.main()
