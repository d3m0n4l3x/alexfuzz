#!/usr/bin/perl -w
use IO::Socket;
use MIME::Base64 ();
use Thread;
$|=1;

print "Please DISABLE firewall daemon of this operating system first, Thank you!\n";

$host=shift;
$port="25";

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


sub restore_array(){
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

return @all;
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

#EHLO/HELO Fuzzing
print "EHLO/HELO Fuzzing.\n";
@helo=('EHLO', 'HELO');
@all1=&restore_array();
foreach $cmd (@helo){
	foreach (@all1) {
		LABEL1: $sock1=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
		if(defined($sock1)){
			undef($content);
			$sock1->recv($content, 500, 0);
			$sock1->send("$cmd $_\r\n", 0);
			sleep(5);
			$sock1->send("QUIT\r\n", 0);
			$sock1->close;
			$thread1=Thread->new(\&check);
			if($thread1->join()!=1){
				print "$cmd COMMAND Payload is $_.\n";
				print "Press <ENTER> to continue.\n";
				<STDIN>;
			}
			undef($thread1);
			$ehlo_or_helo_payload_tmp=$_;
		}else{
			print "$cmd COMMAND Payload maybe $ehlo_or_helo_payload_tmp.\n";
			print "$host -> $port is closed!\n";
			print "Please restart remote SMTP Daemon!\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
			goto LABEL1;
		}
	}
}

#USERNAME Fuzzing
print "USERNAME Fuzzing.\n";
@all2=&restore_array();
foreach $username_payload (@all2){
	LABEL2: $sock2=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined($sock2)){
		$sock2->recv($content, 500, 0);                      #banner [220]
		$sock2->send("EHLO fuzzing_for_test\r\n", 0);
		$sock2->recv($content, 500, 0);                      #banner detail [250]
		sleep(2);
		$sock2->send("AUTH LOGIN\r\n", 0);
		sleep(2);
		$sock2->recv($content, 500, 0);                      #require username [334]
		sleep(2);
		$sock2->send("$username_payload"."\r\n", 0);
		sleep(2);
		$sock2->recv($content, 500, 0);                      #require password [334]
		sleep(5);
		$thread2=Thread->new(\&check);
		if($thread2->join()!=1){
			print "USERNAME Payload is $username_payload.\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
		}
		undef($thread2);
		$sock2->send("QUIT\r\n", 0);
		$sock2->close;
		$username_payload_tmp=$username_payload;
	}else{
		print "USERNAME Payload maybe $username_payload_tmp.\n";
		print "$host -> $port is closed!\n";
		print "Please restart remote SMTP Daemon!\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
		goto LABEL2;
	}
}

#USERNAME Encoded Fuzzing
print "USERNAME Encoded Fuzzing.\n";
@all3=&restore_array();
undef($username_payload);
undef($username_payload_tmp);
foreach $username_payload (@all3){
	LABEL3: $sock3=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined($sock3)){
		$sock3->recv($content, 500, 0);                      #banner [220]
		$sock3->send("EHLO fuzzing_for_test\r\n", 0);
		$sock3->recv($content, 500, 0);                      #banner detail [250]
		sleep(2);
		$sock3->send("AUTH LOGIN\r\n", 0);
		sleep(2);
		$sock3->recv($content, 500, 0);                      #require username [334]
		sleep(2);
		$username_payload=MIME::Base64::encode($username_payload);
		chop($username_payload);
		$sock3->send("$username_payload"."\r\n", 0);
		sleep(2);
		$sock3->recv($content, 500, 0);                      #require password [334]
		sleep(5);
		$thread3=Thread->new(\&check);
		if($thread3->join()!=1){
			print "USERNAME Payload is $username_payload.\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
		}
		undef($thread3);
		$sock3->send("QUIT\r\n", 0);
		$sock3->close;
		$username_payload_tmp=$username_payload;
	}else{
		print "USERNAME Payload maybe $username_payload_tmp.\n";
		print "$host -> $port is closed!\n";
		print "Please restart remote SMTP Daemon!\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
		goto LABEL3;
	}
}

#PASSWORD Fuzzing
print "PASSWORD Fuzzing.\n";
print "Please enter a valid username: ";
$valid_username=<STDIN>;
chop($valid_username);
$valid_username=MIME::Base64::encode($valid_username);
chop($valid_username);
@all4=&restore_array();
foreach $password_payload (@all4){
	LABEL4: $sock4=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined($sock4)){
		$sock4->recv($content, 500, 0);                      #banner [220]
		$sock4->send("EHLO fuzzing_for_test\r\n", 0);
		$sock4->recv($content, 500, 0);                      #banner detail [250]
		sleep(2);
		$sock4->send("AUTH LOGIN\r\n", 0);
		sleep(2);
		$sock4->recv($content, 500, 0);                      #require username [334]
		sleep(2);
		$sock4->send("$valid_username"."\r\n", 0);
		sleep(2);
		$sock4->recv($content, 500, 0);                      #require password [334]
		sleep(2);
		$sock4->send("$password_payload"."\r\n", 0);
		sleep(2);
		$sock4->recv($content, 500, 0);
		sleep(5);
		$thread4=Thread->new(\&check);
		if($thread4->join()!=1){
			print "PASSWORD Payload is $password_payload.\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
		}
		undef($thread4);
		$sock4->send("QUIT\r\n", 0);
		$sock4->close;
		$password_payload_tmp=$password_payload;
	}else{
		print "PASSWORD Payload maybe $password_payload_tmp.\n";
		print "$host -> $port is closed!\n";
		print "Please restart remote SMTP Daemon!\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
		goto LABEL4;
	}
}

#PASSWORD Encoded Fuzzing
print "PASSWORD Encoded Fuzzing.\n";
undef($password_payload);
undef($password_payload_tmp);
@all5=&restore_array();
foreach $password_payload (@all5){
	LABEL5: $sock5=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined($sock5)){
		$sock5->recv($content, 500, 0);                      #banner [220]
		$sock5->send("EHLO fuzzing_for_test\r\n", 0);
		$sock5->recv($content, 500, 0);                      #banner detail [250]
		sleep(2);
		$sock5->send("AUTH LOGIN\r\n", 0);
		sleep(2);
		$sock5->recv($content, 500, 0);                      #require username [334]
		sleep(2);
		$sock5->send("$valid_username"."\r\n", 0);
		sleep(2);
		$sock5->recv($content, 500, 0);                      #require password [334]
		sleep(2);
		$password_payload=MIME::Base64::encode($password_payload);
		chop($password_payload);
		$sock5->send("$password_payload"."\r\n", 0);
		sleep(2);
		$sock5->recv($content, 500, 0);
		sleep(5);
		$thread5=Thread->new(\&check);
		if($thread5->join()!=1){
			print "PASSWORD Payload is $password_payload.\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
		}
		undef($thread5);
		$sock5->send("QUIT\r\n", 0);
		$sock5->close;
		$password_payload_tmp=$password_payload;
	}else{
		print "PASSWORD Payload maybe $password_payload_tmp.\n";
		print "$host -> $port is closed!\n";
		print "Please restart remote SMTP Daemon!\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
		goto LABEL5;
	}
}

#catch real username and password
print "Please enter the real username and password!\n";
print "Real Username: ";
$real_username=<STDIN>;
chop($real_username);
if($real_username=~m/(.*)\@(.*)/){
	$real_username_backup=$1;
}else{
	$real_username_backup=$real_username;
}
print "Real Password: ";
$real_password=<STDIN>;
chop($real_password);
$sock6=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
if(defined($sock6)){
	$sock6->recv($content, 500, 0);                      #banner [220]
	$sock6->send("EHLO fuzzing_for_test\r\n", 0);
	$sock6->recv($content, 500, 0);                      #banner detail [250]
	sleep(2);
	$sock6->send("AUTH LOGIN\r\n", 0);
	sleep(2);
	$sock6->recv($content, 500, 0);                      #require username [334]
	sleep(2);
	$real_username=MIME::Base64::encode($real_username);
	chop($real_username);
	$sock6->send("$real_username"."\r\n", 0);
	sleep(2);
	$sock6->recv($content, 500, 0);                      #require password [334]
	sleep(2);
	$real_password=MIME::Base64::encode($real_password);
	chop($real_password);
	$sock6->send("$real_password"."\r\n", 0);
	sleep(2);
	undef($content);
	$sock6->recv($content, 500, 0);
	sleep(2);
	if(!($content=~m/^235/)){
		print "Username or Password is wrong!\n";
		exit(0);
	}
	$sock6->close;
}else{
	print "$host -> $port is closed!\n";
	exit(0);
}

#'MAIL FROM' Fuzzing One
print "\'MAIL FROM\' Fuzzing, PART I.\n";
@all7=&restore_array();
foreach $mail_from_payload (@all7){
	LABEL7: $sock7=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined($sock7)){
		$sock7->recv($content, 500, 0);                      #banner [220]
		$sock7->send("EHLO fuzzing_for_test\r\n", 0);
		$sock7->recv($content, 500, 0);                      #banner detail [250]
		sleep(2);
		$sock7->send("AUTH LOGIN\r\n", 0);
		sleep(2);
		$sock7->recv($content, 500, 0);                      #require username [334]
		sleep(2);
		$sock7->send("$real_username"."\r\n", 0);
		sleep(2);
		$sock7->recv($content, 500, 0);                      #require password [334]
		sleep(2);
		$sock7->send("$real_password"."\r\n", 0);
		sleep(2);
		$sock7->recv($content, 500, 0);                      #auth successful [235]
		sleep(2);
		$sock7->send("MAIL FROM: <"."$mail_from_payload".">"."\r\n", 0);
		sleep(2);
		$sock7->recv($content, 500, 0);
		sleep(5);
		$thread7=Thread->new(\&check);
		if($thread7->join()!=1){
			print "\'MAIL FROM\' Payload is $mail_from_payload.\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
		}
		undef($thread7);
		$sock7->send("QUIT\r\n", 0);
		$sock7->close;
		$mail_from_payload_tmp=$mail_from_payload;
	}else{
		print "\'MAIL FROM\' Payload maybe $mail_from_payload_tmp.\n";
		print "$host -> $port is closed!\n";
		print "Please restart remote SMTP Daemon!\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
		goto LABEL7;
	}
}
		
#'MAIL FROM' Fuzzing Tow
print "\'MAIL FROM\' Fuzzing, PART II.\n";
undef($mail_from_payload);
undef($mail_from_payload_tmp);
print "Please enter the mail domain(sush as \'163.com\'): ";
$domain=<STDIN>;
chop($domain);
@all8=&restore_array();
foreach $mail_from_payload (@all8){
	LABEL8: $sock8=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined($sock8)){
		$sock8->recv($content, 500, 0);                      #banner [220]
		$sock8->send("EHLO fuzzing_for_test\r\n", 0);
		$sock8->recv($content, 500, 0);                      #banner detail [250]
		sleep(2);
		$sock8->send("AUTH LOGIN\r\n", 0);
		sleep(2);
		$sock8->recv($content, 500, 0);                      #require username [334]
		sleep(2);
		$sock8->send("$real_username"."\r\n", 0);
		sleep(2);
		$sock8->recv($content, 500, 0);                      #require password [334]
		sleep(2);
		$sock8->send("$real_password"."\r\n", 0);
		sleep(2);
		$sock8->recv($content, 500, 0);                      #auth successful [235]
		sleep(2);
		$sock8->send("MAIL FROM: <"."$mail_from_payload"."\@"."$domain".">"."\r\n", 0);
		sleep(2);
		$sock8->recv($content, 500, 0);
		sleep(5);
		$thread8=Thread->new(\&check);
		if($thread8->join()!=1){
			print "\'MAIL FROM\' Payload is ".$mail_from_payload.'@'.$domain.".\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
		}
		undef($thread8);
		$sock8->send("QUIT\r\n", 0);
		$sock8->close;
		$mail_from_payload_tmp=$mail_from_payload;
	}else{
		print "\'MAIL FROM\' Payload maybe ".$mail_from_payload_tmp.'@'.$domain.".\n";
		print "$host -> $port is closed!\n";
		print "Please restart remote SMTP Daemon!\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
		goto LABEL8;
	}
}

#'MAIL FROM' Fuzzing Three
print "\'MAIL FROM\' Fuzzing, PART III.\n";
undef($mail_from_payload);
undef($mail_from_payload_tmp);
@all9=&restore_array();
foreach $mail_from_payload (@all9){
	LABEL9: $sock9=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined($sock9)){
		$sock9->recv($content, 500, 0);                      #banner [220]
		$sock9->send("EHLO fuzzing_for_test\r\n", 0);
		$sock9->recv($content, 500, 0);                      #banner detail [250]
		sleep(2);
		$sock9->send("AUTH LOGIN\r\n", 0);
		sleep(2);
		$sock9->recv($content, 500, 0);                      #require username [334]
		sleep(2);
		$sock9->send("$real_username"."\r\n", 0);
		sleep(2);
		$sock9->recv($content, 500, 0);                      #require password [334]
		sleep(2);
		$sock9->send("$real_password"."\r\n", 0);
		sleep(2);
		$sock9->recv($content, 500, 0);                      #auth successful [235]
		sleep(2);
		$sock9->send("MAIL FROM: <"."$real_username_backup"."\@"."$mail_from_payload".">"."\r\n", 0);
		sleep(2);
		$sock9->recv($content, 500, 0);
		sleep(5);
		$thread9=Thread->new(\&check);
		if($thread9->join()!=1){
			print "\'MAIL FROM\' Payload is ".$real_username_backup.'@'.$mail_from_payload.".\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
		}
		undef($thread9);
		$sock9->send("QUIT\r\n", 0);
		$sock9->close;
		$mail_from_payload_tmp=$mail_from_payload;
	}else{
		print "\'MAIL FROM\' Payload maybe ".$real_username_backup.'@'.$mail_from_payload_tmp.".\n";
		print "$host -> $port is closed!\n";
		print "Please restart remote SMTP Daemon!\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
		goto LABEL9;
	}
}

#catch real mailbox of sender
print "Please enter the real mailbox of sender!\n";
print "Real MailBox of Sender(sush as \'demonalex\@163.com\'): ";
$real_sender=<STDIN>;
chop($real_sender);

#'RCPT TO' Fuzzing One
print "\'RCPT TO\' Fuzzing, PART I.\n";
@all10=&restore_array();
foreach $rcpt_to_payload (@all10){
	LABEL10: $sock10=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined($sock10)){
		$sock10->recv($content, 500, 0);                      #banner [220]
		$sock10->send("EHLO fuzzing_for_test\r\n", 0);
		$sock10->recv($content, 500, 0);                      #banner detail [250]
		sleep(2);
		$sock10->send("AUTH LOGIN\r\n", 0);
		sleep(2);
		$sock10->recv($content, 500, 0);                      #require username [334]
		sleep(2);
		$sock10->send("$real_username"."\r\n", 0);
		sleep(2);
		$sock10->recv($content, 500, 0);                      #require password [334]
		sleep(2);
		$sock10->send("$real_password"."\r\n", 0);
		sleep(2);
		$sock10->recv($content, 500, 0);                      #auth successful [235]
		sleep(2);
		$sock10->send("MAIL FROM: <"."$real_sender".">"."\r\n", 0);
		sleep(2);
		$sock10->recv($content, 500, 0);                      #Mail OK [250]
		sleep(2);
		$sock10->send("RCPT TO: <"."$rcpt_to_payload".">\r\n", 0);
		sleep(2);
		$sock10->recv($content, 500, 0);                      #Mail OK [250]
		sleep(5);
		$thread10=Thread->new(\&check);
		if($thread10->join()!=1){
			print "\'RCPT TO\' Payload is $rcpt_to_payload.\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
		}
		undef($thread10);
		$sock10->send("QUIT\r\n", 0);
		$sock10->close;
		$rcpt_to_payload_tmp=$rcpt_to_payload;
	}else{
		print "\'RCPT TO\' Payload maybe $rcpt_to_payload_tmp.\n";
		print "$host -> $port is closed!\n";
		print "Please restart remote SMTP Daemon!\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
		goto LABEL10;
	}
}

#'RCPT TO' Fuzzing Two
print "\'RCPT TO\' Fuzzing, PART II.\n";
@all11=&restore_array();
foreach $rcpt_to_payload (@all11){
	LABEL11: $sock11=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined($sock11)){
		$sock11->recv($content, 500, 0);                      #banner [220]
		$sock11->send("EHLO fuzzing_for_test\r\n", 0);
		$sock11->recv($content, 500, 0);                      #banner detail [250]
		sleep(2);
		$sock11->send("AUTH LOGIN\r\n", 0);
		sleep(2);
		$sock11->recv($content, 500, 0);                      #require username [334]
		sleep(2);
		$sock11->send("$real_username"."\r\n", 0);
		sleep(2);
		$sock11->recv($content, 500, 0);                      #require password [334]
		sleep(2);
		$sock11->send("$real_password"."\r\n", 0);
		sleep(2);
		$sock11->recv($content, 500, 0);                      #auth successful [235]
		sleep(2);
		$sock11->send("MAIL FROM: <"."$real_sender".">"."\r\n", 0);
		sleep(2);
		$sock11->recv($content, 500, 0);                      #Mail OK [250]
		sleep(2);
		$sock11->send("RCPT TO: <"."$rcpt_to_payload"."\@"."$domain".">\r\n", 0);
		sleep(2);
		$sock11->recv($content, 500, 0);                      #Mail OK [250]
		sleep(5);
		$thread11=Thread->new(\&check);
		if($thread11->join()!=1){
			print "\'RCPT TO\' Payload is $rcpt_to_payload"."\@"."$domain".".\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
		}
		undef($thread11);
		$sock11->send("QUIT\r\n", 0);
		$sock11->close;
		$rcpt_to_payload_tmp=$rcpt_to_payload;
	}else{
		print "\'RCPT TO\' Payload maybe $rcpt_to_payload_tmp"."\@"."$domain".".\n";
		print "$host -> $port is closed!\n";
		print "Please restart remote SMTP Daemon!\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
		goto LABEL11;
	}
}

#'RCPT TO' Fuzzing Three
print "\'RCPT TO\' Fuzzing, PART III.\n";
@all12=&restore_array();
foreach $rcpt_to_payload (@all12){
	LABEL12: $sock12=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined($sock12)){
		$sock12->recv($content, 500, 0);                      #banner [220]
		$sock12->send("EHLO fuzzing_for_test\r\n", 0);
		$sock12->recv($content, 500, 0);                      #banner detail [250]
		sleep(2);
		$sock12->send("AUTH LOGIN\r\n", 0);
		sleep(2);
		$sock12->recv($content, 500, 0);                      #require username [334]
		sleep(2);
		$sock12->send("$real_username"."\r\n", 0);
		sleep(2);
		$sock12->recv($content, 500, 0);                      #require password [334]
		sleep(2);
		$sock12->send("$real_password"."\r\n", 0);
		sleep(2);
		$sock12->recv($content, 500, 0);                      #auth successful [235]
		sleep(2);
		$sock12->send("MAIL FROM: <"."$real_sender".">"."\r\n", 0);
		sleep(2);
		$sock12->recv($content, 500, 0);                      #Mail OK [250]
		sleep(2);
		$sock12->send("RCPT TO: <"."aaa"."\@"."$rcpt_to_payload".">\r\n", 0);
		sleep(2);
		$sock12->recv($content, 500, 0);                      #Mail OK [250]
		sleep(5);
		$thread12=Thread->new(\&check);
		if($thread12->join()!=1){
			print "\'RCPT TO\' Payload is aaa"."\@"."$rcpt_to_payload".".\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
		}
		undef($thread12);
		$sock12->send("QUIT\r\n", 0);
		$sock12->close;
		$rcpt_to_payload_tmp=$rcpt_to_payload;
	}else{
		print "\'RCPT TO\' Payload maybe aaa"."\@"."$rcpt_to_payload".".\n";
		print "$host -> $port is closed!\n";
		print "Please restart remote SMTP Daemon!\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
		goto LABEL12;
	}
}

#MAIL CONTENT Fuzzing
print "MAIL CONTENT Fuzzing.\n";
@all13=&restore_array();
foreach $mail_content_payload (@all13){
	LABEL13: $sock13=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined($sock13)){
		$sock13->recv($content, 500, 0);                      #banner [220]
		$sock13->send("EHLO fuzzing_for_test\r\n", 0);
		$sock13->recv($content, 500, 0);                      #banner detail [250]
		sleep(2);
		$sock13->send("AUTH LOGIN\r\n", 0);
		sleep(2);
		$sock13->recv($content, 500, 0);                      #require username [334]
		sleep(2);
		$sock13->send("$real_username"."\r\n", 0);
		sleep(2);
		$sock13->recv($content, 500, 0);                      #require password [334]
		sleep(2);
		$sock13->send("$real_password"."\r\n", 0);
		sleep(2);
		$sock13->recv($content, 500, 0);                      #auth successful [235]
		sleep(2);
		$sock13->send("MAIL FROM: <"."$real_sender".">\r\n", 0);
		sleep(2);
		$sock13->recv($content, 500, 0);                      #Mail OK [250]
		sleep(2);
		$sock13->send("RCPT TO: <"."$real_sender".">\r\n", 0);
		sleep(2);
		$sock13->recv($content, 500, 0);                      #Mail OK [250]
		sleep(2);
		$sock13->send("Data\r\n", 0);
		sleep(2);
		$sock13->recv($content, 500, 0);                      #End data with <CR><LF>.<CR><LF> [354]
		sleep(2);
		$sock13->send("$mail_content_payload\r\n\r\n"."\x2e"."\r\n", 0);
		sleep(5);
		$thread13=Thread->new(\&check);
		if($thread13->join()!=1){
			print "MAIL CONTENT Payload is $mail_content_payload.\n";
			print "Press <ENTER> to continue.\n";
			<STDIN>;
		}
		undef($thread13);
		$sock13->send("QUIT\r\n", 0);
		$sock13->close;
		$mail_content_payload_tmp=$mail_content_payload;
	}else{
		print "MAIL CONTENT Payload maybe $mail_content_payload_tmp.\n";
		print "$host -> $port is closed!\n";
		print "Please restart remote SMTP Daemon!\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
		goto LABEL13;
	}
}

print "Finish!\n";
exit(0);