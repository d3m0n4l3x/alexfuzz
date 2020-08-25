#!/usr/bin/perl -w
use Socket;
use IO::Socket;
use Win32::Process::List;
$|=1;

#clear logfile log.txt
open(LOG, ">log.txt");
print LOG "\n";
close(LOG);

#obtain testing vector @all
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
@all=@bfo;
push(@all, @fse);
push(@all, @int);

#check function
sub check($$){
	$target_ip=shift;
	$target_port=shift;
	#print "check";
	$sock=IO::Socket::INET->new(PeerAddr=>$target_ip,PeerPort=>$target_port,Timeout=>30);
	if(defined $sock){
		$sock->close;
		return 1;                                           #alive
	}else{
		return 0;                                           #down
	}
}

#test function
sub test($$$){
	$test_ip=shift;
	$test_port=shift;
	$test_payload=shift;
	$test_target=inet_aton($test_ip);
	$test_target=sockaddr_in($test_port, $test_target);
	socket(SOCK, AF_INET, SOCK_STREAM, 6) || return 2;    #2 is fail to create socket!
	connect(SOCK, $test_target) || return 3;              #3 is fail to connect!
	send(SOCK, $test_payload, 0) || return 4;             #4 is fail to send!
	recv(SOCK, $test_payload, 100, 0) || return 5;        #5 is fail to recv!
	close(SOCK) || return 6;                              #6 is fail to close!
	return 1;                                             #1 is success!
}

#get process status function
sub get_process_status($){
	$pn=shift;
	$P = Win32::Process::List->new();
	%list = $P->GetProcesses();
	foreach $key ( keys %list ) {
		# $list{$key} is now the process name and $key is the PID
		#print sprintf("%30s has PID %15s", $list{$key}, $key) . "\n";
		#print "$list{$key}\n";
		if($pn eq $list{$key}){
			return 1;
		}
	}
	return 0;
}

#log function
sub log($){
	$log_content=shift;
	open(LOG, ">>log.txt");
	print LOG "$log_content\n";
	close(LOG);
	return;
}

#obtain $ip and $port of target
print "Target IP : ";
$ip=<STDIN>;
chop($ip);
print "Service Port : ";
$port=<STDIN>;
chop($port);
print "Host : ";
$hostname=<STDIN>;
chop($hostname);
print "DEBUG Mode (y/n) : ";
$debug_mode=<STDIN>;
chop($debug_mode);
if(lc($debug_mode) eq 'y'){
	$debug_mode=1;
}else{
	if(lc($debug_mode) eq 'n'){
		$debug_mode=0;
	}else{
		die "Answer is wrong!\n";
	}
}
print "LOCALHOST Mode (y/n) : ";
$localhost_mode=<STDIN>;
chop($localhost_mode);
if(lc($localhost_mode) eq 'y'){
	$localhost_mode=1;
}else{
	if(lc($localhost_mode) eq 'n'){
		$localhost_mode=0;
	}else{
		die "Answer is wrong!\n";
	}
}
if($localhost_mode==1){
	print "Process Name : ";
	$process_name=<STDIN>;
	chop($process_name);
}
	
#define normal HTTP head $http_head
$http_head=
"GET / HTTP/1.0\r\n".
"Accept: */*\r\n".
"Accept-Language: zh-cn\r\n".
"UA-CPU: x86\r\n".
"Accept-Encoding: gzip, deflate\r\n".
"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; 360SE)\r\n".
"Host: ".$hostname."\r\n".
"Connection: Keep-Alive"."\r\n\r\n";

#main menu
MENU0:
print "-------------------------------\n";
print "Main Menu:\n".
	"0)ALL\n".
	"1)fuzzing of GET\n".
	"2)fuzzing of If-Modified-Since\n".
	"3)fuzzing of If-None-Match\n".
	"4)fuzzing of If-Unmodified-Since\n".
	"5)fuzzing of Last-Modified\n".
	"6)fuzzing of Accept\n".
	"7)fuzzing of Accept-Charset\n".
	"8)fuzzing of Accept-Encoding\n".
	"9)fuzzing of Accept-Language\n".
	"10)fuzzing of Accept-Ranges\n".
	"11)fuzzing of Allow\n".
	"12)fuzzing of Connection\n".
	"13)fuzzing of Content-Encoding\n".
	"14)fuzzing of Content-Language\n".
	"15)fuzzing of Content-Length\n".
	"16)fuzzing of Content-Location\n".
	"17)fuzzing of Content-MD5\n".
	"18)fuzzing of Content-Range\n".
	"19)fuzzing of Content-Type\n".
	"20)fuzzing of Date\n".
	"21)fuzzing of Expires\n".
	"22)fuzzing of From\n".
	"23)fuzzing of Host\n";
print "Answer : ";
$answer=<STDIN>;
chop($answer);
$switch=0;
if($answer==0){
	$switch=1;
}else{
	if($answer==1){
		goto MENU1;
	}else{
		if($answer==2){
			goto MENU2;
		}else{
			if($answer==3){
				goto MENU3;
			}else{
				if($answer==4){
					goto MENU4;
				}else{
					if($answer==5){
						goto MENU5;
					}else{
						if($answer==6){
							goto MENU6;
						}else{
							if($answer==7){
								goto MENU7;
							}else{
								if($answer==8){
									goto MENU8;
								}else{
									if($answer==9){
										goto MENU9;
									}else{
										if($answer==10){
											goto MENU10;
										}else{
											if($answer==11){
												goto MENU11;
											}else{
												if($answer==12){
													goto MENU12;
												}else{
													if($answer==13){
														goto MENU13;
													}else{
														if($answer==14){
															goto MENU14;
														}else{
															if($answer==15){
																goto MENU15;
															}else{
																if($answer==16){
																	goto MENU16;
																}else{
																	if($answer==17){
																		goto MENU17;
																	}else{
																		if($answer==18){
																			goto MENU18;
																		}else{
																			if($answer==19){
																				goto MENU19;
																			}else{
																				if($answer==20){
																					goto MENU20;
																				}else{
																					if($answer==21){
																						goto MENU21;
																					}else{
																						if($answer==22){
																							goto MENU22;
																						}else{
																							if($answer==23){
																								goto MENU23;
																							}else{
																								goto MENU0;
																							}
																						}
																					}
																				}
																			}
																		}
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
print "-------------------------------\n";

MENU1:
#fuzzing of GET
$plan="GET";
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/GET (.*) HTTP\/1.0\r\n/GET \/$v HTTP\/1.0\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU2:
#fuzzing of If-Modified-Since
$plan="If-Modified-Since";
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/UA-CPU: x86\r\n/UA-CPU: x86\r\nIf-Modified-Since: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/UA-CPU: x86\r\n/UA-CPU: x86\r\nIf-Modified-Since: $v, 22 Jun 2011 09:50:36 GMT\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/UA-CPU: x86\r\n/UA-CPU: x86\r\nIf-Modified-Since: Wed, $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU3:
#fuzzing of If-None-Match
$plan="If-None-Match";
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/UA-CPU: x86\r\n/UA-CPU: x86\r\nIf-None-Match: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/UA-CPU: x86\r\n/UA-CPU: x86\r\nIf-None-Match: $v\/\"639-1308736236000\"\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/UA-CPU: x86\r\n/UA-CPU: x86\r\nIf-None-Match: W\/\"$v\"\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU4:
#fuzzing of If-Unmodified-Since
$plan="If-Unmodified-Since";
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/UA-CPU: x86\r\n/UA-CPU: x86\r\nIf-Unmodified-Since: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/UA-CPU: x86\r\n/UA-CPU: x86\r\nIf-Unmodified-Since: $v, 22 Jun 2011 09:50:36 GMT\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/UA-CPU: x86\r\n/UA-CPU: x86\r\nIf-Unmodified-Since: Wed, $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU5:
#fuzzing of Last-Modified
$plan="Last-Modified";
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/UA-CPU: x86\r\n/UA-CPU: x86\r\nLast-Modified: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/UA-CPU: x86\r\n/UA-CPU: x86\r\nLast-Modified: $v, 22 Jun 2011 09:50:36 GMT\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/UA-CPU: x86\r\n/UA-CPU: x86\r\nLast-Modified: Wed, $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU6:
#fuzzing of Accept
$plan="Accept";                                 #"Accept: */*\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept: (.*)\r\n/Accept: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept: (.*)\/\*\r\n/Accept: $v\/\*\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept: (.*)\r\n/Accept: audio\/$v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept: (.*)\r\n/Accept: audio\/\*\; $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept: (.*)\r\n/Accept: audio\/\*\; q=0.2, $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU7:
#fuzzing of Accept-Charset
$plan="Accept-Charset";                                 #"Accept: */*\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept: \*\/\*\r\n/Accept: \*\/\*\r\nAccept-Charset: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept: \*\/\*\r\n/Accept: \*\/\*\r\nAccept-Charset: iso-8859-5, $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept: \*\/\*\r\n/Accept: \*\/\*\r\nAccept-Charset: iso-8859-5, unicode-1-1;$v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU8:
#fuzzing of Accept-Encoding
$plan="Accept-Encoding";                                 #"Accept-Encoding: gzip, deflate\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: compress, $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: compress;$v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: compress;q=$v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU9:
#fuzzing of Accept-Language
$plan="Accept-Language";                                 #"Accept: */*\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept: \*\/\*\r\n/Accept: \*\/\*\r\nAccept-Language: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept: \*\/\*\r\n/Accept: \*\/\*\r\nAccept-Language: da, $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept: \*\/\*\r\n/Accept: \*\/\*\r\nAccept-Language: da, en-gb;$v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept: \*\/\*\r\n/Accept: \*\/\*\r\nAccept-Language: da, en-gb;q=$v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU10:
#fuzzing of Accept-Ranges
$plan="Accept-Ranges";                                 #"Accept: */*\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept: \*\/\*\r\n/Accept: \*\/\*\r\nAccept-Ranges: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU11:
#fuzzing of Allow
$plan="Allow";                                 #"UA-CPU: x86\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/UA-CPU: x86\r\n/UA-CPU: x86\r\nAllow: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/UA-CPU: x86\r\n/UA-CPU: x86\r\nAllow: GET, $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU12:
#fuzzing of Connection
$plan="Connection";                                 #"Connection: Keep-Alive"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Connection: Keep-Alive/Connection: $v/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU13:
#fuzzing of Content-Encoding
$plan="Content-Encoding";                                 #"Accept-Encoding: gzip, deflate\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nContent-Encoding: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU14:
#fuzzing of Content-Language
$plan="Content-Language";                                 #"Accept-Encoding: gzip, deflate\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nContent-Language: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nContent-Language: en, $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU15:
#fuzzing of Content-Length
$plan="Content-Length";                                 #"Accept-Encoding: gzip, deflate\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nContent-Length: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU16:
#fuzzing of Content-Location
$plan="Content-Location";                                 #"Accept-Encoding: gzip, deflate\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nContent-Location: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nContent-Location: http:\/\/$v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU17:
#fuzzing of Content-MD5
$plan="Content-MD5";                                 #"Accept-Encoding: gzip, deflate\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nContent-MD5: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU18:
#fuzzing of Content-Range
$plan="Content-Range";                                 #"Accept-Encoding: gzip, deflate\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nContent-Range: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nContent-Range: bytes $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU19:
#fuzzing of Content-Type
$plan="Content-Type";                                 #"Accept-Encoding: gzip, deflate\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nContent-Type: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nContent-Type: text\/html; $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nContent-Type: text\/html; charset=$v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU20:
#fuzzing of Date
$plan="Date";                                 #"Accept-Encoding: gzip, deflate\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nDate: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nDate: Tue, $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU21:
#fuzzing of Expires
$plan="Expires";                                 #"Accept-Encoding: gzip, deflate\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nExpires: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nExpires: Tue, $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU22:
#fuzzing of From
$plan="From";                                 #"Accept-Encoding: gzip, deflate\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nFrom: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nFrom: $v\@163.com\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Accept-Encoding: gzip, deflate\r\n/Accept-Encoding: gzip, deflate\r\nFrom: sales\@$v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

MENU23:
#fuzzing of Host
$plan="Host";                                                 #"Host: ".$hostname."\r\n"
print "Testing \"$plan\" ...\n";
foreach $v (@all){
	$payload=$http_head;
	$payload=~s/Host: (.*)\r\n/Host: $v\r\n/;
	print "PAYLOAD:\n$payload\n" if $debug_mode==1;
	$result=&test($ip, $port, $payload);
	$process_result=&get_process_status($process_name) if $localhost_mode==1;
	print "Return code : $result.\n" if $debug_mode==1;
	print "Process return code : $process_result.\n" if (($debug_mode==1) && ($localhost_mode==1));
	print "\n" if $debug_mode==1;
	die "Cannot create socket!\n" if($result==2);
	if(($result==3) || ($result==4) || ($result==5) || ($result==6) || (&check($ip, $port)==0) || (($localhost_mode==1) && ($process_result==0))){
		$log_payload="Payload[$plan] :\n$payload\n\n";
		print "$log_payload";
		&log($log_payload);
		print "Details was into log.txt, Press [ENTER] to continue ...";
		<STDIN>;
	}
}
print "Testing \"$plan\" ... Finish!\n";
if($switch==1){
	;
}else{
	goto MENU0;
}

goto MENU0;