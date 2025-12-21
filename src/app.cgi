#!/usr/bin/perl -w
#@HDR@	$Id$
#@HDR@		Copyright 2024 by
#@HDR@		Christopher Caldwell/Brightsands
#@HDR@		P.O. Box 401, Bailey Island, ME 04003
#@HDR@		All Rights Reserved
#@HDR@
#@HDR@	This software comprises unpublished confidential information
#@HDR@	of Brightsands and may not be used, copied or made available
#@HDR@	to anyone, except in accordance with the license under which
#@HDR@	it is furnished.

use strict;

#$| = 1;
#print "Content-type:  text/plain\n\n";
#close( STDERR );
use MIME::Lite;
use lib "/usr/local/lib/perl";
use cpi_cgi qw(show_vars);
use cpi_inlist qw( inlist );
use cpi_file qw(cleanup fatal read_file write_file files_in read_lines
 write_lines );
use cpi_translate qw(breakup_and_translate_strings xprint);
use cpi_compress_integer qw( compress_integer );
use cpi_db qw(db_readable dbget dbpop dbput dbread dbwrite dbadd dbarr);
use cpi_user qw(logout_select can_cgroup can_cuser can_suser all_users
 group_to_name groups write_sid );
use cpi_setup qw(setup);

$cpi_vars::TABLE_TAGS	= "bgcolor=\"#c0c0d0\"";

my $FORMNAME = "form";

&setup(
	stderr=>"User",
	preset_language=>"en",
	Qrequire_captcha=>1
	);

my $form_top;

1;
#########################################################################
#	Remove a session's credentials.					#
#########################################################################
sub logout
    {
    unlink( "$cpi_vars::SIDDIR/$cpi_vars::SID" );
    &log("$cpi_vars::REALUSER logs out from SID $cpi_vars::SID.");
    }

#########################################################################
#	Handle invitations						#
#########################################################################
sub handle_invitations
    {
    my( @msgs ) = ();
    my $written = 0;
    if( $cpi_vars::FORM{activation_code} )
	{
	foreach my $activation_code ( split(/,/,$cpi_vars::FORM{activation_code}) )
	    {
	    my $found_activation_code = 0;
	    foreach my $fld ( @cpi_vars::CONFIRM_FIELDS )
		{
		my $ccode = &dbget($cpi_vars::ACCOUNTDB,
		    "users",$cpi_vars::REALUSER,"confirm$fld");
		if( $ccode eq $activation_code )
		    {
		    my $val = &dbget($cpi_vars::ACCOUNTDB,"users",$cpi_vars::REALUSER,$fld);
		    &dbwrite( $cpi_vars::ACCOUNTDB ) if( $written++ == 0 );
		    &dbput($cpi_vars::ACCOUNTDB,"users",$cpi_vars::REALUSER,
		        "last".$fld,$val);
		    $found_activation_code = 1;
		    push( @msgs, "XL($fld confirmed as) $val." );
		    last;
		    }
		}
	    next if( $found_activation_code );
	    my $action_string =
		&dbget($cpi_vars::ACCOUNTDB,
		    "invitations",$activation_code);
	    if( !defined($action_string) || $action_string eq "" )
		{
		push( @msgs,  "XL(No such invitation as [[$activation_code]])." );
		}
	    elsif( $action_string eq "used" )
		{
		push( @msgs, "XL(Invitation [[$activation_code]] already accepted.)" );
		}
	    else
		{
		&dbwrite( $cpi_vars::ACCOUNTDB ) if( $written++ == 0 );
		&dbput($cpi_vars::ACCOUNTDB,
		    "invitations",$activation_code,"used");
		&invitation_handler( split($cpi_vars::DBSEP,$action_string) );
		}
	    }
	}
    &dbpop( $cpi_vars::ACCOUNTDB ) if( $written );
    if( @msgs )
	{
	&xprint( join("<br>",@msgs) );
	&cleanup(0);
	}
    }

#########################################################################
#	Return an HTML table of who's used the system recently.		#
#########################################################################
sub who
    {
    my @dirs = grep(/^[^\.]/,&files_in( $cpi_vars::SIDDIR ) );
    my %results = ();
    foreach my $sidfile ( @dirs )
        {
	my $fname = "$cpi_vars::SIDDIR/$sidfile";
	my( $st_ino, $st_dev, $st_mode, $st_nlink,
	    $st_uid, $st_gid, $st_rdev, $st_size, $st_atime, $st_mtime,
	    $st_ctime, $st_blksize, $st_blocks) = lstat( $fname );
	my $inactivity = time - $st_mtime;
	if( $inactivity <= $cpi_vars::LOGIN_TIMEOUT )
	    {
	    my( $realuser, $user, $lang ) = &read_lines($fname);
	    my $disuser = ( $realuser eq $user ? $user : "$user/$realuser" );
	    $results{$sidfile} =
		sprintf(
		    "<tr><td>%s</td><td>%2s</td><td>%02d:%02d:%02d</td></tr>\n",
		    $disuser, $lang,
		    $inactivity/3600, ($inactivity/60)%60, $inactivity % 60 );
	    }
	}
    my @toprint = ( <<EOF );
<table><tr><th>XL(User)</th><th>XL(Language)</th><th>XL(Inactive)</th></tr>
EOF
    foreach my $sidfile ( sort {$results{$a} cmp $results{$b}} keys %results )
        { push( @toprint, $results{$sidfile} ); }
    push( @toprint, "</table>" );
    return join("",@toprint);
    }

#########################################################################
#	Invite a user to join a group.					#
#########################################################################
sub invite
    {
    my ( $means, $address, $msg, @parts ) = @_;
    my $new_code = "i" . &compress_integer( rand() );
    &dbwrite( $cpi_vars::ACCOUNTDB );
    &dbput( $cpi_vars::ACCOUNTDB, "invitations",
	$new_code, &dbarr(@parts) );
    &dbpop( $cpi_vars::ACCOUNTDB );
    &send_via( $means, $cpi_vars::DAEMON_EMAIL, $address,
        &xlate("XL(Invitation)"),
	"$msg\n$cpi_vars::URL?func=admin&activation_code=$new_code"
	);
    }

#########################################################################
#	Check to see if field from form is different than user's	#
#	field.  If so, send out missive and update database.		#
#	Returns listof progress messages (or errors).			#
#########################################################################
sub check_com_field
    {
    my( $user, $fld ) = @_;
    my ( @changed_list ) = ();
    my $lastval=&dbget($cpi_vars::ACCOUNTDB,"users",$user,$fld)||"";
    if( $lastval ne ($cpi_vars::FORM{$fld}||"") )
	{
	&dbput($cpi_vars::ACCOUNTDB,
	    "users",$user,$fld,$cpi_vars::FORM{$fld});
	my $new_code = "c" . &compress_integer( rand() );
	&dbput($cpi_vars::ACCOUNTDB,
	    "users",$user,"confirm$fld",$new_code);
	my $conmsg = &xlate(<<EOF);
XL(This message was sent to you by the $cpi_vars::PROG server to verify that
the $fld information you gave it was correct.)

XL(To confirm that it is, login to the $cpi_vars::PROG server as
[[$user]], enter the "Administration" mode and enter the value
'[[$new_code]]' where it asks for an activition code.)
EOF
	if( $fld eq "email" )
	    {
	    $conmsg .= &xlate(<<EOF);

XL(If your e-mail reader supports it, you can click here:

[[$cpi_vars::URL?user=$user&activation_code=$new_code]]
)
EOF
	    }
	print STDERR $conmsg;
	if( $cpi_vars::FORM{$fld} )
	    {
	    &send_via( $fld,
		$cpi_vars::DAEMON_EMAIL, $cpi_vars::FORM{$fld},
		&xlate("XL(Action required)"), $conmsg );
	    push( @changed_list,
		"XL(Confirmation sent to [[$fld $cpi_vars::FORM{$fld}]].)");
	    }
	}
    return @changed_list;
    }

#########################################################################
#	Allow user to change settings about his account.  Normal users	#
#	can only change their password.					#
#########################################################################
sub admin_page
    {
    my( $form_admin ) = @_;
    $form_admin ||= $cpi_vars::DEFAULT_FORM;
    my $msg = "";
    my %mygroups = ();
    my ( $u, $g );
    my ( @problems ) = ();
    my @toprint;

    &write_sid();

    my( @startlist ) =
	( &can_cgroup
	? &dbget($cpi_vars::ACCOUNTDB,"groups")
	: &dbget($cpi_vars::ACCOUNTDB,"users",$cpi_vars::REALUSER,"groups")
	);
    foreach $g ( @startlist )
        {
	&dbget($cpi_vars::ACCOUNTDB,"groups",$g,"inuse")
	    && $mygroups{$g}++;
	}

    $cpi_vars::FORM{modrequest} ||= "";
    $cpi_vars::FORM{switchuser} ||= "";

    if( $cpi_vars::FORM{modrequest} eq "delete_user" )
	{
	&dbwrite( $cpi_vars::ACCOUNTDB );
	&dbdel( $cpi_vars::ACCOUNTDB, "users", $cpi_vars::USER );
	&dbput( $cpi_vars::ACCOUNTDB, "users", $cpi_vars::USER, "inuse",0);
	&dbpop( $cpi_vars::ACCOUNTDB );
	}
    elsif( $cpi_vars::FORM{modrequest} eq "modify_user" )
	{
	my @changed_list = ();
	my $usertobe = $cpi_vars::USER;
	if( &can_cuser() && $cpi_vars::FORM{newuser} )
	    {
	    $usertobe = lc( $cpi_vars::FORM{newuser} );
	    if( $usertobe !~ /^[a-z0-9\.\@_]+$/ )
		{ push( @changed_list, "Bad characters in new user name." ); }
	    }
	if( $cpi_vars::FORM{newuser} ne "" && $cpi_vars::FORM{password0} eq "" )
	    { push( @changed_list, "No password specified." ); }
	elsif( ($cpi_vars::FORM{password0}||"")
	    ne ($cpi_vars::FORM{password1}||"") )
	    { push( @changed_list, "XL(Password mismatch.)" ); }

	my @glist = split(',',$cpi_vars::FORM{groups});

	if( &can_cuser() )
	    {
	    if( ! @glist )
		{ push( @changed_list, "No groups specified." ); }
	    elsif( grep( $mygroups{$_} eq "", @glist ) )
		{ push( @changed_list, "Bad group specified." ); }
	    }

	if( ! @changed_list )
	    {
	    $cpi_vars::USER = $usertobe;
	    &dbwrite($cpi_vars::ACCOUNTDB);
	    if( ! &can_cuser() )
		{
		if( $cpi_vars::FORM{fullname} ne
		    &dbget($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,"fullname") )
		    {
		    &dbput($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,
			"fullname",$cpi_vars::FORM{fullname});
		    push( @changed_list, "Full name updated." );
		    }
		if( $cpi_vars::FORM{password0} ne "" )
		    {
		    &dbput( $cpi_vars::ACCOUNTDB, "users", $cpi_vars::USER,
			"password", &salted_password( $cpi_vars::FORM{password0} ) );
		    push( @changed_list, "Password updated." );
		    }
		}
	    else
		{
		&dbadd($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER);
		&dbput($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,
		    "inuse",1);
		&dbput($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,
		    "password",$cpi_vars::FORM{password0})
		    if( $cpi_vars::FORM{password0} ne "" );
		&dbput($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,
		    "groups",&dbarr(@glist));
		&dbput($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,
		    "fullname",$cpi_vars::FORM{fullname});
		push( @changed_list, "XL(User [[$cpi_vars::USER]] updated)" );
		}

	    foreach my $fld ( @cpi_vars::CONFIRM_FIELDS )
		{
		push( @changed_list,
		    &check_com_field( $cpi_vars::USER, $fld ) );
		}
	    &dbpop( $cpi_vars::ACCOUNTDB );
	    }
	$msg = join("<br>",@changed_list);
	}
    elsif( $cpi_vars::FORM{modrequest} eq "add_group" )
	{
	if( ($cpi_vars::FORM{groupname} ne "") && &can_cgroup )
	    {
	    my $g = &name_to_group( $cpi_vars::FORM{groupname} );
	    if( &dbget($cpi_vars::ACCOUNTDB,"groups",$g,"inuse") )
		{ $msg = "Group $g already in use.  Try another."; }
	    else
		{
		&dbwrite($cpi_vars::ACCOUNTDB);
		&dbadd($cpi_vars::ACCOUNTDB,"groups",$g);
		&dbput($cpi_vars::ACCOUNTDB,"groups",$g,"inuse",1);
		&dbput($cpi_vars::ACCOUNTDB,"groups",$g,"fullname",
		    $cpi_vars::FORM{groupname});
		&dbpop( $cpi_vars::ACCOUNTDB );
		}
	    }
	}
    elsif( $cpi_vars::FORM{modrequest} eq "change_group" )
	{
	if( ($cpi_vars::FORM{group} ne "") && &can_cgroup )
	    {
	    my $g = $cpi_vars::FORM{group};
	    if( ! &dbget($cpi_vars::ACCOUNTDB,"groups",$g,"inuse") )
		{ $msg = "Group $g not in use.  Try another."; }
	    else
		{
		&dbwrite($cpi_vars::ACCOUNTDB);
		&dbadd($cpi_vars::ACCOUNTDB,"groups",$g);
		&dbput($cpi_vars::ACCOUNTDB,"groups",$g,"inuse",1);
		&dbput($cpi_vars::ACCOUNTDB,"groups",$g,"fullname",
		    $cpi_vars::FORM{groupname});
		&dbpop( $cpi_vars::ACCOUNTDB );
		}
	    }
	}
    elsif( $cpi_vars::FORM{modrequest} eq "delete_group" )
	{
	if( ($cpi_vars::FORM{group} ne "") && &can_cgroup )
	    {
	    my $g = $cpi_vars::FORM{group};
	    if( ! &dbget($cpi_vars::ACCOUNTDB,"groups",$g,"inuse") )
		{ $msg = "No group called '$g'.  Try another."; }
	    else
		{
		&dbwrite($cpi_vars::ACCOUNTDB);
		&dbdel($cpi_vars::ACCOUNTDB,"groups",$g);
		&dbput($cpi_vars::ACCOUNTDB,"groups",$g,"inuse","");
		&dbpop( $cpi_vars::ACCOUNTDB );
		}
	    }
	}
    elsif( $cpi_vars::FORM{modrequest} eq "payment"
	    && $cpi_vars::FORM{topay} ne "" )
	{
	my $note;
	push( @problems, "XL(Illegal payment amount specified.)" )
	    if( $cpi_vars::FORM{topay} !~ /^[ \$]*(\d+\.\d\d)$/ );
	my $paid = $1;
	$paid =~ s/^[ \$]*//g;
	if( $cpi_vars::FORM{cardname} )
	    {
	    $_ = $cpi_vars::FORM{cardnum};
	    if( /\*/ )
		{
		$cpi_vars::FORM{cardnum} =
		    &dbget($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,
		    "cardnum");
		$cpi_vars::FORM{cardname} =
		    &dbget($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,
		    "cardname");
		$cpi_vars::FORM{cardexp} =
		    &dbget($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,
		    "cardexp");
		$_ = $cpi_vars::FORM{cardnum};
		}
	    s/[ \-]*//g;
	    if( /^\d\d\d\d\d\d\d\d\d\d\d\d(\d\d\d\d)$/ )
		{ $note="CC$1"; }
	    elsif( /^\d\d\d\d\d\d\d\d\d\d\d\d\d(\d\d\d\d)$/ )
		{ $note="CC$1"; }
	    else
		{
		push( @problems, "XL(Illegal card of credit number: [[$_]]" );
		}
	    $_ = $cpi_vars::FORM{cardexp};
	    push( @problems,
		"XL(Illegal expiration date: [[$_]] [[1=$1, 2=$2]])." )
		if( ! /^(\d\d)\/(\d\d\d\d)$/			||
		    $1<1 || $1>12 || $2<2000 || $2>2100		);
	    push( @problems, "XL(Multiple methods of payment specified.)" )
		if( $cpi_vars::FORM{checknum}
		    || $cpi_vars::FORM{certnum}
		    || $cpi_vars::FORM{usecash} );
	    }
	elsif( $cpi_vars::FORM{checknum} )
	    {
	    push( @problems, "XL(Illegal check number.)" )
		if( $cpi_vars::FORM{checknum} !~ /^\d[\d\-]*$/ );
	    push( @problems, "XL(Multiple methods of payment specified.)" )
		if( $cpi_vars::FORM{certnum} || $cpi_vars::FORM{usecash} );
	    $note = "CK$cpi_vars::FORM{checknum}";
	    }
	elsif( $cpi_vars::FORM{certnum} )
	    {
	    push( @problems, "XL(Illegal certificate number.)" )
		if( $cpi_vars::FORM{certnum} !~ /^\d[\d\-]*$/ );
	    push( @problems, "XL(Multiple methods of payment specified.)" )
		if( $cpi_vars::FORM{usecash} );
	    $note = "CN$cpi_vars::FORM{certnum}";
	    }
	elsif( $cpi_vars::FORM{usecash} )
	    { $note = "Cash"; }
	else
	    { push( @problems, "XL(No payment method specified.)" ); }
	if( @problems )
	    {
	    push( @toprint, "<h1>XL(Problems with your form:)</h1>\n" );
	    foreach $_ ( @problems )
		{ push(@toprint, "<dd><font color=red>$_</font>\n" ); }
	    push( @toprint, "<p>XL(Go back and correct these problems.)\n" );
	    &xprint( @toprint );
	    exit(0);
	    }
	my( $ind ) = $cpi_vars::TODAY;
	&dbwrite($cpi_vars::DB);
	&dbadd($cpi_vars::DB,"users",$cpi_vars::USER,"days",
	    $cpi_vars::TODAY,"payments",$ind);
	&dbput($cpi_vars::DB,"users",$cpi_vars::USER,"days",
	    $cpi_vars::TODAY,"payments",$ind,"note",$note);
	&dbput($cpi_vars::DB,"users",$cpi_vars::USER,"days",
	    $cpi_vars::TODAY,"payments",$ind,"paid",$paid);
	&dbpop($cpi_vars::DB);
	if( $cpi_vars::FORM{cardonfile} )
	    {
	    &dbwrite($cpi_vars::ACCOUNTDB);
	    &dbput($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,
	        "cardnum",$cpi_vars::FORM{cardnum});
	    &dbput($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,
	        "cardexp",$cpi_vars::FORM{cardexp});
	    &dbput($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,
	        "cardname",$cpi_vars::FORM{cardname});
	    &dbpop($cpi_vars::ACCOUNTDB);
	    }
	}

    @startlist =
	( &can_cgroup
	? &dbget($cpi_vars::ACCOUNTDB,"groups")
	: &dbget($cpi_vars::ACCOUNTDB,"users",$cpi_vars::REALUSER,"groups")
	);
    %mygroups = ();
    foreach $g ( @startlist )
        {
	&dbget($cpi_vars::ACCOUNTDB,"groups",$g,"inuse")
	    && $mygroups{$g}++;
	}
    my $pname = $cpi_vars::FULLNAME || $cpi_vars::USER;

    my %thisusergroup = ();
    grep( $thisusergroup{$_}="selected",
	&dbget($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,"groups") );

    push( @toprint, <<EOF );
<script>
function switchuserfnc()
    {
    with ( window.document.$form_admin )
        {
	if( switchuser.options[ switchuser.selectedIndex ].value != "*" )
	    {
	    USER.value = switchuser.options[ switchuser.selectedIndex ].value;
	    }
	modrequest.value = "";
	submit();
	}
    }
</script>
<title>${pname}'s $cpi_vars::PROG XL(Administration Page)</title>
<body $cpi_vars::BODY_TAGS>
$cpi_vars::HELP_IFRAME
<center><form name=$form_admin method=post>
<h1>$msg</h1>
<input type=hidden name=SID value=$cpi_vars::SID>
<input type=hidden name=USER value=$cpi_vars::FORM{USER}>
<input type=hidden name=func value=$cpi_vars::FORM{func}>
<input type=hidden name=modrequest value="">
<input type=hidden name=group value="">
<input type=hidden name=groupname value="">
<table border=1 $cpi_vars::TABLE_TAGS><tr>
<th valign=top><table border=0>
EOF
    my $fullname =
	&dbget($cpi_vars::ACCOUNTDB,"users",
	    $cpi_vars::USER,"fullname");
    if( $cpi_vars::FORM{switchuser} eq "*" )
        {
	push( @toprint, <<EOF );
<tr><th align=left>XL(New user ID:)</th>
    <td><input type=text autocapitalize=none name=newuser size=10></td></tr>
<tr><th align=left>XL(Entire name:)</th>
    <td><input type=text autocapitalize=words name=fullname size=30></td></tr>
EOF
	}
    elsif( &can_suser() )
	{
	push( @toprint, <<EOF );
<tr><th align=left>XL(User ID:)</th>
    <td><select name=switchuser onChange='switchuserfnc();'>
EOF
	push( @toprint, "<option value=*>XL(Create new user)\n" )
	    if( &can_cuser() );
	my %selflag = ( $cpi_vars::USER, " selected" );
	my $cgprivs = &can_cgroup();
	foreach $u ( &all_users() )
	    {
	    next if( ! &dbget($cpi_vars::ACCOUNTDB,"users",$u,"inuse") );
	    my $found_group = $cgprivs;
	    if( ! $found_group )
		{
		$found_group++
		    if( grep($mygroups{$_},
		        &dbget($cpi_vars::ACCOUNTDB,
			    "users",$u,"groups")) );
		}
	    if( $found_group )
		{
		$_ = &dbget($cpi_vars::ACCOUNTDB,"users",$u,"fullname");
		push( @toprint,
		    "<option",
		        ($selflag{$u}||""),
			" value=\"$u\">$u - $_</option>\n" );
		}
	    }
    	push( @toprint, <<EOF );
    </select></td></tr>
<tr><th align=left>XL(Entire name:)</th>
    <td><input type=text autocapitalize=words name=fullname value="$fullname" size=30></td></tr>
EOF
	}
    else
        {
    	push( @toprint, <<EOF );
<tr><th align=left>XL(User ID:)</th><td>$cpi_vars::USER</td></tr>
<tr><th align=left>XL(Entire name:)</th><td><input type=text autocapitalize=words name=fullname value="$fullname" size=30></td></tr>
EOF
	}
#<tr><th align=left>XL(Entire name:)</th><td>$cpi_vars::FULLNAME</td></tr>
    my %current = ();
    my %confirmed = ();
    foreach my $fld ( @cpi_vars::CONFIRM_FIELDS )
        {
	$current{$fld} = &dbget($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,$fld);
	my $lf = &dbget($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,"last".$fld) || "";
	if( ! $current{$fld} )
	    { $confirmed{$fld} = ""; }
	elsif( ($current{$fld}||"") eq $lf )
	    { $confirmed{$fld} = "(Confirmed)"; }
	else
	    { $confirmed{$fld} = "(Unconfirmed)"; }
	}
    push( @toprint, <<EOF );
<tr><th align=left>XL(Password:)</th>
    <td><input type=password name=password0 size=12></td>
    </th></tr>
<tr><th align=left>XL(Password repeated:)</th>
    <td><input type=password name=password1 size=12></td></tr>
EOF
    foreach my $fld ( @cpi_vars::CONFIRM_FIELDS )
        {
	push( @toprint, "<tr><th align=left valign=top>XL($cpi_vars::FLDESC{$fld}{prompt}:)</th><td>",
	    ( ( $cpi_vars::FLDESC{$fld}{rows} && $cpi_vars::FLDESC{$fld}{rows}>1 )
	    ? "<textarea cols=$cpi_vars::FLDESC{$fld}{cols} rows=$cpi_vars::FLDESC{$fld}{rows} name=$fld >$current{$fld}</textarea>"
	    : "<input type=text name=$fld autocapitalize=none size=$cpi_vars::FLDESC{$fld}{cols} value='$current{$fld}'>"
	    ),
	    "XL($confirmed{$fld})</td></tr>" )
	    if( $cpi_vars::FLDESC{$fld}{ask} );
	}
    if( &can_cuser )
	{
	push( @toprint, "<tr><th align=left>XL(Groups:)</th>\n" );
	$_ = 10 if( ($_ = scalar( keys %mygroups )) > 10 );
	push( @toprint, "<td><select name=groups multiple size=$_>\n" );
	foreach $g ( sort keys %mygroups )
	    {
	    push( @toprint,
		"<option value=\"$g\" ".($thisusergroup{$g}||"").">",
	        &group_to_name($g) . "\n" );
	    }
	push( @toprint, <<EOF );
</select></td></tr>
EOF
	}
    $_ = (  ( $cpi_vars::FORM{switchuser} eq "*" )
	    ? "XL(Create new user)"
	    : "XL(Modify) $cpi_vars::USER" );
    push( @toprint, <<EOF );
<tr><th colspan=2><input type=button value="$_" onClick='document.$form_admin.modrequest.value="modify_user";submit();'>
EOF
    push( @toprint, <<EOF ) if( ( $cpi_vars::FORM{switchuser} ne "*" ) && &can_cuser );
<input type=button value="XL(Delete [[$cpi_vars::USER]])" onClick='document.$form_admin.modrequest.value="delete_user";submit();'>
EOF
    push( @toprint, <<EOF );
    </th></tr>
<tr><th colspan=2>&nbsp;</th></tr>
<tr><th align=left>XL(Enter activation code:)</th>
    <td><input type=text autocapitalize=none name=activation_code onChange='submit();'></td></tr>
</table></th>
EOF

    if( $cpi_vars::PAYMENT_SYSTEM )
        {
	my($sec,$min,$hour,$mday,$month,$year) = localtime(time);
	my( $topay, $weight, $cardname, $cardnum, $cardonfile, $checknum, $certnum, $usecash );
	my $expselect = "";

	$cardname = &dbget($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,
			"cardname");
	$cardnum = &dbget($cpi_vars::ACCOUNTDB,"users",$cpi_vars::USER,
			"cardnum");
	$_ = length( $cardnum );
	$cardnum = "************".substr($cardnum,$_-4,4);
	my %selflag = ( &dbget($cpi_vars::ACCOUNTDB,"users",
			    $cpi_vars::USER,"cardexp"), " selected" );

	for( $_=0; $_<48; $_++ )
	    {
	    my $dstr = sprintf("%02d/%d",$month,$year+1900);
	    $expselect .= "<option".($selflag{$dstr}||"")." value=$dstr>$dstr\n";
	    if( ++$month > 12 )
	        {
		$month = 1;
		$year++;
		}
	    }
	push( @toprint, <<EOF );
<th valign=top><table>
<tr><th align=left>XL(To pay:)</th>
    <td><input type=text name=topay autocapitalize=none value="$topay" size=6></td></tr>
<tr><th colspan=2>&nbsp;</th></tr>
<tr><th align=left>XL(Name on credit card:)</th>
    <td><input type=text name=cardname autocapitalize=words value="$cardname" size=20></td></tr>
<tr><th align=left>XL(Credit card number:)</th>
    <td><input type=text name=cardnum value="$cardnum">
    </td></tr>
<tr><th align=left>XL(Expiration:)</th><td><select name=cardexp>
$expselect
</select>
&nbsp;&nbsp;<b>Save:</b>
<input type=checkbox name=cardonfile $cardonfile></td></tr>
<tr><th colspan=2>XL(OR)</th></tr>
<tr><th align=left>XL(Number on the Cheque:)</th>
    <td><input type=text name=checknum value="" size=10></td></tr>
<tr><th colspan=2>XL(OR)</th></tr>
<tr><th align=left>XL(Number on the Certificate:)</th>
    <td><input type=text name=certnum value="" size=10></td></tr>
<tr><th colspan=2>XL(OR)</th></tr>
<tr><th align=left>XL(Cash:)</th>
    <td><input type=checkbox name=usecash $usecash></td></tr>
<tr><th colspan=2><input type=button
    onClick='document.$form_admin.modrequest.value="payment";submit();'
    value="XL(Complete the payment)"></th></tr>
</table></th>
EOF
	}

    if( &can_cgroup )
        {
	push( @toprint, <<EOF );
<th valign=top><table>
<tr><th align=left>XL(Create group:)</th>
    <td><input type=text autocapitalize=words value="" size=10
	onChange='document.$form_admin.groupname.value=this.value;document.$form_admin.modrequest.value="add_group";submit();'></td>
	<td></td>
</tr>
EOF
	foreach my $g ( &groups() )
	    {
	    push( @toprint,
		"<tr><th align=left>$g</th><td>",
		"<input type=text autocapitalize=words size=10 value=\"",
	        &group_to_name( $g ),
	        "\" onChange='document.$form_admin.group.value=\"$g\";document.$form_admin.groupname.value=this.value;document.$form_admin.modrequest.value=\"change_group\";submit();'>",
	        "</td><td><input type=button value=\"XL(Delete)\" ",
	        "onClick='document.$form_admin.modrequest.value=\"delete_group\";document.$form_admin.group.value=\"$g\";submit();'>",
	        "</td></tr>\n" );
	    }
	push( @toprint, "</table></th>" );
	}

    push( @toprint, "<td valign=top>" . &who() . "</td>" );

    push( @toprint, "</tr></table></form>\n" );
    &xprint( @toprint );
    &main::footer("admin") if( exists(&main::footer) );;
    &cleanup(0);
    }

1;
#########################################################################
#	Used by the common administrative functions.			#
#########################################################################
sub footer
    {
    my( $mode ) = @_;

    $mode = "admin" if( !defined($mode) );

    my $s = <<EOF;
<script>
function footerfunc( fnc )
    {
    with( window.document.footerform )
	{
	func.value = fnc;
	submit();
	}
    }
</script>
<form name=footerform method=post>
<input type=hidden name=func>
<input type=hidden name=SID value="$cpi_vars::SID">
<input type=hidden name=USER value="$cpi_vars::USER">
EOF
    $s .= <<EOF;
    <center><table $cpi_vars::TABLE_TAGS border=1>
    <tr><th><table $cpi_vars::TABLE_TAGS><tr><th>
EOF
    $s .= &logout_select("footerform") . <<EOF;
	</th></tr>
	</table></th></tr></table></center></form>
EOF
    &xprint( $s );
    }

#########################################################################
#	Handle regular user commands					#
#########################################################################
sub user_logic
    {
    if( $cpi_vars::FORM{func} eq "admin" )
	{ &admin_page(); }
    else
        { &admin_page(); }
    }

#########################################################################
#	Go read through all the the things that need to be translated.	#
#########################################################################

#########################################################################
#	Main								#
#########################################################################

if( ! $ENV{SCRIPT_NAME} )
    {
    my( $fnc, @args ) = @ARGV;
    &fatal("XL(Usage):  $cpi_vars::PROG.cgi (dump|dumpaccounts|dumptranslations|undump|undumpaccounts|undumptranslations) [ dumpname ]",0)
    }

#&show_vars("All vars:");

my $css = "";
$form_top = <<EOF;
<style>
<!--
$css
-->
</style>
<script>
function submit_func( fnc )
    {
    with( window.document.$FORMNAME )
	{
	func.value = fnc;
	submit();
	}
    }
</script>
</head><body $cpi_vars::BODY_TAGS>
<form name=$FORMNAME method=post>
<input type=hidden name=func>
<input type=hidden name=SID value="$cpi_vars::SID">
<input type=hidden name=USER value="$cpi_vars::USER">
EOF

&user_logic();

&cleanup(0);
