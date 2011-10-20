#################################################################################
#                           QuickBase Client for Perl                           #
#                           -------------------------                           #
#                                                                               #
# Copyright (C) 2011 by Jason Hutchinson                                        #
#                                                                               #
# Permission is hereby granted, free of charge, to any person obtaining a copy  #
# of this software and associated documentation files (the "Software"), to deal #
# in the Software without restriction, including without limitation the rights  #
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell     #
# copies of the Software, and to permit persons to whom the Software is         #
# furnished to do so, subject to the following conditions:                      #
#                                                                               #
# The above copyright notice and this permission notice shall be included in    #
# all copies or substantial portions of the Software.                           #
#                                                                               #
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR    #
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,      #
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE   #
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER        #
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, #
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN     #
# THE SOFTWARE.                                                                 #
#################################################################################

package HTTP::QuickBase;

use strict;
use LWP::UserAgent;
use MIME::Base64 qw(encode_base64);

my %xml_escapes; 

my $VERSION = sprintf "%d.%03d", q$Revision: 2.001 $ =~ /: (\d+)\.(\d+)/;

sub new{
    my $class = shift;
    my $prefix = shift;
    my $self;

    for (0..255){
        $xml_escapes{chr($_)} = sprintf("&#%03d;", $_);
    }

    $self = bless {
        'url_prefix' => $prefix || "https://www.quickbase.com/db" ,
        'ticket' => undef,
        'apptoken' => "",
        'error' => undef,
        'errortext' => undef,
        'username' => undef,
        'password' => undef,
        'credentials' => undef,
        'proxy' => undef,
        'realmhost' => undef
        }, $class;
}

sub add_db_page{
    my ($self, $db, $pagename, $pagetype, $pagebody) = @_;
    if(ref($pagename) eq "HASH"){
        return $self->add_replace_db_page($db, undef, $pagename->{pagename}, $pagename->{pagetype}, $pagename->{pagebody})
    }else{
        return $self->add_replace_db_page($db, undef, $pagename, $pagetype, $pagebody);
    }
}

sub add_record{
    my ($self, $db, $data) = @_;
    my @record;
    if(ref($data) eq 'HASH'){
        for my $key (keys %{$data}){
            my $att_key = $key =~ /[^0-9]/ ? "name" : "fid";
            ( my $att_val = lc($key) ) =~ s/[^a-z0-9]/_/g;
            push @record, {
                tag   => "field", 
                atts  => {$att_key => $att_val},
                value => $data->{$key}
            };
        }
    }else{
        @record=@$data;
    }
    return between($self->post_api($db, "API_AddRecord", \@record)->content, "<rid>", "</rid>");
}

sub add_replace_db_page{
    my($self, $db, $pageid, $pagename, $pagetype, $pagebody) = @_;
    my $res;
    if(ref($pageid) eq "HASH"){
        $res = $self->post_api($db, "API_AddReplaceDBPage", $pageid);
    }else{
        if($pageid =~ m{^\d$}){ # Editing
            $res = $self->post_api($db, "API_AddReplaceDBPage", {pageid => $pageid, pagetype => $pagetype, pagebody => $pagebody});
        }else{ #Adding
            $res = $self->post_api($db, "API_AddReplaceDBPage", {pageid => $pageid, pagename => $pagename, pagetype => $pagetype, pagebody => $pagebody});
        }
    }
    return between(lc($res->content), "<pageid>", "</pageid>");
}

sub apptoken{my ($self,$apptoken) = @_;$self->{'apptoken'} = $apptoken || $self->{'apptoken'};}

sub authenticate ($$){
    my ($self,$u,$p) = @_;
    $self->{'username'} = $u;
    $self->{'password'} = $p;

    $self->{'ticket'} = $self->get_ticket($u,$p);

    return $self->{'ticket'};
}

sub replace_db_page{
    my ($self, $db, $pageid, $pagename, $pagetype, $pagebody) = @_;
    return $self->add_replace_db_page($db, $pageid, $pagename, $pagetype, $pagebody);
}

sub get_ticket{
    my ($self,$u,$p) = @_;
    $u=$u || $self->{'username'};
    $p=$p || $self->{'password'};
    return [$self->post_api("main", "API_Authenticate", {username=>$u, password=>$p})->content =~ /<ticket>(.+)<\/ticket>/i]->[0] || "";
}

sub proxy{my ($self, $proxy) = @_;$self->{'proxy'} = $proxy || $self->{'proxy'};}

sub realmhost{my ($self, $realmhost) = @_;$self->{'realmhost'} = $realmhost || $self->{'realmhost'};}

sub errortext{my ($self, $errortext) = @_;$self->{'errortext'} = $errortext || $self->{'errortext'};}
sub error{my ($self, $error) = @_;$self->{'error'} = $error || $self->{'error'};}

sub url_prefix{
    my($self) = shift;
    if (@_){
        $self->{'url_prefix'}=shift;
        # Seems to be internal to QB, should not be in public SDK
        $self->{'url_prefix'} =~ s/cgi\/sb.exe/db/;
        return $self->{'url_prefix'};
    }else{
        return $self->{'url_prefix'};
    }
}

sub post_api{
    my $self=shift;
    my ($db, $action, $params, $headers)=@_;
    
    my $process_param = sub {
        my ($tag,$value,$atts) = @_;
        
        $tag = $tag || "field";
        
        # Handle file attachments
        if($atts->{filename} or $atts->{file}){
            my $file = $atts->{filename} || $atts->{file};
            my $filename = "";
            my $buffer   = "";
            if($file =~ /[\\\/]([^\/\\]+)$/){
                $filename=$1;
            }else{
                $filename=$file;
            }
            
            unless(open(FORUPLOADTOQUICKBASE, "<$file")){
                $value = encode_base64("Sorry QuickBase could not open the file '$file' for input, for upload to this field in this record.", "")
            }
            binmode(FORUPLOADTOQUICKBASE);
            while(read(FORUPLOADTOQUICKBASE, $buffer, 60*57)){
                $value .= encode_base64($buffer,"");
            }
            close(FORUPLOADTOQUICKBASE);

            $atts->{filename} = $filename;
            delete $atts->{file};
        }

        # ARRAY type
        return "<$tag".
        (scalar(keys %{$atts}) ? ' ' : '').
        join(" ", map {$self->xml_escape($_).'="'.$self->xml_escape($atts->{$_}).'"'} keys %{$atts}).
        ">".$self->xml_escape($value)."</$tag>";
    };
    
    # Set default headers
    $headers->{'QUICKBASE-ACTION'}=($action || $headers->{action} || $headers->{'QUICKBASE-ACTION'});
    $headers->{'Content-Type'}=($headers->{'Content-Type'} || $headers->{'content-type'} || $headers->{'Content-type'} || 'text/xml');
    
    foreach my $header(qw(Content-type content-type action)){
        delete $headers->{"$header"};
    }

    # Create UserAgent (can be considered a "browser" of Perl)
    my $ua = new LWP::UserAgent;
    # How we should identify our "browser" to the server
    $ua->agent("QuickBasePerlAPI/$VERSION");
    # Has the user assigned a proxy?
    if($self->{'proxy'}){
        # If so, have our UserAgent use the proxy for both HTTP and HTTPS requests
        $ua->proxy(['http','https'], $self->{'proxy'});
    }
    
    # Create a new HTTP Request object
    my $req = new HTTP::Request;
    $req->method('POST');
    
    # Has the user defined a realm?
    $req->uri($self->url_prefix().($self->{'realmhost'} ? "/$db?realmhost=$self->{'realmhost'}" : "/$db"));
    
    # Tell the server what kind of information to expect
    $req->content_type('text/xml');
    
    # Set the request headers (including the QB API action)
    while( my ($k, $v) = each %{$headers}){
        $req->header("$k" => "$v");
    }
    
    # Create the XML content of the request
    my $content="<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n".
            "<qdbapi>\n".
                ($self->{apptoken} ? "\t<apptoken>$self->{apptoken}</apptoken>\n" : "").
                ($self->{ticket} ? "\t<ticket>$self->{ticket}</ticket>\n" : "").
                (
                    ref($params) eq "ARRAY"
                    ?
                    join("\n", map {$process_param->($_->{tag}, $_->{value}, $_->{atts});} @{$params})
                    :
                    (
                        ref($params) eq "HASH"
                        ?
                        join("\n", map {$process_param->($_, $params->{$_},{});} keys %{$params})."\n"
                        :
                        $params
                    )
                ).
            "</qdbapi>\n";
    
    if($self->{'debug'}){
        open(XML, ">C:/request.txt");
        print XML $content;
        close(XML);
    }
    
    $req->content($content);
    
    my $response = $ua->request($req);
    
    if($self->{'debug'}){
        open(XML, ">C:/response.txt");
        print XML $response->content;
        close(XML);
    }
    
    if($response->is_error()){
        if($response->code == 500){
            if(defined($self->{'retries'}) && $self->{'retries'}>5){
                die $response->code." ".$response->message."\n";
            }
            print "Error 500: ", $response->message, "\nRetrying...\n";
            $self->{'retries'}++;
            sleep(1);
            return $self->post_api(@_);
        }else{
            print $response->code." ".$response->message."\n";
        }
    }
    
    $self->{'retries'}=0;
    
    $self->{'error'} = between($response->content, "<errcode>", "</errcode>");
    $self->{'errortext'} = between($response->content, "<errdetail>", "</errdetail>") || between($response->content, "<errtext>", "</errtext>");
    
    if($self->{'error'} ne "0" and $self->{'error'} ne ""){
        print between($response->content, "<action>","</action>")." - Error ".$self->{'error'}.": ".$self->{'errortext'}."\n";
    }
    
    return $response;
}

sub add_user_to_role{
    my ($self, $db, $user, $role) = @_;
    return $self->post_api($db, "API_AddUserToRole", {userid=>$user, roleid=>$role}) =~ m{<errcode>0</errcode>}i;
}

sub change_user_role{
    my ($self, $db, $user, $oldrole, $newrole) = @_;
    return $self->post_api($db, "API_ChangeUserRole", {userid=>$user, roleid=>$oldrole, newroleid=>$newrole})->content =~ m{<errcode>0</errcode>}i;
}

sub change_record_owner{
    my ($self, $db, $rid, $newowner) = @_;
    return $self->post_api($db, "API_ChangeRecordOwner", {rid=>$rid, newowner=>$newowner})->content =~ m{<errcode>0</errcode>}i;
}

sub create_table{
    my ($self, $db, $tname, $pnoun) = @_;
    return between(lc($self->post_api($db,"API_CreateTable",{tname=>$tname, pnoun=>$pnoun})->content),"<newdbid>","</newdbid>");
}

sub delete_database{
    my ($self, $db) = @_;
    return $self->post_api($db, "API_DeleteDatabase", {})->content =~ m{<errcode>0</errcode>}i;
}

sub delete_record{
    my ($self, $db, $rid) = @_;
    return $self->post_api($db, "API_DeleteRecord", {rid=>$rid})->content =~ m{<errcode>0</errcode>}i;
}

# Because API_FieldAddChoices and API_FieldRemoveChoices are so similar, they 
# are combined into a "private" subroutine for ease.
sub _field_choices{
    my ($self, $db, $fid, $choices, $addremove) = @_;
    my @params;
    push(@params, {tag=>"fid", value=>$fid});
    foreach my $choice(@{$choices}){push(@params, {tag=>"choice", value=>$choice})}
    my ($ar_tag, $api)=($addremove>0?("numadded", "API_FieldAddChoices"):("numremoved", "API_FieldRemoveChoices"));
    return between($self->post_api($db, $api, \@params)->content, "<numadded>","</numadded>");
}

sub field_add_choices{my ($self, $db, $fid, $choices) = @_;return $self->_field_choices($db,$fid,$choices,1);}
sub field_remove_choices{my ($self, $db, $fid, $choices) = @_;return $self->_field_choices($db,$fid,$choices,-1);}

sub gen_add_record_form{
    my ($self, $db, $fields) = @_;
    my @params;
    foreach my $field(keys %$fields){
        push(@params, {tag=>"field", atts=>{name=>$field}, value=>$fields->{$field}});
    }
    return $self->post_api($db, "API_GenAddRecordForm", @params)->content;
}

sub gen_results_table{
    my ($self, $db, $query, $clist, $slist, $jht, $jsa, $options) = @_;
    
    if(ref($query) eq "HASH"){
        return $self->post_api($db, "API_GenAddRecordForm", {
            query=>$query->{query}, 
            clist=>$query->{clist}, 
            slist=>$query->{slist},
            jht=>$query->{jht}, 
            jsa=>$query->{jsa}, 
            options=>$query->{options}
        })->content;
    }else{
        return $self->post_api($db, "API_GenAddRecordForm", {
            query=>$query, clist=>$clist, slist=>$slist,
            jht=>$jht, jsa=>$jsa, options=>$options
        })->content;
    }
}

sub get_db_info{
    my ($self, $db) = @_;
    
    my $res = $self->post_api($db, "API_GetDBInfo", {})->content;
    
    my %db_info;
    
    foreach my $key(qw(dbname version lastRecModTime lastModifiedTime createdTime numRecords mgrID mgrName)){
        $db_info{$key}=between($res, "<$key>", "</$key>");
    }
    return %db_info;
}

sub get_db_page{
    my ($self, $db, $page_id) = @_;
    return $self->post_api($db, "API_GetDBPage", {($page_id =~ m{^\d+$} ? "pageid" : "pagename")=>$page_id})->content;
}

sub get_db_var{
    my ($self, $db, $var) = @_;
    return between($self->post_api($db, "API_GetDBvar", {varname=>$var})->content, "<value>", "</value>");
}

sub get_num_records{
    my ($self, $db) = @_;
    return between(lc($self->post_api($db, "API_GetNumRecords", {})->content), "<num_records>", "</num_records>");
}

# API_GetOneTimeTicket has no documentation in HTTP API Programmer's Guide
sub get_one_time_ticket{
    my ($self) = @_;
    return between(lc($self->post_api("main", "API_GetOneTimeTicket", {})->content), "<ticket>", "</ticket>");
}

sub get_record_info{
    my ($self, $db, $rid) = @_;
    return $self->post_api($db, "API_GetRecordInfo", {rid=>$rid})->content;
}

sub get_record{
    my ($self, $db, $rid) = @_;
    my $res = $self->get_record_info($db, $rid);
    
    my %record;
    
    $record{'rid'}        = between($res, "<rid>", "</rid>");
    $record{'num_fields'} = between($res, "<num_fields>", "</num_fields>");
    $record{'update_id'}  = between($res, "<update_id>", "</update_id>");
    
    my @fields = $res=~ /<field>(.+?)<\/field>/isg;
    
    foreach my $field(@fields){
        my %field = $field =~ m{<([^>]+)>(.+?)</\1>}ig;
        $record{$field{name}}=\%field;
        $record{"f_".$field{fid}}=\%field;
    }
    
    return \%record;
}

sub get_record_as_html{
    my ($self, $db, $rid, $jht) = @_;
    my %params=(rid=>$rid);
    if($jht == 1){$params{jht}=1;}
    return $self->post_api($db, "API_GetRecordAsHTML", \%params)->content;
}

sub get_role_info{
    my ($self, $db) = @_;
    my @roles = between($self->post_api($db, "API_GetRoleInfo", {})->content, "<roles>","</roles>") =~ /(<role.+?<\/role>)/isg;
    my @out;
    foreach my $role(@roles){
        my %role;
        $role{id}   = between($role, "role id=\"", "\"");
        $role{name} = between($role, "<name>", "</name>");
        $role{access_id} = between($role, "<access id=\"", "\"");
        $role{access} = between($role, "<access id=\"$role{access_id}\">", "</access>");

        push(@out, \%role);
    }
    return @out;
}

sub get_schema{
    my ($self, $db) = @_;
    my $res=$self->post_api($db, "API_GetSchema", {})->content;
    
    my %table;
    foreach my $key(qw(name desc table_id cre_date mod_date next_record_id next_field_id next_query_id def_sort_fid def_sort_order)){
        $table{$key}=between($res, "<$key>", "</$key>");
    }
    
    $table{variables}={};
    my $vars = between($res, "<variables>", "</variables>");
    foreach my $var(@{[$vars =~ /(<var .+?<\/var>)/isg]}){
        $table{variables}{between($var, "<var name=\"","\"")}=between($var, ">", "<");
    }
    $table{queries}={};
    $table{queries}=process_queries_xml(between($res, "<queries>", "</queries>",0,1));
    
    $table{fields}={};
    $table{fields} =process_fields_xml(between($res, "<fields>", "</fields>",0,1));
    
    $table{chdbids}={};
    my $chdbids = between($res, "<chdbids>", "</chdbids>");
    foreach my $chdbid(@{[$chdbids =~ /(<chdbid .+?<\/chdbid>)/isg]}){
        my $chdbid_name=between($chdbid, "<chdbid name=\"","\"");
        my $chdbid_dbid=between($chdbid, ">", "<");
        
        $table{chdbids}{$chdbid_name}=$chdbid_dbid if $chdbid_name;
    }
    
    return \%table;
}

sub get_dtm_info{
    my ($self, $dbid) = @_;
    my $res = $self->post_api($dbid, "API_GetAppDTMInfo")->content;
    
    my %info=(
        "RequestTime" => between($res, "<RequestTime>","</RequestTime>"),
        "RequestNextAllowedTime" => between($res, "<RequestNextAllowedTime>","</RequestNextAllowedTime>"),
        "tables" => ()
    );
    
    if($res =~ m{<app id=}){
        my $app=between($res, '<app id="', "</app>", 1);
        $info{'app_id'}=between($app, '<app id="', '"');
        $info{'lastModifiedTime'}=between($app,"<lastModifiedTime>","</lastModifiedTime>");
        $info{'lastRecModTime'}=between($app,"<lastRecModTime>","</lastRecModTime>");
    }
    
    foreach my $table([$res =~ m{(<table.+?</table>)}isg]){
        push(@{$info{'tables'}}, {
            "table_id"         => between($table, '<table id="','">'),
            "lastModifiedTime" => between($table,"<lastModifiedTime>","</lastModifiedTime>"),
            "lastRecModTime"   => between($table,"<lastRecModTime>","</lastRecModTime>")
        });
    }
    
    return %info;
}

sub get_user_info{
    my ($self, $user) = @_;
    my $res = $self->post_api("main", "API_GetUserInfo", {email=>$user})->content;
    
    my %user_info;
    $user_info{id}=between($res, '<user id="', '">');
    foreach my $key(qw(firstName lastName login email screenName isVerified externalAuth)){
        $user_info{$key}=between($res, "<$key>", "</$key>");
    }
    
    return \%user_info;
}

sub get_user_roles{
    my ($self, $db, $userid) = @_;
    my $res=$self->post_api($db, "API_GetUserRole", {userid=>$userid})->content;
    return {
        id=>between($res, "<user id=\"", "\""),
        name=>[$res =~ /<name>([^<]+?)<\/name>.*<roles>/is]->[0],
        roles=>process_roles_xml(between($res, "<roles>", "</roles>"))
    };
}

sub granted_dbs{
    my ($self, $include_parents, $include_children, $admin_only) = @_;
    
    my %params=();
    
    $params{'Excludeparents'}=($include_parents ? 0 : 1);
    $params{'withembeddedtables'}=($include_children ? 1 : 0);
    $params{'adminOnly'}=1 if $admin_only;
    
    my @databases = map {
        {
            "dbname" => between($_, "<dbname>", "</dbname>"),
            "dbid" => between($_, "<dbid>", "</dbid>")
        }
    } $self->post_api("main", "API_GrantedDBs", \%params)->content =~ m{<dbinfo>(.+?)</dbinfo>}sig;
    
    return @databases;
}

sub provision_user{
    my ($self, $db, $email, $fname, $lname, $roleid) = @_;
    return [$self->post_api($db, "API_ProvisionUser", {
        roleid=>$roleid,
        email=>$email,
        fname=>$fname,
        lname=>$lname
    })->content =~ /<userid>(.+?)<\/userid>/i]->[0];
}

sub remove_user_from_role{
    my ($self, $db, $userid, $roleid) = @_;
    return $self->post_api($db, "API_RemoveUserFromRole", {userid=>$userid, roleid=>$roleid})->content =~ m{<errcode>0</errcode>}i;
}

sub rename_app{
    my ($self, $db, $newappname) = @_;
    return $self->post_api($db, "API_RenameApp", {newappname=>$newappname})->content =~ m{<errcode>0</errcode>}i;
}

sub send_invitation{
    my ($self, $db, $userid, $usertext) = @_;
    return $self->post_api($db, "API_SendInvitation", {userid=>$userid, usertext=>$usertext})->content =~ m{<errcode>0</errcode>}i;
}

sub set_db_var{
    my ($self, $db, $varname, $value) = @_;
    return $self->post_api($db, "API_SetDBvar", {varname=>$varname, value=>$value})->content =~ m{<errcode>0</errcode>}i;
}

sub user_roles{
    my ($self, $db) = @_;
    my $res=$self->post_api($db, "API_UserRoles", {})->content;
    my @output_users;
    my @users = $res =~ /(<user id.+?<\/user>)/isg;
    
    foreach my $user(@users){
        my @roles = $user =~ /<roles>(.+)<\/roles>/isg;
        $user =~ s/<roles>.+<\/roles>//isg;
        push(@output_users, {
            id=> [$user=~/user id="(\d+)"/i]->[0],
            name=> [$user=~/<name>(.+)<\/name>/i]->[0],
            roles=> [
                map {
                    my $role=$_; 
                    return {
                        id=>[$role=~/role id="(\d+)"/i]->[0],
                        name=>[$role=~/<name>(.+)<\/name>/i]->[0],
                        access=>[$role=~/<access[^>]*>(.+)<\/access>/i]->[0],
                        access_id=>[$role=~/<access id="(\d+)"/i]->[0]
                    }
                } @roles
            ]
        });
    }
    return @output_users;
}

sub GetURL{
    my($self, $QuickBaseDBid, $action) = @_;
    my $error;

    unless( $action =~ /^act=API_|\&act=API_/i){
        $self->{'error'} = "1";
        $self->{'errortext'} = "Error: You're using a QuickBase URL that is not part of the HTTP API. ". $action . "\n"
            . "Please use only actions that start with 'API_' i.e. act=API_GetNumRecords.\n"
            . "Please refer to the <a href='https://www.quickbase.com/up/6mztyxu8/g/rc7/en/'>QuickBase HTTP API documentation</a>.";
        return $self->{'errortext'};
    }
    my $ua = new LWP::UserAgent;
    $ua->agent("QuickBasePerlAPI/$VERSION");
    if ($self->{'proxy'}){
        $ua->proxy(['http','https'], $self->{'proxy'});
    }
    my $req = new HTTP::Request;
    $req->method("GET");
    $req->uri($self->url_prefix()."/$QuickBaseDBid?$action");
    unless($self->{'ticket'}){
        $self->{'ticket'}=$self->getTicket($self->{'username'},$self->{'password'});
    }
    $req->header('Cookie' => "TICKET=$self->{'ticket'};");
    $req->header('Accept' => 'text/html');
    # send request
    my $res = $ua->request($req);

    # check the outcome
    if($res->is_error){
        $self->{'error'} = $res->code;
        $self->{'errortext'} =$res->message;
        return "Error: ".$res->code." ".$res->message;
    }
    return $res->content;
}

sub get_file{
    my ($self, $db, $rid, $fid, $version) = @_;
    my $prefix = $self->url_prefix();
    $prefix =~ s{/db$}{/up};
    
    $version = $version || 0;
    
    unless($self->{'ticket'}){
        $self->{'ticket'} = $self->get_ticket();
    }
    
    my $ua = new LWP::UserAgent;
       $ua->agent("QuickBasePerlAPI/$VERSION");
    
    if($self->proxy){
        $ua->proxy(['http','https'], $self->proxy);
    }

    my $uri = "$prefix/$db/a/r".$self->xml_escape($rid)."/e".$self->xml_escape($fid)."/?ticket=".$self->{'ticket'};

    my $req = new HTTP::Request;
       $req->method("POST");
       $req->uri($uri);
       $req->header('Accept' => '*/*');
       $req->header('Content-Length' => '0');
       
    my $res = $ua->request($req);
    
    if($res->is_error){
        $self->error($res->code);
        $self->errortext($res->message);
        return ("Error: ".$res->code." ".$res->message, $res->headers);
    }
    
    return ($res->content, $res->headers);
}

sub PostURL{
    my $self = shift;
    my $QuickBaseDBid = shift;
    my $action = shift;
    my $content = shift;
    my $content_type = shift || 'application/x-www-form-urlencoded';

    my $ua = new LWP::UserAgent;
    if ($self->{'proxy'}){
        $ua->proxy(['http','https'], $self->{'proxy'});
    }
    $ua->agent("QuickBasePerlAPI/1.0");
    my $req = new HTTP::Request;
    $req->method("POST");
    $req->uri($self->url_prefix."/$QuickBaseDBid?$action");
    unless ($self->{'ticket'}){
        $self->{'ticket'}=$self->getTicket($self->{'username'},$self->{'password'});
    }
    $req->header('Cookie' => "TICKET=$self->{'ticket'};");
    $req->content_type($content_type);

    #This is where we post the info for the new record

    $req->content($content);
    my $res = $ua->request($req);
    if($res->is_error()){
        $self->{'error'} = $res->code;
        $self->{'errortext'} =$res->message;
        return $res;
    }
    $res->content =~ /<errcode>(.*?)<\/errcode>.*?<errtext>(.*?)<\/errtext>/s ;
    $self->{'error'} = $1;
    $self->{'errortext'} = $2;
    if ($res->content =~ /<errdetail>(.*?)<\/errdetail>/s){
        $self->{'errortext'} = $1;
    }
    return $res;
}

sub PostAPIURL{
    my($self, $QuickBaseDBid, $action, $content) = @_;
    my $ua = new LWP::UserAgent;
    $ua->agent("QuickBasePerlAPI/$VERSION");
    if ($self->{'proxy'}){
        $ua->proxy(['http','https'], $self->{'proxy'});
    }
    my $req = new HTTP::Request;
    $req->method('POST');
    if($self->{'realmhost'}){
        $req->uri($self->url_prefix()."/$QuickBaseDBid?realmhost=$self->{'realmhost'}");
    }else{
        $req->uri($self->url_prefix()."/$QuickBaseDBid");
    }

    $req->content_type('text/xml');
    $req->header('QUICKBASE-ACTION' => "$action");

    if ($self->{'apptoken'} ne "" && $self->{'credentials'} !~ /<apptoken>/){
        $self->{'credentials'} .= "<apptoken>".$self->{'apptoken'}."</apptoken>";
    }

    if($content =~ /^<qdbapi>/){
        $content =~s/^<qdbapi>/<qdbapi>$self->{'credentials'}/;
    }elsif($content eq "" || !defined($content)) {
        $content ="<qdbapi>$self->{'credentials'}</qdbapi>";
    }
    if($content =~ /^<qdbapi>/){
        $content = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>" . $content;
    }
    my $res;
    if ($self->{'ticket'}){
        $req->header('Cookie' => "TICKET=$self->{'ticket'};");
    }

    $req->content($content);
    $res = $ua->request($req);
    if($res->is_error()){
        $self->{'error'} = $res->code;
        $self->{'errortext'} =$res->message;
        return $res;
    }
    if (defined ($res->header('Set-Cookie')) && $res->header('Set-Cookie') =~ /TICKET=(.+?);/){
        $self->{'ticket'} = $1;
        $self->{'credentials'} = "<ticket>$self->{'ticket'}</ticket>";
    }elsif ($res->content =~ /<ticket>(.+?)<\/ticket>/){
        $self->{'ticket'} = $1;
        $self->{'credentials'} = "<ticket>$self->{'ticket'}</ticket>";
    }

    $res->content =~ /<errcode>(.*?)<\/errcode>.*?<errtext>(.*?)<\/errtext>/s;
    $self->{'error'} = $1;
    $self->{'errortext'} = $2;
    if ($res->content =~ /<errdetail>(.*?)<\/errdetail>/s){
        $self->{'errortext'} = $1;
    }
    if($self->{'error'} eq '11'){
        $self->{'errortext'} .= "\nXML request:\n" . $content;
    }
    return $res;
}

sub find_db_by_name{
    my ($self, $db_name) = @_;
    my @dbids = $self->post_api("main", "API_FindDBByName", {dbname=>$db_name})->content =~ /<dbid>(.+?)<\/dbid>/g;
    return @dbids;
}

sub clone_database{
    my ($self, $db, $name, $desc, $keep_data, $exclude_files)=@_;
    $self->post_api("$db", "API_CloneDatabase", {
        newdbname=>$name, 
        newdbdesc=>$desc,
        keepdata=>$keep_data,
        excludefiles=>$exclude_files
    })->content =~ /<newdbid>(.*)<\/newdbid>/;
    return $1 || "";
}

sub create_database{
    my ($self, $name, $desc, $create_apptoken) = @_;

    my $content=$self->post_api("main", "API_CreateDatabase", {dbname=>$name, dbdesc=>$desc, createapptoken=>$create_apptoken})->content;

    return (
        dbid=>between($content, "<dbid>","</dbid>"), 
        appdbid=>between($content, "<appdbid>","</appdbid>"),
        apptoken=>between($content, "<apptoken>","</apptoken>")
    );
}

sub add_field{
    my ($self, $db, $label, $inp_type, $mode)=@_;
    my $type;
    
    $type = "checkbox"  if $inp_type =~ m{checkbox|check|cb|check box|check-box}i;
    $type = "dblink"    if $inp_type =~ m{dblink|databaselink|database link|database-link}i;
    $type = "date"      if $inp_type =~ m{date}i;
    $type = "duration"  if $inp_type =~ m{duration}i;
    $type = "email"     if $inp_type =~ m{email|e-mail}i;
    $type = "file"      if $inp_type =~ m{file|attachment|file-attachment|file attachment}i;
    $type = "float"     if $inp_type =~ m{numeric|float|floating}i;
    $type = "currency"  if $inp_type =~ m{currency|numeric currency|numeric-currency}i;
    $type = "rating"    if $inp_type =~ m{rating|rate|numeric rating|numeric-rating}i;
    $type = "phone"     if $inp_type =~ m{phone|phone number|phone ?#}i;
    $type = "text"      if $inp_type =~ m{text}i;
    $type = "timeofday" if $inp_type =~ m{timeofday|time of day|time}i;
    $type = "url"       if $inp_type =~ m{url|link|uri}i;
    
    my $content=$self->post_api($db, "API_AddField", {label=>$label, type=>$type, mode=>$mode})->content;

    return between($content, "<fid>", "</fid>");
}

sub delete_field{
    my ($self, $db, $fid)=@_;
    return $self->post_api($db, "API_DeleteField", {fid=>$fid})->content =~ m{<errcode>0</errcode>}i;
}

sub set_field_properties{
    my ($self, $db, $fid, $properties)=@_;
    my %params=((fid=>$fid), %$properties);
    return $self->post_api($db, "API_SetFieldProperties", \%params)->content =~ m{<errcode>0</errcode>}i;
}

# $query can be a scalar value or hash reference
sub purge_records{
    my ($self, $db, $query)=@_;
    
    unless(ref($query)){
        if($query =~ m/^\{.*\}$/){
            $query={query=>$query};
        }elsif($query =~ m/^\d+$/){
            $query={qid=>$query};
        }else{
            $query={qname=>$query};
        }
    }
    
    return between($self->post_api($db, "API_PurgeRecords", $query)->content, "<num_records_deleted>","</num_records_deleted>");
}

sub do_query{
    my ($self, $db, $query, $clist, $slist, $options, $fmt)=@_;

    my %response=(
        "records" => [],
        "users" => []
    );

    $fmt="structured" unless defined($fmt);

    my %params=(
        fmt=>$fmt,
        clist=>$clist,
        slist=>$slist,
        options=>$options
    );

    if ($query =~ /^\{.*\}$/){
        $params{query}=$query;
    }elsif ($query =~ /^\d+$/){
        $params{qid}=$query;
    }else{
        $params{qname}=$query;
    }

    my $result = $self->post_api($db, "API_DoQuery", \%params)->content;
    
    if(lc($fmt) eq "structured"){
        my @keys=qw(action errcode errtext qid qname name desc table_id app_id cre_date mod_date next_record_id next_field_id next_query_id def_sort_fid def_sort_order lastluserid);
        
        foreach my $key(@keys){
            $response{$key}=between($result, "<$key>", "</$key>") if index($result, "<$key>")>-1;
        }

        ########################################################
        ##                       FIELDS                       ##
        ########################################################        

        $response{fields} = process_fields_xml(between($result,"<fields>","</fields>",0,1));
        
        ########################################################
        ##                      QUERIES                       ##
        ########################################################        

        $response{queries} = process_queries_xml(between($result,"<queries>","</queries>",0,1));

        #########################################################
        ##                        USERS                        ##
        #########################################################        
        
        $response{users}=();
        
        my @users = split "\r\n", between($result, "<lusers>", "</lusers>");
        shift(@users);
        
        foreach my $user(@users){
            $response{users}{between($user, '"', '"')}=between($user, "\">", "</");
        }
       
        #########################################################
        ##                       RECORDS                       ##
        #########################################################
        
        my @records = split "</record>", between($result, "<records>", "</records>");
        pop(@records);
                
        foreach my $record(@records){
            my %rec=(update_id=>between($record, "<update_id>", "</update_id>"));
            
            foreach my $id(keys %{$response{fields}{by_id}}){
                my $val="";
                unless($record =~ m{<f id="$id"/>}i){
                    $val=between($record, "<f id=\"$id\">", "</f>");
                }
                
                $rec{"f_$id"}=$self->xml_unescape($val);
                $rec{$response{fields}{by_id}{$id}{label}}=$self->xml_unescape($val);
            }
            push(@{$response{records}}, \%rec);
        }
    }else{ # unstructured
        my @keys=qw(action errcode errtext name desc);

        foreach my $key(@keys){
            $response{$key}=between($result, "<$key>", "</$key>")  if index($result, "<$key>")>-1;
        }
        
        my @records = $result =~ /<record>(.+?)<\/record>/gs;
        
        foreach my $record(@records){
            my %rec;
            my @fields = $record =~ /<([^>]+)>([^<]+)<\/[^>]+>/g;
            my @fieldsets;
            push @fieldsets, [splice @fields, 0, 2] while @fields;
            
            foreach my $fieldset(@fieldsets){
                $rec{@{$fieldset}[0]}=@{$fieldset}[1];
            }
            push(@{$response{records}}, \%rec);
        }
    }
    
    return(wantarray() ? @{$response{records}||()} : \%response);
}

sub get_complete_csv{
    my ($self, $db)=@_;
    return $self->post_api($db, "API_GenResultsTable", {query=>"{'0'.CT.''}", clist=>"a", options=>"csv"})->content;
}

sub get_rids{
    my ($self, $db)=@_;
    my @arr=split(/\r\n|\r|\n/, $self->post_api($db, "API_GenResultsTable", {query=>"{'0'.CT.''}", clist=>"3", slist=>"3", options=>"csv"})->content);
    return splice(@arr,1);
}

sub edit_record{
    my ($self, $db, $rid, $fields) = @_;
    return $self->edit_record_with_update_id($db, $rid, 0, $fields);
}

sub edit_record_with_update_id{
    my ($self, $db, $rid, $uid, $fields) = @_;
    
    my @params=({tag=>"rid", value=>$rid});
    if($uid){push(@params, {tag=>"update_id", value=>$uid});}
    
    if(ref($fields) eq "ARRAY"){
        foreach my $field(@{$fields}){
            foreach my $att(qw(name fid)){
                if(defined($fields->{$att})){
                    push(@params, {tag=>"field", atts=>{"$att"=>$fields->{$att}},value=>$fields->{value}});
                }
            }
        }
    }else{ # HASH
        while(my ($field, $value) = each(%{$fields})){
            push(@params,{tag=>"field", atts=>{($field=~m/^\d+$/?"fid":"name")=>$field}, value=>$value});
        }
    }
    
    my $content=$self->post_api($db, "API_EditRecord", \@params)->content;
    
    if($self->error ne '0'){
        return 0;
    }
    
    return (
        num_fields_changed => between($content, "<num_fields_changed>","</num_fields_changed>"),
        update_id          => between($content, "<update_id>", "</update_id>"),
        content => $content
    );
}

sub import_from_csv{
    my ($self, $db, $data, $clist, $skip) = @_;
    return $self->post_api($db, "API_ImportFromCSV", {clist=>$clist, skipfirst=>($skip ? 1 : 0), records_csv=>"<![CDATA[$data]]>"})->content;
}

sub GetNextField ($$$$){
    my ($self, $datapointer, $delim, $offsetpointer, $fieldpointer)=@_;
    my $BEFORE_FIELD=0;
    my $IN_QUOTED_FIELD=1;
    my $IN_UNQUOTED_FIELD=2;
    my $DOUBLE_QUOTE_TEST=3;
    my $c="";
    my $state = $BEFORE_FIELD;
    my $p = $$offsetpointer;
    my $endofdata = length($$datapointer);
    my $false=0;
    my $true=1;
    
    $$fieldpointer = "";
    
    while ($true){
        if ($p >= $endofdata){
            # File, line and field are done
            $$offsetpointer = $p;
            return $false;
        }

        $c = substr($$datapointer, $p, 1);
    
        if($state == $DOUBLE_QUOTE_TEST)
            {
            # These checks are ordered by likelihood */
            if ($c eq $delim){
                # Field is done; delimiter means more to come
                $$offsetpointer = $p + 1;
                return $true;
            }elsif ($c eq "\n" || $c eq "\r"){
                # Line and field are done
                $$offsetpointer = $p + 1;
                return $false;
            }elsif ($c eq '"'){
                # It is doubled, so append one quote
                $$fieldpointer .= '"';
                $p++;
                $state = $IN_QUOTED_FIELD;
                }else{
                # !!! Shouldn't have anything else after an end quote!
                # But do something reasonable to recover: go into unquoted mode
                $$fieldpointer .= $c;
                $p++;
                $state = $IN_UNQUOTED_FIELD;
            }
        }elsif($state == $BEFORE_FIELD){
            # These checks are ordered by likelihood */
            if ($c eq $delim){
                # Field is blank; delimiter means more to come
                $$offsetpointer = $p + 1;
                return $true;
            }elsif ($c eq '"'){
                # Found the beginning of a quoted field
                $p++;
                $state = $IN_QUOTED_FIELD;
            }elsif ($c eq "\n" || $c eq "\r"){
                # Field is blank and line is done
                $$offsetpointer = $p + 1;
                return $false;
            }elsif ($c eq ' '){
                # Ignore leading spaces
                $p++;
            }else{
                # Found some other character, beginning an unquoted field
                $$fieldpointer.=$c;
                $p++;
                $state = $IN_UNQUOTED_FIELD;
            }
        }elsif ($state == $IN_UNQUOTED_FIELD){
            # These checks are ordered by likelihood */
            if ($c eq $delim){
                # Field is done; delimiter means more to come
                $$offsetpointer = $p + 1;
                return $true;
            }elsif ($c eq "\n" || $c eq "\r"){
                # Line and field are done
                $$offsetpointer = $p + 1;
                return $false;
            }else{
                # Found some other character, add it to the field
                $$fieldpointer.=$c;
                $p++;
            }
        }elsif($state == $IN_QUOTED_FIELD){
            if ($c eq '"')                {
                $p++;
                $state = $DOUBLE_QUOTE_TEST;
            }else{
                # Found some other character, add it to the field
                $$fieldpointer.=$c;
                $p++;
            }
        }   
    }
}

sub GetNextLine ($$$$$$){
    my ($self, $data, $delim, $offsetpointer, $fieldpointer, $line, $lineIsEmptyPtr)=@_;
    my $false=0;
    my $true=1;

    undef(@$line);
    # skip any empty lines
    while(
        $$offsetpointer < length($$data)
        && 
        (
            substr($$data, $$offsetpointer, 1) eq "\r"
            ||
            substr($$data, $$offsetpointer, 1) eq "\n"
        )
    ){
        $$offsetpointer++;
    }
    
    if ($$offsetpointer >= length($$data)){
        return $false;
    }
    
    $$lineIsEmptyPtr = $true;
    my $moreToCome;
    do{
        $moreToCome = $self->GetNextField ($data, $delim, $offsetpointer, $fieldpointer);
        push (@$line, $$fieldpointer);
        if ($$fieldpointer){
            $$lineIsEmptyPtr = $false;
        }
    }while($moreToCome);

    return $true;
}

sub ParseDelimited ($$){
    my ($self, $data, $delim)=@_;
    my @output;
    my @line;
    my $offset=0;
    my $field="";
    my $lineEmpty=1;
    my $maxsize = 0;
    my $numfields=0;
    my $i;

    # Parse lines until the eof is hit
    while ($self->GetNextLine (\$data, $delim, \$offset, \$field, \@line, \$lineEmpty)){
        unless($lineEmpty){
            push (@output, [@line]);
            $numfields=@line;
            if ($numfields > $maxsize){
                $maxsize = $numfields;
            }
        }
    }
        
    # If there are any lines which are shorter than the longest
    # lines, fill them out with "" entries here. This simplifies
    # checking later.
    foreach $i(@output){
        while (@$i < $maxsize){
            push (@$i, "");
        }
    }
        
    return @output;
}

sub process_fields_xml{
    my $xml = shift;
    my %response;
    my @fields = split "</field>", between($xml, "<fields>","</fields>");
    pop(@fields);

    $response{by_id}={};

    foreach my $field(@fields){
        my ($id) = $field =~ /<field.*id="(\d+)"/i;
        my ($field_type) = $field =~ /<field.*field_type="([^"]+)"/i;
        my ($base_type) = $field =~ /<field.*base_type="([^"]+)"/i;
        my ($role) = $field =~ /<field.*role="([^"]+)"/i;
        my ($mode) = $field =~ /<field.*mode="([^"]+)"/i;

        $response{by_id}{$id}={
            field_type=>$field_type,
            base_type=>$base_type,
            role=>$role,
            mode=>$mode
        };
        
        foreach my $key(qw(
                label nowrap bold required appears_by_default find_enabled allow_new_choices sort_as_given 
                carrychoices foreignkey unique doesdatacopy fieldhelp display_user default_kind num_lines 
                append_only allowHTML has_extension max_versions see_versions use_new_window comma_start 
                does_average does_total blank_is_zero
            )){
            $response{by_id}{$id}{$key}=between($field, "<$key>", "</$key>");
        }

        $response{by_label}{$response{by_id}{$id}{label}}=$response{by_id}{$id};
    }
    return \%response;
}

sub process_queries_xml{
    my $xml=shift;    
    my %response;    
    my @queries = split "</query>", between($xml, "<queries>","</queries>");    
    pop(@queries);
    foreach my $query(@queries){
        my ($id) = $query =~ /<query.*id="(\d+)"/i;
        $response{by_id}{$id}={"id"=>$id};
        foreach my $key(qw(qyname qytype qycrit qyopts qycalst qyclst qydesc qyslst qyform qyflbl qyftyp)){
            $response{by_id}{$id}{$key}=between($query, "<$key>", "</$key>");
        }
        $response{by_name}{$response{by_id}{$id}{qyname}}=$response{by_id}{$id};
    }    
    return \%response;
}

sub process_roles_xml{
    my $xml=shift;
    my @roles;
    foreach my $role(@{[$xml =~ /(<role .+?<\/role>)/sig]}){
        my $aid=between($role, "<access id=\"", "\"");
        push(@roles,{
            id        => between($role, "<role id=\"", "\""),
            name      => between($role, "<name>", "</name>"),
            access_id => $aid,
            access    => between($role, "<access id=\"$aid\">", "</access>")
        })
    }
    return \@roles;
}

sub between{
    my ($str, $start, $end, $pos, $inclusive) = @_;

    $pos=0         unless defined($pos);
    $inclusive = 0 unless defined($inclusive);

    my $start_index =index($str, $start, $pos);
       $start_index+=length($start) unless $inclusive;
    
    my $end_index =index($str, $end, $start_index)-$start_index;
       $end_index+=length($end) if $inclusive;
    
    return "" if $start_index < 0 or $end_index < 0;
    
    return substr($str, $start_index, $end_index);
}

sub xml_escape($) {
    my ($self, $rest) = @_;
    unless(defined($rest)){return "";}
    $rest   =~ s/&/&amp;/g; 
    $rest   =~ s/</&lt;/g;
    $rest   =~ s/>/&gt;/g;
    $rest   =~ s/([^;\/?:@&=+\$,A-Za-z0-9\-_.!~*'()# ])/$xml_escapes{$1}/g;
    return $rest;
} 

sub xml_unescape($) {
    my ($self, $rest) = @_;
    unless(defined($rest)){return "";}
    $rest   =~ s/<br\/>\n?/\n/ig;
    $rest   =~ s/&lt;/</g;
    $rest   =~ s/&gt;/>/g;
    $rest   =~ s/&amp;/&/g;
    $rest   =~ s/&apos;/'/g;
    $rest   =~ s/&quot;/\"/g;
    $rest   =~ s/&#([0-9]{2,3});/chr($1)/eg;
    return $rest;
} 

sub encode32($){
    my ($self, $number) = @_;
    my $result = "";
    while ($number > 0){
          my $remainder = $number % 32;
          $number = ($number - $remainder)/32; 
          $result = substr('abcdefghijkmnpqrstuvwxyz23456789', $remainder, 1) . $result;
    }
    return $result;
}

sub unencode32 ($){
    my ($self, $number) = @_;
    my $result = 0;
    while ($number ne ""){
        my $l = length($number);
        my $firstchar = substr($number, 0, 1);
        $result = ($result * 32) + index('abcdefghijkmnpqrstuvwxyz23456789', $firstchar);
        $number = substr($number, 1, $l-1);
    }
    return $result;
}

sub createFieldXML{
    my($self, $tag, $value) = @_;
    my $nameattribute;
    if($tag =~ /^[1-9]\d*$/){
        $nameattribute = "fid";
    }else{
        $nameattribute = "name";
    }
    if(ref($value) eq "ARRAY"){
        if($$value[0] =~ /^file/i){
            #This is a file attachment!
            my $filename = "";
            my $buffer = "";    
            my $filecontents = "";
            if($$value[1] =~ /[\\\/]([^\/\\]+)$/){
                $filename = $1;
            }else{
                $filename = $$value[1];
            }
            unless(open(FORUPLOADTOQUICKBASE, "<$$value[1]")){
                $filecontents = encode_base64("Sorry QuickBase could not open the file '$$value[1]' for input, for upload to this field in this record.", "");
            }
            binmode FORUPLOADTOQUICKBASE;
            while (read(FORUPLOADTOQUICKBASE, $buffer, 60*57)){
                $filecontents .= encode_base64($buffer, "");
            }
            close FORUPLOADTOQUICKBASE;
            return "<field $nameattribute='$tag' filename=\"".$self->xml_escape($filename)."\">".$filecontents."</field>";
        }
    }else{
        $value = $self->xml_escape($value);
        return "<field $nameattribute='$tag'>$value</field>";
    }
}

################################ DEPRECATED ################################

sub CreateTable{my($self,$db, $pnoun, $tname) = @_;return $self->create_table($db, $tname, $pnoun);}
sub DeleteDatabase{my($self,$db) = @_;return $self->delete_database($db)}
sub DeleteRecord{my($self, $db, $rid) = @_;return $self->delete_record($db, $rid)->content;}
sub FieldAddChoices{my ($self,$db,$fid,@choices) = @_;return $self->field_add_choices($db, $fid, \@choices)}
sub FieldRemoveChoices{my ($self,$db,$fid,@choices) = @_;return $self->field_remove_choices($db, $fid, \@choices)}
sub GenAddRecordForm{my ($self,$db,%fields) = @_;return $self->gen_add_record_form($db,\%fields);}
sub AddUserToRole{my ($self,$db, $user, $role) = @_;return $self->add_user_to_role($db, $user, $role);}
sub GenResultsTable{my ($self, $db, $query, $clist, $slist, $jht, $jsa, $options) = @_; return $self->gen_results_table($db, "API_GenAddRecordForm",$query, $clist, $slist, $jht, $jsa, $options);}
sub ChangeUserRole{my ($self, $db, $user, $oldrole, $newrole) = @_;$self->change_user_role($db, $user, $oldrole, $newrole);}
sub ChangeRecordOwner{my($self, $db, $rid, $newowner); return $self->change_record_owner($db, $rid, $newowner)}
sub GetDBInfo{my ($self,$db) = @_;return $self->get_db_info($db);}
sub GetDBPage{my ($self, $db, $page_id, $page_name) = @_; return $self->get_db_page($db, $page_id, $page_name);}
sub GetDBvar{my($self,$db, $var) = @_;return $self->get_db_var($db,$var);}
sub GetNumRecords{my($self,$db) = @_;return $self->get_num_records($db);}
sub GetOneTimeTicket{my($self) = @_;return $self->get_one_time_ticket();}
sub GetRecordInfo{my($self, $db, $rid) = @_;return $self->get_record_info($db, $rid);}
sub GetRecord{my ($self, $db, $rid) = @_;return $self->get_record($db, $rid);}
sub GetRecordAsHTML{my($self, $db, $rid, $jht) = @_;return $self->get_record_as_html($db, $rid, $jht);}
sub GetRoleInfo{my ($self, $db) = @_; $self->post_api($db, "API_GetRoleInfo", {})->content;}
sub GetSchema{my ($self,$db) = @_; return $self->post_api($db, "API_GetSchema", {})->content;}
sub RemoveUserFromRole{my($self, $db, $userid, $roleid) = @_; return $self->remove_user_from_role($db, $userid, $roleid);}
sub ProvisionUser{my($self, $db, $email, $fname, $lname, $roleid) = @_; return $self->provision_user($db, $roleid, $email, $fname, $lname);}
sub RenameApp{my($self,$db,$newappname) = @_;return $self->rename_app($db, $newappname);}
sub SendInvitation{my($self, $db, $userid, $usertext) = @_;return $self->post_api($db, $userid, $usertext);}
sub SetDBvar{my ($self, $db, $varname, $value) = @_;return $self->set_db_var($db, $varname, $value);}
sub GetUserRole{my($self,$db,$userid) = @_;return $self->post_api($db, "API_GetUserRole", {userid=>$userid})->content;}
sub GrantedDBs{my($self) = @_; $self->post_api("main", "API_GrantedDBs", {})->content;}
sub GetUserInfo{my ($self,$user) = @_;return $self->get_user_info($user);}
sub UserRoles{my ($self,$db) = @_;return $self->post_api($db, "API_UserRoles", {})->content;}
sub getoneBaseIDbyName{my ($self, $db) = @_;return $self->find_db_by_name($db);}
sub getIDbyName{my ($self, $db) = @_;return $self->find_db_by_name($db);}
sub FindDBByName{my ($self, $db) = @_;return $self->find_db_by_name($db);}
sub cloneDatabase{my ($self, $db, $name, $desc, $keep_data, $exclude_files)=@_;return $self->clone_database($db, $name, $desc, $keep_data, $exclude_files);}
sub createDatabase ($$$){my ($self, $name, $desc, $create_apptoken)=@_; return $self->create_database($name, $desc, $create_apptoken);}
sub addField ($$$$){my ($self, $db, $label, $inp_type, $mode)=@_; return $self->add_field($db, $label, $inp_type, $mode);}
sub deleteField ($$){my ($self, $db, $fid)=@_;return $self->delete_field($db, $fid);}
sub setFieldProperties ($$%){my ($self, $db, $fid, %properties)=@_;return $self->set_field_properties($db, $fid, \%properties);}
sub purgeRecords ($$){my ($self, $db, $query)=@_;return $self->purge_records($db, $query);}
sub DoQuery{my ($self, $db, $query, $clist, $slist, $options, $fmt)=@_; return $self->do_query ($db, $query, $clist, $slist, $options, $fmt);}
sub doQuery{my ($self, $db, $query, $clist, $slist, $options, $fmt)=@_; return $self->do_query ($db, $query, $clist, $slist, $options, $fmt);}
sub setProxy{my($self, $proxy) = @_;return $self->proxy($proxy);}
sub getTicket{my ($self,$u,$p) = @_;return $self->get_ticket($u,$p);}
sub setRealmHost{my($self, $realmhost) = @_;return $self->realmhost($realmhost);}
sub getCompleteCSV{my ($self, $db)=@_;return $self->get_complete_csv($db);}
sub GetRIDs ($){my ($self, $db) = @_;return $self->get_rids($db)}
sub EditRecord ($$%){my ($self, $db, $rid, %recorddata) = @_;my @params;foreach my $name(keys %recorddata){$name =~ tr/A-Z/a-z/;$name =~ s/[^a-z0-9]/_/g;push(@params, {tag=>"field", atts=>{name=>"$name"}, value=>"$recorddata{$name}"});}return $self->edit_record($db, $rid, \@params)->content;}
sub EditRecordWithUpdateID ($$$%){my ($self, $db, $rid, $uid, %recorddata) = @_;my @params;foreach my $name(keys %recorddata){$name =~ tr/A-Z/a-z/;$name =~ s/[^a-z0-9]/_/g;push(@params, {tag=>"field", atts=>{name=>"$name"}, value=>"$recorddata{$name}"});}return $self->edit_record_with_update_id($db, $rid, $uid, \@params)->content;}
sub AddRecord{my($self, $db, %recorddata) = @_;my @params;foreach my $name(keys %recorddata){$name =~ tr/A-Z/a-z/;$name =~ s/[^a-z0-9]/_/g;push(@params, {tag=>"field", atts=>{name=>"$name"}, value=>"$recorddata{$name}"});}return $self->add_record($db, \@params);}
sub setAppToken{my ($self,$apptoken) = @_; return $self->apptoken($apptoken);}
sub AddReplaceDBPage{my($self,$db, $pageid, $pagename, $pagetype, $pagebody) = @_; return $self->add_replace_db_page($db, $pageid, $pagename, $pagetype, $pagebody);}
sub ImportFromCSV ($$$$){my ($self, $db, $data, $clist, $skip) = @_;return $self->import_from_csv($db, $data, $clist, $skip);}

1;

__END__

Run the command below in a command prompt to export POD documentation to HTML
perl -MPod::Html -e "pod2html('--infile=QuickBase.pm','--outfile=QuickBase.html')"

=pod

=for html 
<style type="text/css">
    a:link, a:visited, h1, h2{background:transparent; color:#1A75CF;}
    body{background: white;color: black;font-family: arial,sans-serif;margin: 0;padding: 1ex;}
    table{border-collapse: collapse;border-spacing: 0;border-width: 0;color: inherit;}
    img{border:0;}
    form{margin:0;}
    input{ margin:2px;}
    td{margin:0;padding: 0;}
    div{border-width: 0;}
    dt{margin-top: 1em;}
    th{background: #bbb;color: inherit;padding: 0.4ex 1ex;text-align: left;}
    th a:link, th a:visited{color: black;}
    pre{background: #eee;border: 1px solid #888;color: black;padding: 1em;white-space: pre;}
</style>
<h1 align="center">HTTP::QuickBase</h1>
<h2 align="center">Create a web shareable database in under a minute.</h2>
<h2 align="center">Version 2.0a</h2>

=head1 NAME

HTTP::QuickBase - Create a web shareable database in under a minute

=head1 SYNOPSIS

 use HTTP::QuickBase;
 $qdb = HTTP::QuickBase->new();
 
 # If you don't want to use HTTPS or your Perl installation doesn't support
 # HTTPS then make sure you have the "Allow non-SSL access (normally OFF)"
 # checkbox checked on your QuickBase database info page. You can get to this
 # page by going to the database "MAIN" page and then clicking on
 # "Administration" under "SHORTCUTS". Then click on "Basic Properties". To use
 # this module in non-SSL mode invoke the QuickBase object like this:
 
 # $qdb = HTTP::QuickBase->new('http://www.quickbase.com/db');
 
 $username = "fred";
 $password = "flinstone";
 
 $qdb->authenticate($username, $password);
 
 $database_name = "GuestBook Template";
 $database_id = "9mztyxu8";
 
 $clone_name = "My Guest Book";
 
 $database_clone_id = $qdb->clone_database($database_id, $clone_name, "Description of my new database.");
 
 
 # Let's put something into the new guest book
 $record_id = $qdb->add_record(
    $database_clone_id, 
    {
      "Name"             => "Fred Flinstone",
      "Daytime Phone"    => "978-533-2189", 
      "Evening Phone"    => "781-839-1555",
      "Email Address"    => "fred\@bedrock.com", 
      "Street Address 1" => "Rubble Court",
      "Street Address 2" => "Pre Historic Route 1",
      "City"             => "Bedrock",
      "State"            => "Stonia",
      "Zip Code"         => "99999-1234",
      "Comments"         => "Hanna Barbara, the king of Saturday morning cartoons.",
      
      # If you want to attach a file you need to create an array with the first 
      # member of the array set to the literal string "file" and the second 
      # member of the array set to the full path of the file.
      "Attached File"    => ["file", "c:\\my documents\\bedrock.txt"]
    }
 );
 
 # Let's get that information back out again
 %new_record=$qdb->get_record($database_clone_id, $record_id);
 # Now let's edit that record!
 $new_record{"Daytime Phone"} = "978-275-2189";
 $qdb->edit_record($database_clone_id, $record_id, \%new_record);
 
 # Let's print out all records in the database.
 
 @records = $qdb->do_query($database_clone_id, "{0.CT.''}");
 foreach $record (@records){
    foreach $field (keys %$record){
        print "$field -> $record->{$field}\n";
    }
 }
 
 # Let's save the entire database to a local comma separated values (CSV) file.
 
 open CSV, ">my_qdb_snapshot.csv";
 print CSV $qdb->get_complete_csv($database_clone_id);
 close CSV; 
 
 # Where field number 10 contains Wilma (the query)
 # let's print out fields 10, 11, 12 and 15 (the clist)
 # sorted by field 14 (the slist)
 # in descending order (the options)
 
 @records = $qdb->do_query($database_clone_id, "{10.CT.'Wilma'}", "10.11.12.15", "14", "sortorder-D");
 foreach $record (@records){
    foreach $field (keys %$record){
        print "$field -> $record->{$field}\n";
    }
 }
 
 # You can find out what you need in terms of the query, clist, slist and 
 # options by going to the View design page of your QuickBase database and 
 # filling in the form. Hit the "Display" button and look at the URL in the 
 # browser "Address" window. The View design page is accessible from any 
 # database home page by clicking on VIEWS at the top left and then clicking 
 # on "New View..." in the lower left.

=head1 REQUIRES

Perl5.005, LWP::UserAgent, Crypt::SSLeay (optional unless you want to talk to QuickBase via HTTPS)

=head1 SEE ALSO

https://www.quickbase.com/up/6mztyxu8/g/rc7/en/ for details of the underlying QuickBase HTTP API

=head1 EXPORTS

Nothing

=head1 DESCRIPTION

HTTP::QuickBase allows you to manipulate QuickBase databases.  
Methods are provided for cloning databases, adding records, editing records, deleting records and retrieving records.
All you need is a valid QuickBase account, although with anonymous access you can read from publically accessible QuickBase
databases. To learn more about QuickBase please visit http://www.quickbase.com/
This module supports a single object that retains login state. You call the authenticate method only once. 

=head1 METHODS

=for comment ######################### add_db_page #########################

=head2 add_db_page

A subroutine for adding a DB page.

B<Parameters>

=over

=item * QuickBase Database ID

The QuickBase Database ID of the application you wish to add the page to.

=item * Page Name

The name of the page you wish to add.

=item * Page Type

Should be 1 for XSL stylesheets or HTML pages, or 3 for Exact Forms.

=item * Page Body

The contents of the page you are adding.

=back

B<Example(s)>

=begin html

<PRE> my $pagename="newstylesheet.xsl";
 my $pagetype=1;
 my $pagebody&lt;&lt;XSLHTML;
 &lt;?xml version='1.0'?&gt;
 &lt;xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"&gt;
     &lt;xsl:template match="/"&gt;
         &lt;html&gt;
             &lt;head&gt;&lt;/head&gt;
             &lt;body&gt;
                 Hello World
             &lt;/body&gt;
         &lt;/html&gt;
     &lt;/xsl:template&gt;
 &lt;/xsl:stylesheet&gt;
 XSLHTML
 
 my $page_id=$qdb-&gt;add_db_page("bdcagynhs", $pagename, $pagetype, $pagebody);
 
 print $page_id; # 6</PRE>

=end html

B<See Also:> L</"add_replace_db_page">, L</"replace_db_page">

=for comment ######################### add_field #########################

=head2 add_field

Add a field to a QuickBase table.

B<Parameters>

=over

=item * QuickBase Database ID

The unique ID of the QuickBase table you wish to add the field to.

=item * Field Name/Label

The name of the new field.

=item * Field Type

The type of field you wish to add.  The eligible type names differ slightly 
from their QuickBase UI counterparts:

 QUICKBASE TYPE (UI)        API TYPE
 -------------------        ------------------------
 CheckBox                   checkbox
 Database Link              dblink
 Date                       date
 Duration                   duration
 Email Address              email
 File Attachment            file
 Formula                    see the "mode" parameter
 Lookup                     see the "mode" parameter
 Numeric                    float
 Numeric-Currency           currency
 Numeric-Rating             rating
 Phone Number               phone
 Text                       text
 Time of Day                timeofday
 URL-Link                   url

=item * [optional] Mode

If you want the field to be a formula specify "virtual".  This can be set for 
any field type (type can be set to any value).  If you want the field to be 
lookup specify "lookup" and set the Field Type to a text or numeric type.

=back

B<Example(s)>

 my $fid=$qdb->add_field("bddrqepes", "Phone Number", "phone");
 
 print $fid; # Prints 10

B<See Also:> L</"delete_field">

=for comment ######################### add_record #########################

=head2 add_record

Adds record to table

B<Parameters>

=over

=item * QuickBase Database ID

The QuickBase Database ID of the table you wish to add the record to.

=item * Record Data

An array reference containing the record data.  Each array item should contain a hash reference detailing the field information, like so:

 ARRAY:
 [
     # First field, referenced by field name
     {tag=>"field", atts=>{name=>"fieldname"}, value=>"fieldvalue"},
     # Second field, referenced by field ID
     {tag=>"field", atts=>{fid=>"22"}, value=>"otherfieldvalue"},
     # Third field, file attachment type, referenced by field ID
     {tag=>"field", atts=>{fid=>"30", filename=>"/path/to/myfile.jpg"}}
 ]

OR

A hash reference containing the record data:

 HASH:
 {
     # First field, referenced by field name
     "fieldname" => "fieldvalue",
     
     # Second field, referenced by field ID
     "22" => "otherfieldvalue",
     
     # Third field, file attachment type, referenced by field ID
     "30" => ["file", "/path/to/myfile.jpg"]
 }

=back

B<Returns>

The record ID of the record added.

B<Example(s)>

 my $rid = $qdb->add_record("bdcagynhs", {"FirstName"=>"John", "LastName"=>"Doe"});
 
 print $rid; # Prints 7

=for comment ######################### add_replace_db_page #########################

=head2 add_replace_db_page

A subroutine for adding or replacing a DB page.

B<Parameters>

=over

=item * QuickBase Database ID

The QuickBase Database ID of the application on which the page resides or will reside.

=item * Page ID OR Page Name

If you are adding a new page then you should pass the file name of the page 
here.  If you are editing an existing page then you should pass the page ID
here.

=item * Page Type

Should be 1 for XSL stylesheets or HTML pages, or 3 for Exact Forms.

=item * Page Body

The contents of the page.

=back

B<Returns>

The page ID of the page that was added or replaced.

B<Example(s)>

=begin html

<PRE> my $pagename="newstylesheet.xsl";
 my $pagetype=1;
 my $pagebody&lt;&lt;XSLHTML;
 &lt;?xml version='1.0'?&gt;
 &lt;xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"&gt;
     &lt;xsl:template match="/"&gt;
         &lt;html&gt;
             &lt;head&gt;&lt;/head&gt;
             &lt;body&gt;
                 Hello World
             &lt;/body&gt;
         &lt;/html&gt;
     &lt;/xsl:template&gt;
 &lt;/xsl:stylesheet&gt;
 XSLHTML
 
 my $page_id=$qdb-&gt;add_replace_db_page("bdb5rjd6h", $pagename, $pagetype, $pagebody);
 
 print $page_id; # Prints 6
 
 # Replaces new page with empty file
 my $edited_page_id=$qdb-&gt;add_replace_db_page("bdcagynhs", $page_id, $pagetype, "");
 
 print $edited_page_id; # Prints 6</PRE>

=end html

B<See Also:> L</"add_db_page">, L</"replace_db_page">

=for comment ######################### add_user_to_role #########################

=head2 add_user_to_role

Access to your application is governed by the roles in effect for your 
application.  Users can access your application only if you assign them to one 
(or more) of these roles.  You assign a user to a role using this call.  A 
common use of this call is to set up a second call, L</"send_invitation">, 
where you let the user know that the user can access the application.

If you want a user to have several roles, you can invoke this on the same user 
several times, each time specifying a different role.

Although an application can use the standard default roles (viewer, participant, 
administrator), each application can have its own set of roles, with the access 
and permissions per role set up as needed by that particular application.  You 
can find out what the roles are for the current application by calling 
L</"get_role_info">.

In order to make this call, you have to have administrator-level access in the 
application.

See also L</"provision_user"> for an alternate way to assign roles to users.

B<Parameters>

=over

=item * QuickBase Database ID

The application-level dbid of the application for which the role will be assigned.

=item * User ID

The QuickBase userid of the user that will be added to the role.

=item * Role ID

The role id of the access role the user is being added to.

=back

B<Returns>

True/False value for success/failure.

B<Example(s)>

 print "Success!" if $qdb->add_user_to_role("6mpjiez8", "112245.efy7", 10);

B<See Also:> L</"provision_user">, L</"send_invitation">, L</"get_role_info">

=for comment ######################### apptoken #########################

=head2 apptoken

Provides access to the apptoken property

B<Parameters>

=over

=item * [optional] Apptoken 

The apptoken for subsequent calls

=back

B<Example(s)>

 # Prints the current apptoken
 print $qdb->apptoken();
 
 # Assigns "b8qtx9rsf9gd..." to the apptoken property
 $qdb->apptoken("b8qtx9rsf9gd...");

=for comment ######################### authenticate #########################

=head2 authenticate

Initiates an authentication process, sending the     
username and password and retrieving a unique        
ticket identifier.  Ticket retrieved will be stored  
in QuickBase instance and automatically inserted into
subsequent API calls.                                

B<Parameters>

=over 

=item * Username

The username of the QuickBase user.

=item * Password

The password of the QuickBase user

=back

B<Example(s)>

 # Authenticates the current $qdb object with QuickBase 
 # using the username/password my-username/my-password
 $qdb->authenticate("my-username","my-password");

=for comment ######################### change_record_owner #########################

=head2 change_record_owner

The record owner, by default, is the user who created it.  QuickBase can use 
record ownership to restrict access.  Normally, this is done through roles, 
where a role can be set up to restrict view and/or modify access to the record 
owner.

In order to call this method, you must have administrator rights to the 
application.

B<Parameters>

=over 

=item * QuickBase Database ID

Table-level dbid of the table containing the record you wish to transfer 
ownership of.

=item * Record ID

The ID of the record you wish to transfer ownership of.

=item * New Owner

The screen name or email address of the new owner.

=back

B<Returns>

True/False value for success/failure.

B<Example(s)>

 print "Record owner changed" if $qdb->change_record_owner("bdb5rjd6h", 3, "Muggsy");

=for comment ######################### change_user_role #########################

=head2 change_user_role

This call allows you to assign a user to a different role.

B<Parameters>

=over 

=item * QuickBase Database ID

The ID of the QuickBase application in which the user's role will change.

=item * User ID

The user ID of the user you wish to change the role of.

=item * Current Role ID

The current role ID of the user.

=item * [optional] New Role ID

The role ID of the role you wish to change the user to.  If no ID is specified 
for this parameter then the new role will be "None".

=back

B<Returns>

True/False value for success/failure.

B<Example(s)>

 $qdb->change_user_role("bdb5rjd6h", "112248.5nzg", "11", ""); # Changes role from 11 to "None"

=for comment ######################### clone_database #########################

=head2 clone_database

Clone a QuickBase Application, including the schema, views, and users.  
Optionally, the data can be cloned as well, and if so the file attachments can 
be optionally included or excluded.

B<Parameters>

=over 

=item * QuickBase Database ID

The unique ID of the QuickBase application you wish to copy.

=item * Database Name

The name of the new database.

=item * Description

The description of the new database.

=item * Keep Data

Set to 1 to clone the data as well as the structure.

=item * Exclude Files

Set to 1 to exclude file attachments from the clone process.

=back

B<Returns>

The DB ID of the new database.

B<Example(s)>

 # Clone bdb5rjd6h, calling the clone "New Database" with the description 
 # "My cloned database".  Keep the data and the file attachments.
 my $newdbid = $qdb->clone_database("bdb5rjd6h","New Database","My cloned database",1,0);
 
 print $newdbid; # Prints bddnc6pn7

=for comment ######################### create_database #########################

=head2 create_database

Creates a new QuickBase application with the main application table 
populated only with the built-in fields and optionally generates and 
returns an apptoken for API use.

B<Parameters>

=over 

=item * Application Name

The name of your new application

=item * Application Description

The description of your new application.

=item * [optional] Create Apptoken

Set to 1 to create an apptoken for the new application.

=back

B<Returns>

Returns a hash object containing the new application-level dbid of the new 
application and the apptoken if one was created:

 {
   appdbid=>"bddnn3uz8",
   dbid=>"bddnn3uz9",
   apptoken=>"cmzaaz3dgdmmwwksdb7zcd7a9wg"
 }

B<Example(s)>

 # Create a new application named Fuel Charter with the description Vehicle 
 # and Fuel Cost Tracker.
 # Also create an apptoken for the new application.
 my %newapp = $qdb->create_database("Fuel Charter", "Vehicle and Fuel Cost Tracker", 1);
 
 print $newapp{'dbid'}; # Prints bddnn3uz9
 
 print $newapp{'apptoken'}; # Prints cmzaaz3dgdmmwwksdb7zcd7a9wg

=for comment ######################### create_table #########################

=head2 create_table

Creates a QuickBase table.

B<Parameters>

=over

=item * Parent Application ID

The application in which the table will be created.

=item * Table Name

The name of the table

=item * Table Pronoun

The pronoun that describes the items stored in the table

=back

B<Returns>

The new table's database identifier.

B<Example(s)>

 my $newdbid = $qdb->create_table("bddrqepes", "Project Management", "Projects");
 print $newdbid; # bdb5rjd6h

=for comment ######################### delete_database #########################

=head2 delete_database

If you have application administration rights you can use this call to delete 
either a child table or the entire application, depending on the dbid you 
supply.

B<Parameters>

=over 

=item * QuickBase Database ID

The Application or Table ID of the database you wish to delete.

=back

B<Returns>

True/False value for success/failure.

B<Example(s)>

 print "Application deleted!" if $qdb->delete_database("6mpjiez8");

=for comment ######################### delete_field #########################

=head2 delete_field

If you have application administration rights you can use  this call to delete 
a table field by specifying the field id.  You have to use a table-level dbid, 
otherwise you will get an Error 31: No such field.

B<Parameters>

=over 

=item * QuickBase Database ID

The unique ID of the QuickBase table you wish to delete the field from.

=item * Field ID

The field ID of the field you wish to delete.

=back

B<Returns>

True/False value for success/failure.

B<Example(s)>

 print "Field deleted!" if $qdb->delete_field("6mpjiez8", 8);

=for comment ######################### delete_record #########################

=head2 delete_record

If you have application administration rights you can use this call to delete 
a table record.  You have to use a table-level dbid, otherwise you will get an 
error.  If you want to delete several records at one time, you might want to 
use L</"purge_records">.

B<Parameters>

=over 

=item * QuickBase Database ID

The unique ID of the QuickBase table you wish to delete the record from.

=item * Record ID

The record ID of the record you wish to delete.

=back

B<Returns>

True/False value for success/failure.

B<Example(s)>

 print "Record deleted!" if $qdb->delete_record("bddnc2idi", 18);

=for comment ######################### do_query #########################

=head2 do_query

You invoke this on a table dbid to get records from the table.  You can use 
this to get all the records and fields, but typically you would want to get 
only some of the records and only those fields you want, ordered and sorted 
the way you want them to be.

=for html
<p>More information on queries can be found in the <a target="_blank"
href="http://member.developer.intuit.com/MyIDN/technical_resources/quickbase/framework/httpapiref/HTML_API_Programmers_Guide.htm">
QuickBase HTTP API Programmer's Guide</a> under "Building and Using Queries".</p>

B<Parameters>

=over 

=item * QuickBase Database ID

The table-level dbid of the QuickBase database you wish to query.

=item * [optional] Query/Query ID/Query Name

This parameter can be an ad hoc custom query or the ID or name of a query 
currently saved in the QuickBase application.

If the parameter is blank all records will be returned.

=item * [optional] Column List

A period-delimited list of field IDs to be returned.  The order you list these 
in is the order in which they'll be returned.  Alternatively, you can specify 
the value "C<a>" to get all the columns.

If the parameter is blank the table's default columns will be returned.

=item * [optional] Sort List

A period delimited list of field IDs for sorting.

=item * [optional] Options

A period-delimited list of options.

 OPTION         EFFECT
 -----------    -----------------------------------------------------------
 num-n          return a maximum of n records.
 onlynew        return only those records marked with new or updated flags.
 skp-n          skip the first n records returned by the query.
 sortorder-A    sort ascending
 sortorder-D    sort descending

C<sortorder->I<x> options work with the Sort List.  If one sortorder is 
specified it will use the first column in the Sort List, the second will
use the second column, etc.

=item * [optional] Format

Specify "C<structured>" to get additional table, field, and application information.

Specify a value other than C<structured> to retrieve minimal information.  
"C<unstructured>" is recommended in these cases.

Default if left blank is C<structured>.

=back

B<Returns>

The value returned by do_query depends on the value expected and the type of format specified.

For either format, if the subroutine is called in array context then an array of records will be returned.

Otherwise, the subroutine will return a hash with the following structure:

 {
     action=>"API_DoQuery",
     errcode=>0,
     errtext=>"No error",
     qid=>0,
     qname=>'',
     name=>"My Table",
     desc=>"My table description",
     table_id=>"bdb5rjd6g",
     cre_date=>1204586581894,
     mod_date=>1206583187767,
     next_record_id=>34
     next_field_id=>24
     next_query_id=>5
     def_sort_fid=>6
     def_sort_order=>1
     lastluserid=>0,
     
     # fields only available via "structured" format
     fields=>{
         by_id=>{
             "5"=>{
                 id=>5,
                 field_type=>"userid",
                 base_type=>"int32",
                 role=>"modifier",
                 mode=>"",
                 label=>"Last Modified By",
                 nowrap=>1,
                 bold=>0,
                 required=>0,
                 appears_by_default=>0,
                 find_enabled=>1,
                 allow_new_choices=>1,
                 sort_as_given=>0,
                 carrychoices=>1,
                 foreignkey=>0,
                 unique=>0,
                 doesdatacopy=>0,
                 fieldhelp=>"",
                 display_user=>"fullnamelf",
                 default_kind=>none,
                 num_lines=>0,
                 append_only=>0,
                 allowHTML=>0,
                 has_extension=>0,
                 max_versions=>"",
                 see_versions=>"",
                 use_new_window=>"",
                 comma_start=>"",
                 does_average=>"",
                 does_total=>"",
                 blank_is_zero=>""
             },
             "6"=>{
                 id=>6,
                 field_type=>"phone",
                 base_type=>"text",
                 role=>"",
                 mode=>"",
                 label=>"Business Phone Number",
                 nowrap=>0,
                 bold=>0,
                 required=>1,
                 appears_by_default=>1,
                 find_enabled=>1,
                 allow_new_choices=>0,
                 sort_as_given=>0,
                 carrychoices=>0,
                 foreignkey=>0,
                 unique=>1,
                 doesdatacopy=>0,
                 fieldhelp=>"This is the phone number",
                 display_user=>"",
                 default_kind=>"",
                 num_lines=>1,
                 append_only=>0,
                 allowHTML=>0,
                 has_extension=>1,
                 max_versions=>"",
                 see_versions=>"",
                 use_new_window=>"",
                 comma_start=>"",
                 does_average=>"",
                 does_total=>"",
                 blank_is_zero=>""
             }
         },
         by_label=>{
             "Last Modified By"=>{
                 # Repeat of structure found in fields->by_id->5
             },
             "Phone Number"=>{
                 # Repeat of structure found in fields->by_id->6
             }
         }
     },
     
     # queries only available via "structured" format
     queries=>{
         by_id=>{
             "1"=>{
                 qyname=>"List All",
                 qytype=>"table",
                 qycrit=>"",
                 qyopts=>"",
                 qycalst=>"0.0",
                 qyclst=>"",
                 qydesc=>"",
                 qyslst=>"",
                 qyform=>"",
                 qyflbl=>"",
                 qyftyp=>""
             },
             "2"=>{
                 qyname=>"List Changes",
                 qytype=>"table",
                 qycrit=>"",
                 qyopts=>"so-D.onlynew.",
                 qycalst=>"0.0",
                 qyclst=>"",
                 qydesc=>"Sorted by Date Modified",
                 qyslst=>"2",
                 qyform=>"",
                 qyflbl=>"",
                 qyftyp=>""
             }
         },
         by_name=>{
             "List All"=>{
                 # Repeat of structure found in queries->by_id->1
             },
             "List Changes"=>{
                 # Repeat of structure found in queries->by_id->2
             }
         }
     },
     
     # users only available via "structured" format
     users=>{
         "112149.bhsv"=>"AppBoss"
     },
     
     # if the subroutine is called in array context then only this array will return
     records=>[
         
         # Structured format
         {
             "5"=>"112149.bhsv",
             "Last Modified By"=>"112149.bhsv",
             
             "6"=>"(123) 333-4321 x34566",
             "Business Phone Number"=>"(123) 333-4321 x34566"
         },
         
         # Unstructured format
         {
             last_modified_by=>"AppBoss",
             business_phone_number=>"(123) 333-4321 x34566"
         },
         
         {
             # etc...
         }
     ]
 }

B<Example(s)>

 # Place the request
 my %results = $qdb->do_query(
     "bdb5rjd6h",         # Table to query
     "{'6'.SW.'(123)'}",  # Search for phone numbers that start with (123)
     "5.6",               # Columns to return
     "5",                 # Columns to sort by
     "sortorder-A",       # Sort ascending
     "structured"         # Request structured results
 );
 
 # Loop through the records of the results
 foreach my $record(@{$results->{'records'}}){
     
     # Retrieve the Contact username of the current record by looking up the
     # user id in the results->users hash
     my $user = $results->{'users'}{$record->{'Contact'}};
     
     # Prints "Ragnar: (123) 333-4321 x34566"
     print "$user: " . $record->{'Business Phone Number'} . "\n";
 }
 
 # Alternative method using array context
 # Using query ID 6 and defaults for other params
 foreach my $record($qdb->do_query("bdb5rjd6h","6")){
     print $results->{'users'}{$record->{'Contact'}} . ": " . $record->{'Business Phone Number'} . "\n";
 }

=for comment ######################### edit_record #########################

=head2 edit_record

You can use this to change any of the editable field values in the specified 
record.  Only those fields specified are changed, unspecified fields are left 
unchanged.

B<Parameters>

=over 

=item * QuickBase Database ID

The QuickBase dbid of the table in which the record resides.

=item * Record ID

The record ID of the record you want to edit.

=item * Fields/Values

A hash or array reference of field name/value pairs for editing.  e.g. 
C<{"email"=E<gt>"cucamonga@chuck.com"}> or C<[{"name"=E<gt>"email", "value"=E<gt>"cucamonga@chuck.com"}]>

The hash reference will assume that hash keys are field names if they do not 
match the regex C<m/^\d+$/>.  Otherwise they will be assumed to be field IDs.

=back

B<Returns>

A hash reference containing the number of fields changed, the update ID, and 
the full content of the server response in the following format:

 {
     num_fields_changed=>5,
     update_id=>1205700275470,
     content=>'<?xml version="1.0" ?>\n<qdbapi>\n\t...'
 }

B<Example(s)>

 # Update record 25 in table bdb5rjd6h and change the email field to "cucamonga@chuck.com"
 my %results=$qdb->edit_record("bdb5rjd6h","25",{"email"=>"cucamonga@chuck.com"});
 
 # Prints "1205700275470 1"
 print $results->{'update_id'} . " " . $results->{'num_fields_changed'} . "\n";

B<See Also:> L</"edit_record_with_update_id">

=for comment ######################### edit_record_with_update_id #########################

=head2 edit_record_with_update_id

Like L</"edit_record">, you can use this to change any of the editable field 
values in the specified record.  Unlike L</"edit_record">, the update will only
be successful if the update_id provided is valid.  This is to prevent potential 
collisions with multiple people editing the same record.

As before, only those fields specified are changed,  unspecified fields are 
left unchanged.

B<Parameters>

=over 

=item * QuickBase Database ID

The QuickBase dbid of the table in which the record resides.

=item * Record ID

The record ID of the record you want to edit.

=item * Update ID

The current Update ID of the record you want to edit.

=item * Fields/Values

A hash or array reference of field name/value pairs for editing.  e.g. 
C<{"email"=E<gt>"cucamonga@chuck.com"}> or C<[{"name"=E<gt>"email", "value"=E<gt>"cucamonga@chuck.com"}]>

The hash reference will assume that hash keys are field names if they do not 
match the regex C<m/^\d+$/>.  Otherwise they will be assumed to be field IDs.

=back

B<Returns>

If unsuccessful, a False value.

If successful, a hash reference containing the number of fields changed, the update ID, and 
the full content of the server response in the following format:

 {
     num_fields_changed=>3,
     update_id=>992017018414,
     content=>'<?xml version="1.0" ?>\n<qdbapi>\n\t...'
 }

B<Example(s)>

 # Update record 25 in table bdb5rjd6h and change the email field to "cucamonga@chuck.com"
 my %results=$qdb->edit_record("bdb5rjd6h","25",1205700275470,{"email"=>"cucamonga@chuck.com"});
 
 # Prints "992017018414 1"
 print $results->{'update_id'} . " " . $results->{'num_fields_changed'} . "\n";

B<See Also:> L</"edit_record">

=for comment ######################### error #########################

=head2 error

A method for accessing the current error code.

B<Parameters>

=over 

=item * [optional] Error Code

If present, will set the error code to the provided value.

=back

B<Returns>

The current error code.

B<Example(s)>

 print $qdb->error; # Prints "0"
 
 $qdb->create_database("Fuel Charter", "Vehicle and Fuel Cost Tracker", 1);
 
 print $qdb->error; # Prints "74" (You are not allowed to create applications)

=for comment ######################### errortext #########################

=head2 errortext

A method for accessing the current error text.

B<Parameters>

=over 

=item * [optional] Error Text

If present, will set the error text to the provided value.

=back

B<Returns>

The current error text.

B<Example(s)>

 print $qdb->errortext; # Prints ""
 
 $qdb->create_database("Fuel Charter", "Vehicle and Fuel Cost Tracker", 1);
 
 print $qdb->errortext; # Prints "You are not allowed to create applications"

=for comment ######################### field_add_choices #########################

=head2 field_add_choices

If you have administrative rights you can add new choices to any field through 
this method.  If you don't have administrative rights you can only invoke this 
method if the multiple-choice field properties are set to allow new choices to 
be added.

If the choice you add already exists in the multiple choice list, the choice 
will not be added (no duplicates).

B<Parameters>

=over 

=item * QuickBase Database ID

The QuickBase dbid of the table the field resides in.

=item * Field ID

The field ID of the field you wish to add choices to.

=item * Choices

An array reference of choices to be added, e.g. C<["Choice 1","Choice 2","etc..."]>

=back

B<Returns>

The number of choices that were added to the field.

B<Example(s)>

 my $num_added = $qdb->field_add_choices("bdb5rjd6h", 25, ["Choice 1","Choice 2"]);
 
 print $num_added; # Prints "2"

B<See Also:> L</"field_remove_choices">

=for comment ######################### field_remove_choices #########################

=head2 field_remove_choices

If you have administrative rights you can remove choices from any field through 
this method.  If you don't have administrative rights you can only invoke this 
method if the choice was created by you.

B<Parameters>

=over 

=item * QuickBase Database ID

The QuickBase dbid of the table the field resides in.

=item * Field ID

The field ID of the field you wish to remove choices from.

=item * Choices

An array reference of choices to be removed, e.g. C<["Choice 1","Choice 2","etc..."]>

=back

B<Returns>

The number of choices that were removed from the field.

B<Example(s)>

 my $num_removed = $qdb->field_remove_choices("bdb5rjd6h", 25, ["Choice 1","Choice 2"]);
 
 print $num_removed; # Prints "2"

B<See Also:> L</"field_add_choices">

=for comment ######################### find_db_by_name #########################

=head2 find_db_by_name

This method can be used to get the application-level dbid of an application 
whose name you know.  Only those applications that have granted you access 
rights will be searched.

Because there can exist multiple applications with the same name, you should 
be aware that more than one application dbid can be returned.

B<Parameters>

=over 

=item * Database Name

The name of the database you want to search for.

=back

B<Returns>

An array of dbids for databases matching the name you searched for.

B<Example(s)>

 my @dbids = $qdb->find_db_by_name("My Application");
 
 print $dbids[0]; # Prints "bdcagynhs"

=for comment ######################### gen_add_record_form #########################

=head2 gen_add_record_form

This method returns the standard QuickBase new record add page (in HTML) for 
the table whose dbid you specify.  It contains edit fields for the user to fill 
and a save button to add the record to the database.

If you want to pre-fill any fields you can do so by supplying one or more 
field/value pairs in the request.  Any fields not pre-filled or filled in by 
the user will get the default values set in the table field properties.

B<Parameters>

=over 

=item * QuickBase Database ID

The table-level dbid of the table you want to generate the form for.

=item * [optional] Field/Value List

A hash reference of field/value pairs for default values, e.g. 
C<{"email"=E<gt>"cucamonga@chuck.com", "phone"=E<gt>"(123) 456-7890"}>

=back

B<Returns>

Returns an HTML page containing the record add page with any pre-filled values.

B<Example(s)>

 my $html = $qdb->gen_add_record_form("bddrqepes", {"email"=>"cucamonga@chuck.com", "phone"=>"(123) 456-7890"});
 
 print $html; # Prints the html page

=for comment ######################### gen_results_table #########################

=head2 gen_results_table

This method is typically used in its URL form in an HTML page to embed the 
results as HTML, but it can also return results as a JavaScript array, in CSV 
format, or as tab separated values.

The SDK does not yet parse the results of any of these formats, and simply 
returns the raw response.

B<Parameters (A)>

=over 

=item * QuickBase Database ID

The QuickBase table-level dbid against which the query will be executed.

=item * [optional] Query

This parameter can be an ad hoc custom query or the ID or name of a query 
currently saved in the QuickBase application.

If the parameter is blank all records will be returned.

=item * [optional] Column List

A period-delimited list of field IDs to be returned.  The order you list these 
in is the order in which they'll be returned.  Alternatively, you can specify 
the value "C<a>" to get all the columns.

If the parameter is blank the table's default columns will be returned.

=item * [optional] Sort List

A period delimited list of field IDs for sorting.

=item * [optional] Format: HTML

Leave this parameter blank if you do not wish to receive HTML formatted results.

Set to 1 to use the CSS styles that render the HTML table with the QuickBase look and feel prior to April 11, 2003.

Set to n to use the CSS styles that render the HTML table with the QuickBase look and feel introduced on April 11, 2003.

=item * [optional] Format: JavaScript Array

Set to 1 if you wish to receive JavaScript Array formatted results, otherwise leave blank.

=item * [optional] Options

A period-delimited list of options.

 OPTION         EFFECT
 -----------    -----------------------------------------------------------
 num-n          return a maximum of n records.
 onlynew        return only those records marked with new or updated flags.
 skp-n          skip the first n records returned by the query.
 sortorder-A    sort ascending
 sortorder-D    sort descending
 ned            omit the edit icons in HTML table format
 nvw            omit the view icons in HTML table format
 nfg            omit the new and updated icons in HTML table format
 phd            plain (non-hyperlinked) headers
 abs            absolute URLs
 csv            comma-separated value output format
 tsv            tab-separated value output format

C<sortorder->I<x> options work with the Sort List.  If one sortorder is 
specified it will use the first column in the Sort List, the second will
use the second column, etc.

=back

B<Parameters (B)>

Because of the number of parameters this method accepts, it will also accept 
an alternative style wherein the 2nd through 7th parameters can be combined 
into a single hash reference.  This aids readability and cuts down on
unnecessary empty parameters.

=over

=item * QuickBase Database ID

The QuickBase table-level dbid against which the query will be executed.

=item * Options Hash

A hash object reference containing the options you wish to set in the following 
format:

 {
     query=>"",
     clist=>"",
     slist=>"",
     jht=>"",
     jsa=>"",
     options=>""
 }

=back

B<Returns>

Currently returns the raw response contents from the API call.

B<Example(s)>

 my $results = $qdb->gen_results_table("bddrqepes",{query=>"{'0'.CT.''}",options=>'csv'});
 
 print $results; # Prints "one,two,three,etc."

=for comment ######################### get_complete_csv #########################

=head2 get_complete_csv

Performs a L</"gen_results_table"> call, specifying all columns and all records 
and the CSV format.

B<Parameters>

=over 

=item * QuickBase Database ID

The QuickBase dbid of the database you want the CSV of.

=back

B<Returns>

CSV text.

B<Example(s)>

 my $csv = $qdb->get_complete_csv("bdcagynhs");

=for comment ######################### get_db_info #########################

=head2 get_db_info

You can invoke this on the application-level dbid or the table dbid to get 
metadata information, such as the last time the table was modified.  For 
example, you might use this function to find out if the table has changed since 
you last used it, or to find out if a new record has been added to the table.

B<Parameters>

=over 

=item * QuickBase Database ID

QuickBase application- or table-level dbid.

=back

B<Returns>

Returns a hash of the following format:

 {
   dbname=>"Test DB",
   version=>"1.42",
   lastRecModTime=>1205806751959,
   lastModifiedTime=>1205877093679,
   createdTime=>1204745351407,
   numRecords=>3,
   mgrID=>112149.bhsv,
   mgrName=>AppBoss
 }

B<Example(s)>

 my %dbinfo = $qdb->get_db_info("bddrqepes");
 
 print $dbinfo{'dbname'}; # Prints "Test DB"

=for comment ######################### get_db_page #########################

=head2 get_db_page

QuickBase allows you to store various types of pages, ranging from user-guide 
pages for your application to Exact Forms which are used to automate insertion 
of data into Word documents using a special Word template from QuickBase.  This 
call lets you retrieve one of those pages in HTML.

B<Parameters>

=over 

=item * QuickBase Database ID

The QuickBase dbid of the application in which the page is stored.

=item * Page ID or Page Name

The ID or name of the page you want to retrieve.

=back

B<Returns>

The requested page is returned in HTML.

B<Example(s)>

 my $page = $qdb->get_db_page("bdb5rjd6h", 6);
 
 print $page; # Prints "<html><head>..."

=for comment ######################### get_db_var #########################

=head2 get_db_var

DBVars are variables you can create and set values in at the application level, 
using the application-level dbid.  This lets you get the values from these 
DBVars.

B<Parameters>

=over 

=item * QuickBase Database ID

The application-level dbid of the application the variable is stored in.

=item * Variable Name

The name of the variable whose value you wish to retrieve.

=back

B<Returns>

The value of the DBVar requested.

B<Example(s)>

 my $color = $qdb->get_db_var("bddrqepes", "MyColor");
 
 print $color; # Prints "blue"

=for comment ######################### get_file #########################

=head2 get_file

Retrieves a file from QuickBase for given a table, record, and field.

B<Parameters>

=over 

=item * QuickBase Database ID

Table-level dbid containing the file.

=item * Record ID

The record ID containing the file.

=item * Field ID

The field ID of the file.

=item * [optional] Version

The version number of the file.  Omitting this parameter, or using 0, will 
return the most recent version.

=back

B<Returns>

An array containing the file as the first element and the HTTP::Response 
headers as the second element.

B<Example(s)>

 my ($file) = $qdb->get_file("bdcagynhs", 78, 13);
 
 print "$file"; # Prints retrieved file's contents

=for comment ######################### get_num_records #########################

=head2 get_num_records

Returns the number of records in the table.

B<Parameters>

=over 

=item * QuickBase Database ID

The table-level dbid of the table you wish to query.

=back

B<Returns>

The number of records in the table.

B<Example(s)>

 my $num_records = $qdb->get_num_records("bdb5rjd6h");
 
 print $num_records; # Prints 17

=for comment ######################### get_one_time_ticket #########################

=head2 get_one_time_ticket

Returns a single-use ticket that expires after five minutes.  After use, the 
ticket is no longer valid.

Intended for use with API_UploadFile, which is necessary only in environments 
that do not have access to the local filesystem.

B<Parameters>

I<None.>

B<Returns>

A single-use ticket.

B<Example(s)>

 print $qdb->get_one_time_ticket(); # Prints "5_besfdf9uc..."

=for comment ######################### get_record #########################

=head2 get_record

You invoke this on a table-level dbid to get all of the fields in a record.

B<Parameters>

=over 

=item * QuickBase Database ID

The table-level dbid of the QuickBase table the record is in.

=item * Record ID

The Record ID of the record you wish to retrieve.

=back

B<Returns>

Returns a hash of the following format:

 {
     rid=>20,
     num_fields=>28,
     update_id=>1205780029699,
     user=>{
         fid=>6,
         name=>"user",
         type=>"User",
         value=>"Lodbrok"
     },
     f_6=>{
         # reference to same hash as user
     },
     "file attachment"=>{
         fid=>7,
         name=>"file attachment",
         type=>"File Attachment",
         value=>"BatchID.html"
     },
     f_7=>{
         # reference to same hash as file attachment
     }
 }

B<Example(s)>

 my %record = $qdb->get_record("bdb5rjd6h", 20);
 
 print $record{'file attachment'}{'value'}; # Prints "BatchID.html"

=for comment ######################### get_record_as_html #########################

=head2 get_record_as_html

You invoke this call on a table-level dbid to return a record as an HTML 
fragment that can be embedded in another HTML page.

Most frequently this method will be called via the GET method in a URL.

B<Parameters>

=over 

=item * QuickBase Database ID

QuickBase table-level database ID of the table containing the record

=item * Record ID

The Record ID (or rid) of the record you wish to retrieve

=item * [optional] Format

Set to 1 to return the information in Javascript format.  The javascript will 
contain a function called qdbWrite which, when called, will output the HTML 
via document.write commands.

Omit this parameter for plain HTML format.

=back

B<Returns>

A string containing either a Javascript or an HTML representation of the record.

B<Example(s)>

 my $html = $qdb->get_record_as_html("bdb5rjd6h", 27);
 
 # Prints HTML output, including css style information, links to javascript 
 # files on QuickBase's server, and the table containing the record.
 print $html; 

=for comment ######################### get_record_info #########################

=head2 get_record_info

Invoking this call on a table-level dbid will return all the fields of a 
record, similar to L</"do_query"> with all fields specified.

B<Parameters>

=over 

=item * QuickBase Database ID

Table-level QuickBase database ID in which the record resides

=item * Record ID

The Record ID (or rid) of the record

=back

B<Returns>

Currently returns unprocessed XML response.

B<Example(s)>

 my $xml = $qdb->get_record_info("bdcagynhs", 27);
 
 print $xml;
 
 ###################################################
 
 Prints:
 <?xml version="1.0" ?>
 <qdbapi>
 <action>API_GetRecordInfo</action>
 <errcode>0</errcode>
 <errtext>No error</errtext>
 <rid>20</rid>
 <num_fields>28</num_fields>
 <update_id>1205780029699</update_id>
 
 <field>
 <fid>6</fid>
 <name>user</name>
 <type>User</type>
 <value>Lodbrok</value>
 <printable>Boneless, Ivar</printable>
 </field>
 <field>
 <fid>7</fid>
 <name>file attachment</name>
 <type>File Attachment</type>
 <value>BatchID.html</value>
 </field>
 .
 .
 .
 </qbdapi>

=for comment ######################### get_rids #########################

=head2 get_rids

Used to retrieve a list of record IDs in a table.

B<Parameters>

=over 

=item * QuickBase Database ID

Table-level QuickBase database ID

=back

B<Returns>

Array of record IDs.

B<Example(s)>

 my @rids = $qdb->get_rids("bdb5rjd6h");
 
 print join(", ", @rids);
 
 # Prints: 1, 2, 3, 4, etc.

=for comment ######################### get_role_info #########################

=head2 get_role_info

Use this method to get all of the roles that apply to an application.

Each application can have its own set or foles that govern user access to that 
application.  To find out what roles are available in an application, you can 
invoke this method to return all of the roles and their information (name, ID, 
application access level).

The access level returned is one of these available access types:

=over

=item * Basic Access (able to view/modify/add records, depending on permissions)

=item * Basic Access with Share (same as Basic, but can share application with others)

=item * Administrator (full administrative access)

=back

B<Parameters>

=over 

=item * QuickBase Database ID

Application-level QuickBase database ID

=back

B<Returns>

An array of roles in the following format:

 [
     {
         id        => 10,
         name      => "Viewer",
         access_id => 3,
         access    => "Basic Access"
     },
     {
         id        => 11,
         name      => "Participant",
         access_id => 3,
         access    => "Basic Access"
     },
     {
         id        => 12,
         name      => "App Admin",
         access_id => 1,
         access    => "Administrator"
     }
 ]

B<Example(s)>

 # Retrieve the array of roles
 my @roles = $qdb->get_role_info("bddrqepes");
 
 # Print a list of role names and their access level
 foreach my $role (@roles){
     print $role{"name"}.": ".$role{"access"}."\n";
 }

=for comment ######################### get_schema #########################

=head2 get_schema

If you invoke this method on an application-level dbid it will return 
information about the application, such as any DBVars created for it and all 
child table dbids available.

If you invoke this method on a table-level dbid the DBVars are also listed, but 
there will additionally be table-related information such as queries, field IDs 
(fids), and the current property settings for each field.

B<Parameters>

=over 

=item * QuickBase Database ID

An application-level or table-level QuickBase database ID.

=back

B<Returns>

A detailed hash object containing the application or table schema in the 
following format:

 {
     "name"           => "My Application/Table",
     "desc"           => "My application/table description",
     "table_id"       => "bdb5rjd6h", # dbid, field name same for applications and tables
     "cre_date"       => 1204586581894,
     "mod_date"       => 1206394201119,
     "next_record_id" => 1,
     "next_field_id"  => 1,
     "next_query_id"  => 7,
     "def_sort_fid"   => 5,
     "def_sort_order" => 6,
     "variables" => {
         "Blue" => 14,
         "Jack" => 14,
         "Magenta" => 12,
         "usercode" => 14
     },
     
     # Available only in application-level dbids
     "chdbids" => {
         "_dbid_sample_database" => "bdb5rjd6g",
         "_dbid_pronouns" => "bddrydqhg"
     },
     
     # Available only in table-level dbids
     "queries" => {
         "by_id" => {
             "1" => {
                 "id"      => 1,
                 "qyname"  => "List All",
                 "qytype"  => "table",
                 "qycalst" => 0.0
             }
         },
         "by_name" => {
             "List All" => {
                 "id"      => 1,
                 "qyname"  => "List All",
                 "qytype"  => "table",
                 "qycalst" => 0.0
             }
         }
     }
 }

B<Example(s)>

 # Example code goes here

=for comment ######################### get_ticket #########################

=head2 get_ticket

Returns a new authentication ticket from QuickBase.

B<Parameters>

=over

=item * [optional] Username

The username of the QuickBase user.

=item * [optional] Password

The password of the QuickBase user.

=back

B<Example(s)>

 # Prints a new authentication ticket
 print $qdb->get_ticket("my-username","my-password");

=for comment ######################### get_user_info #########################

=head2 get_user_info

You invoke this method to get the user name and userid associated with the 
specified email address (used for QuickBase login).  This call is useful in 
the contet of granting a user access rights to your application and then 
inviting that user to your application.  This call is typically made to return 
the QuickBase userid for a user whose email address you know, in preparation 
for subsequent calls to L</"add_user_to_role"> (grant access rights) and 
L</"send_invitation">, both of which require the userid.

The user email you specify must be recognized in QuickBase or this call won't 
work.  For users not registered with QuickBase use the alternative 
L</"provision_user">.

If the email parameter is not supplied the ticket will be used to determine 
the user, and information for the currently authenticated user will be 
returned.

B<Parameters>

=over 

=item * [optional] Email

Email address of the registered QuickBase user for whom you wish to retrieve 
information.  If omitted, the currently authenticated user's information will 
be returned.

=back

B<Returns>

A hash object of the following format:

 {
     "id"         => "112149.bhsv",
     "firstName"  => "Ragnar",
     "lastName"   => "Lodbrok",
     "login"      => "Ragnar",
     "email"      => "rlodbrok@paris.net",
     "screenName" => "Ragnar"
 }

B<Example(s)>

 my %user_info = $qdb->get_user_info("rlodbrok@paris.net");
 
 print $user_info{'id'}; # Prints "112149.bhsv"

=for comment ######################### get_user_roles #########################

=head2 get_user_roles

You invoke this method on an application-level dbid to find out what roles are 
currently assigned to a specific user in an application.

In contrast, the similar L</"user_roles"> casts a bigger net, getting all users and 
their roles for the specified application.

B<Parameters>

=over 

=item * QuickBase Database ID

Application-level dbid for which the specified user's roles will be retrieved.

=item * User ID

The user id of the user whose roles will be retrieved.

=back

B<Returns>

A hash object of the following format:

 {
     "id"    => "112245.efy7",
     "name"  => "Ivar Boneless",
     "roles" => [
         {
             "id" => 10,
             "name" => "Viewer",
             "access_id" => 3,
             "access" => "Basic Access"
         },
         # etc...
     ]
 }

B<Example(s)>

 my %user_roles = $qdb->get_user_roles("57pa5vjf","112245.efy7");
 
 while my $role (@{$user_roles{'roles'}}){
     
     # Prints "Viewer: Basic Access"
     print $role->{'name'}.": ".$role->{'access'}."\n";
 }

=for comment ######################### granted_dbs #########################

=head2 granted_dbs

You invoke this method to get the names and dbids of all the applications and 
tables that you are able to access.  Optionally, you can choose to retrieve 
parent applications, child tables, or both, or restrict the list to only those 
applications and tables to which you have administrative rights.

B<Parameters>

=over 

=item * [optional] Include Applications

Set this parameter to 1 to include applications in the response.

=item * [optional] Include Tables

Set this parameter to 1 to include tables in the response.

=item * [optional] Filter for Administrative Rights

Set this parameter to 1 to only show the applications and/or tables for which 
administrative rights have been granted.

=back

Note: Omitting all parameters will return an empty array in all cases.

B<Returns>

An array of the following format:

 [
     {
         "dbname" => "Misc_Comments",
         "dbid"   => "bdadur4ak",
     },
     {
         "dbname" => "Misc_Comments: Comment",
         "dbid"   => "bdadur4am"
     },
     {
         "dbname" => "Misc_Comments: Rating",
         "dbid"   => "bdbs8ms3g"
     },
     {
         "dbname" => "Misc_Comments: Emails",
         "dbid"   => "bdbtbrxed"
     },
     {
         "dbname" => "API Created Sample",
         "dbid"   => "bdb5rjd6g"
     }
 ]

B<Example(s)>

 my @databases = $qdb->granted_dbs(1,1);
 
 foreach my $db(@databases){
     print "$db->{'dbname'}: $db->{'dbid'}\n"; # Prints "Misc_Comments: bdadur4ak", etc.
 }

=for comment ######################### import_from_csv #########################

=head2 import_from_csv

You invoke this method on a table-level dbid to add or update a batch of 
records.  You can even do adds and edits together in the same import_from_csv 
call.  (For an add, leave the RecordID empty -- that's how QuickBase knows it's 
an add.)

In comparison, L</"add_record"> and L</"edit_record"> will only let you add or edit one 
record at a time.  There is one limitation, though: you can't use this call to 
modify file attachment fields.

The clist parameter is optional when adding new records to a table.  However, 
when updating existing records, you must specify the clist parameter. QuickBase 
uses this parameter to determine whether new records to a table or existing 
records are being updated.

For an edit operation, the clist parameter must contain the field ID for the 
Record ID# field.  Also, the CSV must include a column that contains a record 
id for each record that you are updating.

B<Parameters>

=over 

=item * QuickBase Database ID

The QuickBase table-level dbid of the table you wish to update or add to.

=item * CSV Data

The comma-separated input data.

=item * [optional] Column List (clist)

A period delimited list of field IDs to which the CSV columns map.  This means 
that the first field ID in the list maps to the first column in the CSV file, 
the second ID maps to the second column in the CSV file, and so forth.

To prevent a column in the CSV file from being imported, enter a 0 in the field list.

Examples:

 In the following examples, the CSV file contains 4 columns
 
 "0.7.0.6"
 In this example, QuickBase will not import either the first or the third 
 columns in the CSV file.
 
 "7.8.5"
 In this example the field ID of 7 is mapped to the first column in the CSV 
 file, the field with a field ID of 8 is mapped to the second column, and 
 the field id of 5 is mapped to the third column.  Since the clist parameter 
 does not include a fourth field ID, the fourth column in the CSV file is 
 ignored.

=item * [optional] Skip First

This parameter prevents QuickBase from importing the first row of data in a CSV 
file.  You must set this parameter to 1 if the first row of your CSV contains 
column names.

=back

B<Returns>

Currently returns unprocessed XML.

B<Example(s)>

 my $xml_response = $qdb->import_from_csv("bddrqepes", "First Name,Last Name,Phone Number,Email,...", "5.6.10.11", 1);

=for comment ######################### post_api #########################

=head2 post_api

A (mostly) private method for direct communication with the QuickBase API.  The 
post_api method will take a parameter list and convert it into the requisite 
XML for a request, including the authentication and header information 
automatically.  It returns an HTTP::Response object, after checking its 
contents for error information  which is stored in the L</"error"> and 
L</"errortext"> properties if found.

B<Parameters>

=over 

=item * QuickBase Database ID

A QuickBase application- or table-level dbid.  ("main" should be used for API 
calls which do not require a database.)

=item * QuickBase Action

The name of the QuickBase API to be invoked. Typically begins in API_xxxx.

=item * API Parameters

A hash or array list of parameters to be sent to QuickBase.

=item * [optional] Headers

A hash list of headers to send to QuickBase.  Basic headers such as 
Content-Type and QUICKBASE-ACTION are set automatically.

=back

B<Returns>

An HTTP::Response object containing the response from QuickBase.

B<Example(s)>

 my $response = $qdb->post_api("bddrqepes", "API_GetDBvar", {"varname"=>"usercode"});
 
 print $response->content;
 
 # Prints:
 <?xml version="1.0" ?>
 <qdbapi>
    <action>API_getDBvar</action>
    <errcode>0</errcode>
    <errtext>No error</errtext>
    <value>12</value>
 </qdbapi>

=for comment ######################### provision_user #########################

=head2 provision_user

This method is invoked on an application-level dbid for a user that is not yet 
registered with QuickBase, but whose email is known to you.  This call will:

=over

=item * Start a new user registration in QuickBase using the supplied email, 
first name, and last name.

=item * Give application access to the user by adding the user to the specified
role.

=back

After you invoke this method, you'll need to invoke L</"send_invitation"> to invite 
the new user via email.  When the user clicks on the link in the email 
invitation, the user is prompted to complete the brief registration.  At this 
time, the user can change the first and last name you assigned.

If a user is already registered with QuickBase, you can't use this call.  
Instead, to do these same tasks you'll have to use L</"get_user_info">, 
L</"add_user_to_role">, and L</"send_invitation">.

B<Parameters>

=over 

=item * QuickBase Database ID

The application-level dbid of the QuickBase application you wish to grant the 
user access to.

=item * Email

The email address of the person to whom you are granting access.

=item * First Name

The first name of the new QuickBase user.

=item * Last Name

The last name of the new QuickBase user.

=item * [optional] Role ID

The role ID of the role you want to assign the user to.  If you don't supply a 
role, the role will be set to 'none'.  This can be found via L</"get_role_info">.

=back

B<Returns>

The userid of the newly created user.

B<Example(s)>

 my $new_userid = $qdb->provision_user("bdcagynhs", "sanskor@sbcglobal.com", "Margi", "Rita" 10);
 
 print $new_userid; # Prints "112248.5nzg"

=for comment ######################### proxy #########################

=head2 proxy

Gets and sets the proxy for LWP::UserAgent to use when making API calls.

B<Parameters>

=over 

=item * [optional] Proxy Address

The address for the proxy server to use.

=back

B<Returns>

The current proxy address.

B<Example(s)>

=begin html

<PRE> print $qdb->proxy(); # Prints ""
 
 $qdb->proxy("http://myproxy.com:8080");
 
 print $qdb->proxy(); #Prints "http://myproxy.com:8080"</PRE>

=end html

=for comment ######################### purge_records #########################

=head2 purge_records

=for html <strong style="color:red">CAUTION: Use this method carefully!</strong>

The purge_records method is used to delete several records at once, and has the 
potential to completely wipe out a table if the query parameter is omitted or 
empty.

You invoke this call on the table-level dbid of the table you want to delete 
the records from.  If you only need to delete one record, L</"delete_record"> 
would be a better choice.

All records matching your query criteria will be deleted.

B<Parameters>

=over 

=item * QuickBase Database ID

The table-level dbid of the table in which the records reside.

=item * Query (or Query Identifier)

This parameter will accept one of three input types:

=over

=item * Query Name

The name (qname) of the pre-built query you wish to execute.

=item * Query ID

The ID (qid) of the pre-built query you wish to execute.

=item * Query String

The custom query built using the language specified at 
http://member.developer.intuit.com/MyIDN/technical_resources/quickbase/framework/httpapiref/HTML_API_Programmers_Guide.htm
under Building and Using Queries.

=back

=back

B<Returns>

The number of records deleted.

B<Example(s)>

 my $num_deleted = $qdb->purge_records("bddrqepes", "{'7'.CT.'Company B'}");
 
 print "$num_deleted record(s) deleted.";

=for comment ######################### realmhost #########################

=head2 realmhost

Gets and sets the realmhost to use when accessing QuickBase.

B<Parameters>

=over 

=item * [optional] Realmhost

The realmhost to use.

=back

B<Returns>

The current realmhost.

B<Example(s)>

=begin html

<PRE> print $qdb->realmhost(); # Prints ""
 
 $qdb->realmhost("http://mycompany.quickbase.com");
 
 print $qdb->realmhost(); # Prints "http://mycompany.quickbase.com"</PRE>

=end html

=for comment ######################### remove_user_from_role #########################

=head2 remove_user_from_role

You invoke this method on an application-level dbid to remove the user entirely 
from the specified role in that application.  Keep in mind that if the user has 
no other role, it eliminates the user entirely from the application's role list.  
This means that calling L</"user_roles"> won't return the user at all, so 
you'll need to get the userid by calling L</"get_user_info"> if you want to 
assign the user to another role in the future.

This method can be used to remove the user entirely from any role in the 
application, effectively turning off access to that user.  If you intend to 
turn off all access, you would need to call L</"get_user_roles"> to see what 
roles the user has, then invoke L</"remove_user_from_role"> on each role.

If you expect to add that user to another role in the future, you should 
consider using L</"change_user_role">, which can be used to turn off access 
with a role set to None while keeping the user on the application's role list 
for future reinstatement or role change.

If you are simply changing the user from one role to another, you should use 
L</"change_user_role">.

B<Parameters>

=over 

=item * QuickBase Database ID

Application-level dbid of the application containing the role you want to 
remove the user from.

=item * User ID

The user you want removed from the role.

=item * Role ID

The ID of the role you want the user removed from.

=back

B<Returns>

True/False value for success/failure.

B<Example(s)>

 print "Success!" if $qdb->remove_user_from_role("bdb5rjd6h", "112245.efy7", 11);

=for comment ######################### rename_app #########################

=head2 rename_app

You invoke this method on an application-level dbid to change the application 
name.  No dbids, fids, or anything other than the application name is affected.  
You must have administrator rights to call this.

B<Parameters>

=over 

=item * QuickBase Database ID

Application-level QuickBase dbid.

=item * New Application Name

The name you want to change the application to.

=back

B<Returns>

True/False value for success/failure.

B<Example(s)>

 print "Application renamed" if $qdb->rename_app("bddrqepes", "My New Application Name");

=for comment ######################### replace_db_page #########################

=head2 replace_db_page

A subroutine for replacing a DB page.  See L</"add_replace_db_page"> for more information.

B<See Also:> L</"add_replace_db_page">, L</"add_db_page">

=for comment ######################### send_invitation #########################

=head2 send_invitation

You invoke this method to send an email invitation for your application.  The 
userid is either from an existing QuickBase user that you have granted access 
to via L</"add_user_to_role">, or from a new QuickBase user that you have 
created via L</"provision_user">.

B<Parameters>

=over 

=item * QuickBase Database ID

Application-level dbid of the application you want to invite the user to.

=item * User ID

The ID of the user you want to invite to the application.

=item * [optional] Message

The message you want to display in your email invitation.

=back

B<Returns>

True/False value for success/failure.

B<Example(s)>

 print "Invitation sent" if $qdb->send_invitation("bdb5rjd6h","112249.ctdg","Welcome to my app!");

=for comment ######################### set_db_var #########################

=head2 set_db_var

If you have administrator rights in an aplication, you can invoke this method 
to create a DBVar variable and/or set a value for it.  If the DBVar already 
exists, this call will overwrite the existing value.  You can only invoke this 
call on one DBVar at a time.

DBVars can only be set at the application level, so you must specify an 
application-level dbid.

B<Parameters>

=over 

=item * QuickBase Database ID

Application-level dbid in which the DBVar will be created or modified.

=item * DBVar Variable Name

The name of the DBVar you wish to modify or create.

=item * DBVar Value

The value you want to set the DBVar to.

=back

B<Returns>

True/False value for success/failure.

B<Example(s)>

 print "Value changed" if $qdb->set_db_var("bddrqepes", "Day Number", 353);

=for comment ######################### set_field_properties #########################

=head2 set_field_properties

You invoke this method on a table-level dbid to set one or more properties of a 
field.  Normally, you use this call after you create a new field using 
L</"add_field">, to set up its default behavior, however you can also use this 
call any time you want to change properties, even if the affected field has 
data.

The properties available for a field vary slightly for different field types.  
To get all of the available properties for a field, and to get the field id 
(fid) needed, use the L</"get_schema"> method.

B<Parameters>

=over 

=item * QuickBase Database ID

Table-level dbid containing the field you wish to modify.

=item * Field ID

The field ID of the field to modify.

=item * Properties

A hash reference containing a list of properties and values to change.  For a 
complete list of field properties, see the link below.

http://member.developer.intuit.com/MyIDN/technical_resources/quickbase/framework/httpapiref/QBaseSDK_/04_API_LangRef/04_API_LangRef-168.htm

=back

B<Returns>

True/False value for success/failure.

B<Example(s)>

 my $success = $qdb=>set_field_properties("bddrqepes", 15, {"default_value" => "Hello"});
 
 print "Default value changed" if $success;

=for comment ######################### user_roles #########################

=head2 user_roles

You invoke this method to find out details about an application's users and 
their roles.  You have to use the application-level dbid; a table-level dbid 
returns an error.

This method returns all users and their roles.  In contrast, 
L</"get_user_role"> gets only the roles for a specified user.

You can invoke this method if you have basic access rights or higher.

B<Parameters>

=over 

=item * QuickBase Database ID

Application-level dbid you want to retrieve the users/roles for.

=back

B<Returns>

An array of the following format:

 (
     {
         "id"    => "112149.bhsv",
         "name"  => "Jack Danielsson",
         "roles" => [
             {
                 "id"        => 12,
                 "name"      => "Administrator",
                 "access"    => "Administrator",
                 "access_id" => 1
             }
             # etc.
         ]
     }
     # etc.
 )

B<Example(s)>

 my @user_roles = $qdb->user_roles("bddrqepes");
 
 my $num_users = $#user_roles;
 
 foreach my $user (@user_roles){
     print "User ID: $user->{'id'}\n";
     print "User Name: $user->{'name'}\n";
     print "Roles:\n";
     foreach my $role (@{$user->{'roles'}}){
         print "  Role ID: $role->{'id'}\n"
         print "  Role Name: $role->{'name'}\n"
         print "  Role Access: $role->{'access'}\n"
         print "  Role Access ID: $role->{'access_id'}\n\n"
     }
     print "\n";
 }

=for comment 
###############################################################################
#                                                                             #
#                                 DEPRECATED                                  #
#                                                                             #
###############################################################################

=head1 DEPRECATED

These methods are no longer preferred.  They will be phased out in future 
versions of the SDK.

=head2 addField

See L</"add_field">

=head2 AddRecord

See L</"add_record">

=head2 AddReplaceDBPage

See L</"add_replace_db_page">

=head2 AddUserToRole

See L</"add_user_to_role">

=head2 ChangeRecordOwner

See L</"change_record_owner">

=head2 ChangeUserRole

See L</"change_user_role">

=head2 cloneDatabase

See L</"clone_database">

=head2 createDatabase

See L</"create_database">

=head2 CreateTable

See L</"create_table">

=head2 DeleteDatabase

See L</"delete_database">

=head2 deleteField

See L</"delete_field">

=head2 DeleteRecord

See L</"delete_record">

=head2 doQuery

See L</"do_query">

=head2 DoQuery

See L</"do_query">

=head2 EditRecord

See L</"edit_record">

=head2 EditRecordWithUpdateID

See L</"edit_record_with_update_id">

=head2 FieldAddChoices

See L</"field_add_choices">

=head2 FieldRemoveChoices

See L</"field_remove_choices">

=head2 FindDBByName

See L</"find_db_by_name">

=head2 GenAddRecordForm

See L</"gen_add_record_form">

=head2 GenResultsTable

See L</"gen_results_table">

=head2 getCompleteCSV

See L</"get_complete_csv">

=head2 GetDBInfo

See L</"get_db_info">

=head2 GetDBPage

See L</"get_db_page">

=head2 GetDBvar

See L</"get_db_var">

=head2 GetFile

See L</"get_file">

=head2 getIDbyName

See L</"find_db_by_name">

=head2 GetNumRecords

See L</"get_num_records">

=head2 getoneBaseIDbyName

See L</"find_db_by_name">

=head2 GetOneTimeTicket

See L</"get_one_time_ticket">

=head2 GetRecord

See L</"get_record">

=head2 GetRecordAsHTML

See L</"get_record_as_html">

=head2 GetRecordInfo

See L</"get_record_info">

=head2 GetRIDs

See L</"get_rids">

=head2 GetRoleInfo

See L</"get_role_info">

=head2 GetSchema

See L</"get_schema">

=head2 getTicket

See L</"get_ticket">

=head2 GetURL

=head2 GetUserInfo

See L</"get_user_info">

=head2 GetUserRole

See L</"get_user_roles">

=head2 GrantedDBs

See L</"granted_dbs">

=head2 ImportFromCSV

See L</"import_from_csv">

=head2 PostAPIURL

See L</"post_api">

=head2 PostURL

=head2 ProvisionUser

See L</"provision_user">

=head2 purgeRecords

See L</"purge_records">

=head2 RemoveUserFromRole

See L</"remove_user_from_role">

=head2 RenameApp

See L</"rename_app">

=head2 SendInvitation

See L</"send_invitation">

=head2 setAppToken

See L</"apptoken">

=head2 SetDBvar

See L</"set_db_var">

=head2 setFieldProperties

See L</"set_field_properties">

=head2 setProxy

See L</"proxy">

=head2 setRealmhost

See L</"realmhost">

=head2 UserRoles

See L</"user_roles">

=cut