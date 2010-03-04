#!/usr/bin/perl -w
 
use strict;
use warnings;
use Config::General;
use Switch;

# Configuration
# TODO: Accept command line argument
my $conf_file = './pb-route.conf';
my $verbose = 1;

# Runtime variables
my $IPT;	# Path to 'iptables' binary
my $IP2;	# Path to iproute2 'ip' binary
my $PRINT_ONLY = 1;	# True = Print to Screen; False = Do rules

# Read the config file (or die)
my %config; # The hash where the config will be stored once read
{
	my $conf;				# The conf object to read config files
	my %confHash;				# Hash storing details of the config to read
	unless ( -e $conf_file ) {
		&bomb(sprintf('Config file "%s" not found!', $conf_file));
	}

	$confHash{-ConfigFile} = $conf_file;	# Path to the conf file
	$confHash{-LowerCaseNames} = 1;		# Fold keys lowercase
	$conf = new Config::General(%confHash);	# Create the config reading object
	%config = $conf->getall;		# Read the config into the hash

	$IPT = defined($config{iptables}) ? $config{iptables} : '/sbin/iptables';
	$IP2 = defined($config{ip}) ? $config{ip} : '/sbin/ip';
}

&setup_route_tables;

&ipt_flush;

&initialize_mangle;

# Setup Policies
my @dests;
@dests = ref($config{destination}) eq 'ARRAY' ? @{$config{destination}} : ($config{destination});
foreach (@dests) {
	my($dest_address, $gw) = split(' ', $_);
	next unless ($dest_address =~ /^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/[0-9]{1,2})$/);
	$dest_address = $1;
	&ipt("-t mangle -A PREROUTING -m state --state NEW -d $dest_address -m comment --comment '$dest_address via connection $gw' -j M10$gw");
	&ipt("-t mangle -A PREROUTING -m state --state NEW -d $dest_address -m comment --comment '$dest_address via connection $gw' -j ACCEPT");
	&ipt("-t mangle -A OUTPUT -m state --state NEW -d $dest_address -m comment --comment '$dest_address via connection $gw' -j M10$gw");
	&ipt("-t mangle -A OUTPUT -m state --state NEW -d $dest_address -m comment --comment '$dest_address via connection $gw' -j ACCEPT");
}
my @ports;
@ports = ref($config{port}) eq 'ARRAY' ? @{$config{port}} : ($config{port});
foreach (@ports) {
	my($dest_port, $gw) = split(' ', $_);
	next unless ($dest_port =~ /^([0-9]+)$/);
	$dest_port = $1;
	&ipt("-t mangle -A PREROUTING -m state --state NEW -p tcp --dport $dest_port -m comment --comment 'tcp $dest_port via connection $gw' -j M10$gw");
	&ipt("-t mangle -A PREROUTING -m state --state NEW -p tcp --dport $dest_port -m comment --comment 'tcp $dest_port via connection $gw' -j ACCEPT");
	&ipt("-t mangle -A PREROUTING -m state --state NEW -p udp --dport $dest_port -m comment --comment 'udp $dest_port via connection $gw' -j M10$gw");
	&ipt("-t mangle -A PREROUTING -m state --state NEW -p udp --dport $dest_port -m comment --comment 'udp $dest_port via connection $gw' -j ACCEPT");
	&ipt("-t mangle -A OUTPUT -m state --state NEW -p tcp --dport $dest_port -m comment --comment 'tcp $dest_port via connection $gw' -j M10$gw");
	&ipt("-t mangle -A OUTPUT -m state --state NEW -p tcp --dport $dest_port -m comment --comment 'tcp $dest_port via connection $gw' -j ACCEPT");
	&ipt("-t mangle -A OUTPUT -m state --state NEW -p udp --dport $dest_port -m comment --comment 'udp $dest_port via connection $gw' -j M10$gw");
	&ipt("-t mangle -A OUTPUT -m state --state NEW -p udp --dport $dest_port -m comment --comment 'udp $dest_port via connection $gw' -j ACCEPT");
}
my @protos;
@protos = ref($config{proto}) eq 'ARRAY' ? @{$config{proto}} : ($config{proto});
foreach (@protos) {
	my($protocol, $gw) = split(' ', $_);
	next unless ($protocol =~ /^(tcp|udp|icmp|gre)$/);
	$protocol = $1;
	&ipt("-t mangle -A PREROUTING -m state --state NEW -p $protocol -m comment --comment '$protocol via connection $gw' -j M10$gw");
	&ipt("-t mangle -A PREROUTING -m state --state NEW -p $protocol -m comment --comment '$protocol via connection $gw' -j ACCEPT");
	&ipt("-t mangle -A OUTPUT -m state --state NEW -p $protocol -m comment --comment '$protocol via connection $gw' -j M10$gw");
	&ipt("-t mangle -A OUTPUT -m state --state NEW -p $protocol -m comment --comment '$protocol via connection $gw' -j ACCEPT");
}
	
switch ($config{default}) {
	case "balanced" {
		# Default balance between connections
		&ipt("-t mangle -A PREROUTING -p tcp -m state –state ESTABLISHED,RELATED -m comment --comment 'default balancing' -j CONNMARK –restore-mark");
		&ipt("-t mangle -A PREROUTING -p udp -m state –state ESTABLISHED,RELATED -m comment --comment 'default balancing' -j CONNMARK –restore-mark");
		&ipt("-t mangle -A PREROUTING -m mark --mark 0 -p tcp -m state –state NEW -m statistic –mode nth –every 2 –packet 0 -m comment --comment 'default balancing' -j M101");
		&ipt("-t mangle -A PREROUTING -m mark --mark 0 -p tcp -m state –state NEW -m statistic –mode nth –every 2 –packet 0 -m comment --comment 'default balancing' -j ACCEPT");
		&ipt("-t mangle -A PREROUTING -m mark --mark 0 -p tcp -m state –state NEW -m statistic –mode nth –every 2 –packet 1 -m comment --comment 'default balancing' -j M102");
		&ipt("-t mangle -A PREROUTING -m mark --mark 0 -p tcp -m state –state NEW -m statistic –mode nth –every 2 –packet 1 -m comment --comment 'default balancing' -j ACCEPT");
		&ipt("-t mangle -A PREROUTING -m mark --mark 0 -p udp -m state –state NEW -m statistic –mode nth –every 2 –packet 0 -m comment --comment 'default balancing' -j M101");
		&ipt("-t mangle -A PREROUTING -m mark --mark 0 -p udp -m state –state NEW -m statistic –mode nth –every 2 –packet 0 -m comment --comment 'default balancing' -j ACCEPT");
		&ipt("-t mangle -A PREROUTING -m mark --mark 0 -p udp -m state –state NEW -m statistic –mode nth –every 2 –packet 1 -m comment --comment 'default balancing' -j M102");
		&ipt("-t mangle -A PREROUTING -m mark --mark 0 -p udp -m state –state NEW -m statistic –mode nth –every 2 –packet 1 -m comment --comment 'default balancing' -j ACCEPT");
	}
	case /[0-9]/ {
		# Default via a specific connection
		&ipt("-t mangle -A PREROUTING -p tcp -m state –state ESTABLISHED,RELATED -m comment --comment 'default via connection $config{default}' -j CONNMARK –restore-mark");
		&ipt("-t mangle -A PREROUTING -p udp -m state –state ESTABLISHED,RELATED -m comment --comment 'default via connection $config{default}' -j CONNMARK –restore-mark");
		&ipt("-t mangle -A PREROUTING -m mark --mark 0 -p tcp -m state –state NEW -m comment --comment 'default via connection $config{default}' -j M10$config{default}");
		&ipt("-t mangle -A PREROUTING -m mark --mark 0 -p tcp -m state –state NEW -m comment --comment 'default via connection $config{default}' -j ACCEPT");
	}
}


&setup_snat;

# Flush the route cache to make it pickup new route tables
&ip2('route flush cache');

###############################################################################
### SUBROUTINES
###############################################################################

sub bomb {
	# Bomb out for some reason
	my($err) = @_;
	printf ("BOMBED OUT: %s\n", $err);
	exit 1;
}

sub setup_route_tables {
	my @routes = map { chomp; $_ } grep { !/^default/ } `/sbin/ip route list table main`;

	# Routing Table for packets directed out Connection 1
	&ip2('route flush table 1 2>/dev/null');
	&ip2('rule del fwmark 101 table 1 2>/dev/null');
	foreach (@routes) {
	        &ip2('route add table 1 '.&trim($_).' 2>/dev/null');
	}
	&ip2("route add table 1 default via $config{gw1ip}");
	&ip2('rule add fwmark 101 table 1');

	# Routing Table for packets directed out Connection 2
	&ip2('route flush table 2 2>/dev/null');
	&ip2('rule del fwmark 102 table 2 2>/dev/null');
	foreach (@routes) {
	        &ip2('route add table 2 '.&trim($_).' 2>/dev/null');
	}
	&ip2("route add table 2 default via $config{gw2ip}");
	&ip2('rule add fwmark 102 table 2');
}

sub ipt_flush {
	# Flush all iptables rules
	&ipt('-F');
	&ipt('-X');
	&ipt('-t nat -F');
	&ipt('-t nat -X');
	&ipt('-t filter -F');
	&ipt('-t filter -X');
	&ipt('-t mangle -F');
	&ipt('-t mangle -X');
	return undef;
}

sub initialize_mangle {
	&ipt('-t mangle -A PREROUTING -j CONNMARK --restore-mark');
	&ipt('-t mangle -A PREROUTING -m comment --comment "this stream is already marked; escape early" -m mark ! --mark 0 -j ACCEPT');
	# This marks any NEW incoming connections with the connection
	# they came in via so replies go back the same way.
	&ipt("-t mangle -A PREROUTING -i $config{if1} -m mac --mac-source $config{gw1mac} -m state --state NEW -j M101");
	&ipt("-t mangle -A PREROUTING -i $config{if2} -m mac --mac-source $config{gw2mac} -m state --state NEW -j M102");
}

sub setup_mark_chains {
	&ipt('-t mangle -N M101');
	&ipt('-t mangle -A M101 -j MARK –set-mark 101');
	&ipt('-t mangle -A M101 -j CONNMARK –save-mark');
	&ipt('-t mangle -N M102');
	&ipt('-t mangle -A M102 -j MARK –set-mark 102');
	&ipt('-t mangle -A M102 -j CONNMARK –save-mark');
}

sub setup_snat {
	foreach (split(' ', $config{snat})) {
		next unless (/^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/[0-9]{1,2})$/);
		my $snat_source = $1;
		&ipt("-t nat -A POSTROUTING -o $config{if1} -s $snat_source -m mark --mark 101 -j SNAT –to-source $config{ip1}");
		&ipt("-t nat -A POSTROUTING -o $config{if2} -s $snat_source -m mark --mark 102 -j SNAT –to-source $config{ip2}");
	}
}

sub ip2 {
	# Do an iproute2 command
	$PRINT_ONLY = 1 ? printf("%s %s\n", $IP2, @_) : system(sprintf('%s %s', $IP2, @_));
}
sub ipt {
	# Do an iptables command
	$PRINT_ONLY = 1 ? printf("%s %s\n", $IPT, @_) : system(sprintf('%s %s', $IPT, @_));
}

sub trim($) {
	my $string = shift;
	$string =~ s/\s{2,}/ /;	# Multiple Spaces
	$string =~ s/^\s//;	# Leading Spaces
	$string =~ s/\s$//;	# Trailing Spaces
	return $string;
}
