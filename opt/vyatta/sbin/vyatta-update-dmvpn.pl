#!/usr/bin/perl

# **** License ****
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# This code was originally developed by Adam Asay with INVITE Networks
#
# **** End License ****

use strict;
use lib "/opt/vyatta/share/perl5";
use IO::Handle;
use Getopt::Long;
use Vyatta::Config;
use Test::More;
use Data::Dumper;

my $commitTunnel;
my $commitIPSec;

GetOptions(
    'tunnel=s' => \$commitTunnel,
    'ipsec' => \$commitIPSec,
);

my $exitCode = 0;
my $indent = '  ';
my $config = new Vyatta::Config;
my $baseNHRP = 'protocols nhrp';
my $baseIPSec= 'vpn ipsec';
my $nhrpConfig = '/etc/opennhrp/opennhrp.conf';
my $racoonConfig = '/etc/racoon/racoon.conf';
my $preSharedKeyConfig = '/etc/racoon/psk.txt';
my ($nhrpEnable, $nhrpChanges, $ipsecChanges, $ipsecEnable, $nhrpRestart); # Flags to mark if deamons need changes

sub getNodes {
    my $level = shift;
    my $getOrig = shift;

    $config->setLevel($level);

    if ($getOrig) {
        return $config->listOrigNodes();
    }

    return $config->listNodes();
}

sub getValue {
    my $level = shift;
    my $getOrig = shift;

    $config->setLevel($level);

    if ($getOrig) {
        return $config->returnOrigValue();
    }

    return $config->returnValue();
}

sub getExists {
    my $level = shift;
    my $getOrig = shift;

    $config->setLevel($level);

    if ($getOrig) {
        return $config->existsOrig();
    }

    return $config->exists();
}

sub isChanged {
    my $level = shift;

    $config->setLevel($level);

    return $config->isChanged();
}

sub getIPSecConfig {
    foreach my $profile (getNodes("$baseIPSec profile")) {
        if (getExists("$baseIPSec profile $profile bind")) {
            my %ipsecConfig = getIPSecProfileConfig($profile);

            if (keys %ipsecConfig > 0) {
                $ipsecEnable = 1;
                getNHRPTunnels();

                my %ipsecOrigConfig = getIPSecProfileConfig($profile, 1);

                if (! eq_hash(\%ipsecConfig, \%ipsecOrigConfig)) {
                    buildIPSecConfig(%ipsecConfig);
                }
            }
        }
    } 
}

sub getIPSecProfileConfig {
    my $profile = shift;
    my $getOrig = shift;
    my %ipsecConfig;

    my @nodes = getNodes("$baseIPSec profile $profile");

    $ipsecConfig{'nat-traversal'} = getValue("vpn ipsec nat-traversal", $getOrig);
    $ipsecConfig{'log'} = getValue("vpn ipsec logging log-level", $getOrig);

    foreach my $node (@nodes) {
        if ($node eq 'authentication') {
            my $authentication = getValue("$baseIPSec profile $profile $node mode", $getOrig);

            if ($authentication eq 'pre-shared-secret') {
                $ipsecConfig{'authentication'} = 'pre_shared_key';
                $ipsecConfig{'key'} = getValue("$baseIPSec profile $profile $node pre-shared-secret", $getOrig);
            }

        } elsif ($node eq 'ike-group') {
            my $ikeGroup = getValue("$baseIPSec profile $profile $node", $getOrig);

            if ($ikeGroup) {
                %{$ipsecConfig{'ike'}} = getIPSecGroupConfig($ikeGroup, 'ike', $getOrig);
            }
        } elsif ($node eq 'esp-group') {
            my $espGroup = getValue("$baseIPSec profile $profile $node", $getOrig);

            if ($espGroup) {
                %{$ipsecConfig{'esp'}} = getIPSecGroupConfig($espGroup, 'esp', $getOrig);
            }
        } elsif ($node eq 'bind') {
            $ipsecConfig{'bind'} = getValue("$baseIPSec profile $profile $node", $getOrig);
        } else {
            print "Unknown IPSec node '$node'\n";
        }
    }

    return %ipsecConfig; 
}


sub getIPSecGroupConfig {
    my $group = shift;
    my $type = shift; # ike or esp 
    my $getOrig = shift;
    my %config;

    my @nodes = getNodes("$baseIPSec $type-group $group", $getOrig);

    foreach my $node (@nodes) {
        if ($node eq 'proposal') {
            $config{$node} = {};
            my @proposals =  getNodes("$baseIPSec $type-group $group $node", $getOrig);

            foreach my $proposal (@proposals) {
                $config{$node}{$proposal} = {};

                my @proposalConfig = getNodes("$baseIPSec $type-group $group $node $proposal", $getOrig);

                foreach my $config (@proposalConfig) {
                    $config{$node}{$proposal}{$config} = getValue("$baseIPSec $type-group $group $node $proposal $config", $getOrig)
                }
            }
        } else {
           $config{$node} = getValue("$baseIPSec $type-group $group $node", $getOrig);
        } 
    }

    return %config;
}

sub buildIPSecConfig {
    my (%ipsecConfig) = @_;
    my @config;

    $ipsecChanges = 1;

    my ($espHash, $espEncryption, $espCompresssion);

    # Defaults
    my $exchangeMode = "main, aggressive";
    my $natt = 'off';
    my $ikeLifetime = 3600; 
    my $espLifetime = 3600; 
    my $dpdDelay = 30;
    my $dpdRetry = 30;
    my $log = 'error';

    if (length($ipsecConfig{'ike'}{'proposal'} > 1)) {
        $exchangeMode = "main";
    }

    if (exists $ipsecConfig{'nat-traversal'} && $ipsecConfig{'nat-traversal'} eq 'enable') {
        $natt = 'on';
    }

    if (exists $ipsecConfig{'esp'}{'lifetime'}) {
        $espLifetime = $ipsecConfig{'esp'}{'lifetime'};
    }

    if (exists $ipsecConfig{'ike'}{'lifetime'}) {
        $ikeLifetime = $ipsecConfig{'ike'}{'lifetime'};
    }

    if ($ipsecConfig{'log'} == 1) {
        $log = 'info';
    } elsif ($ipsecConfig{'log'} == 2) {
        $log = 'debug';
    }

    push(@config, "path pre_shared_key \"$preSharedKeyConfig\";");
    push(@config, "log $log;");
    push(@config, "complex_bundle on;");

    push(@config, "listen {");
    push(@config, "$indent adminsock \"/usr/var/racoon/racoon.sock\" \"root\" \"vyattacfg\" 0660;");
    push(@config, "}");

    push(@config, "remote anonymous {");
    push(@config, "$indent exchange_mode $exchangeMode;");
    push(@config, "$indent nat_traversal $natt;");
    push(@config, "$indent dpd_delay $dpdDelay;");
    push(@config, "$indent dpd_retry $dpdRetry;");
    push(@config, "$indent lifetime time $ikeLifetime seconds;");
    push(@config, "$indent script \"/etc/opennhrp/racoon-ph1dead.sh\" phase1_down;");

    foreach (sort keys %{$ipsecConfig{'ike'}{'proposal'}}) {
        my $hash = $ipsecConfig{'ike'}{'proposal'}{$_}{'hash'}; 
        my $encryption= $ipsecConfig{'ike'}{'proposal'}{$_}{'encryption'};
        my $dhGroup = $ipsecConfig{'ike'}{'proposal'}{$_}{'dh-group'};

        push(@config, "$indent proposal {");
        push(@config, "$indent $indent encryption_algorithm $encryption;");
        push(@config, "$indent $indent hash_algorithm $hash;");
        push(@config, "$indent $indent dh_group $dhGroup;");
        push(@config, "$indent $indent authentication_method pre_shared_key;");
        push(@config, "$indent }");
    }

    foreach (sort keys %{$ipsecConfig{'esp'}{'proposal'}}) {
        if ($espHash) {
            $espHash = "$espHash, hmac_" . $ipsecConfig{'esp'}{'proposal'}{$_}{'hash'};
            $espEncryption = "$espEncryption, " . $ipsecConfig{'esp'}{'proposal'}{$_}{'encryption'};
        } else {
            $espHash = "hmac_" . $ipsecConfig{'esp'}{'proposal'}{$_}{'hash'};
            $espEncryption = $ipsecConfig{'esp'}{'proposal'}{$_}{'encryption'}; 
        } 
    }

    push(@config, "}");
    push(@config, "sainfo anonymous {");
    push(@config, "$indent lifetime time $espLifetime seconds;");
    push(@config, "$indent encryption_algorithm $espEncryption;");
    push(@config, "$indent authentication_algorithm $espHash;");

    if (exists $ipsecConfig{'esp'}{'pfs'} && $ipsecConfig{'esp'}{'pfs'} ne 'enable') {
        $ipsecConfig{'esp'}{'pfs'} =~ s/dh-group//g;
        push(@config, "$indent pfs_group $ipsecConfig{'esp'}{'pfs'};");
    }

    # The compression option must be enabled 
    #if (exists $ipsecConfig{'esp'}{'compression'} && $ipsecConfig{'esp'}{'compression'} eq 'enable') {
    push(@config, "$indent compression_algorithm deflate;");
    #}

    push(@config, "}");

    if (exists $ipsecConfig{'key'}) {
        my @psk = ("*\t$ipsecConfig{'key'}");
        writeArrayToFile("$preSharedKeyConfig", @psk);
    }

    writeArrayToFile("$racoonConfig", @config);
}

sub getNHRPTunnels {
    my @nhrpTunnels;

    foreach my $tunnel (getNodes("$baseNHRP tunnel")) {
       push (@nhrpTunnels, $tunnel);
    }

    if (@nhrpTunnels) {
        $nhrpEnable = 1;
    }

    return @nhrpTunnels;
}

sub getNHRPConfig {
    my @nhrpTunnels = getNHRPTunnels();

    if ($commitTunnel && $commitTunnel ~~ @nhrpTunnels) {
        my %nhrpConfig = getTunnelNHRPConfig($commitTunnel);
        my %nhrpOrigConfig = getTunnelNHRPConfig($commitTunnel, 1);

        if (! eq_hash(\%nhrpConfig, \%nhrpOrigConfig)) {
            buildNHRPConfig($commitTunnel, %nhrpConfig);
        }
    }
}

sub getTunnelNHRPConfig {
    my $tunnel = shift;
    my $getOrig = shift;
    my %nhrpConfig;
    my $baseNode = "$baseNHRP tunnel $tunnel";
    my @nodes = getNodes($baseNode, $getOrig);

    foreach my $node (@nodes) {
        my ($auth, $hold, $multicast, $redirect, $shortcut);

        if ($node eq 'authentication') {
            $nhrpConfig{'cisco-authentication'} = getValue("$baseNode $node", $getOrig);
        } elsif ($node eq 'holding-time') {
            $nhrpConfig{'holding-time'} = getValue("$baseNode $node", $getOrig);
        } elsif ($node eq 'multicast') {
            $nhrpConfig{'multicast'} = getValue("$baseNode $node", $getOrig);
        } elsif ($node eq 'redirect') {
            $nhrpConfig{'redirect'} = $node; 
        } elsif ($node eq 'shortcut') {
            $nhrpConfig{'shortcut'} = $node; 
        } elsif ($node eq 'map') {
            $nhrpConfig{'maps'} = getNHRPMap($tunnel, $getOrig);
        } else {
            print "Unknown NHRP node '$node'\n";
        }
    }

    return %nhrpConfig;
}

sub getNHRPMap {
    my $tunnel = shift;
    my $getOrig = shift;
    my $register;
    my @nhrpMaps;
    my $baseNode = "$baseNHRP tunnel $tunnel";
    my @destinations = getNodes("$baseNode map", $getOrig);

    foreach my $destination (@destinations) {
        my $nbma = getValue("$baseNode map $destination nbma-address", $getOrig);

        if ($nbma) {
            if (getExists("$baseNode map $destination register", $getOrig)) {
                $register = 'register';

                if (getNodes("$baseNode map $destination register", $getOrig) > 0) {
                    $register = 'register cisco';
                } 

                push (@nhrpMaps, "map $destination $nbma $register");

            } else {
                push (@nhrpMaps, "map $destination $nbma");
            }
        }
    }

    return \@nhrpMaps;
}

sub buildNHRPConfig {
    my $tunnel = shift;
    my (%nhrpConfig) = @_; 
    my @config;

    $nhrpChanges = 1;

    while ( my ($key, $value) = each %nhrpConfig ) {
        if ($key eq 'maps') {
            foreach my $nhrpMap (@{$nhrpConfig{'maps'}}) {
                unshift (@config, $indent . $nhrpMap);
            }
        } elsif ($key eq $value) {
            push (@config, $indent . $key);
        } else {
            push (@config, $indent . "$key $value");
        }
    }

    unshift (@config, "interface $tunnel");

    updateNHRPConfig($tunnel, @config);
}


sub updateNHRPConfig {
    my $tunnel = shift;
    my @updatedConfig = @_; 
    my @config;
    my $remove;

    my @currentConfig = getFileAsArray("$nhrpConfig");

    if ("interface $tunnel" ~~ @currentConfig) {
        foreach (@currentConfig) {
            if ($_ eq "interface $tunnel") {
                $remove = 1;
            } elsif ($_ =~ /^interface/) {
                $remove = '';
                push (@config, $_);
            } elsif (!$remove) {
                push (@config, $_);
            }
        }

        foreach (@updatedConfig) {
            push (@config, $_);
        }

    } else {
        push (@config, @currentConfig);
        push (@config, @updatedConfig); 
    }

    writeArrayToFile("$nhrpConfig", @config);
}

sub isRunning {
    my $process = shift;

    chomp (my $status = `ps -ef | grep -v grep | grep $process`);

    if (length($status) > 1) {
        return 1;
    }

}

sub runCommand {
    my $command = shift;
    my $quiet = shift;

    my $output = `$command`;
    my $exitStatus = $?;

    if (! $quiet) {
        print $output; 
    }

    if ($exitStatus > 0) {
        $exitCode = $exitStatus;
    }
}

sub getFileAsArray {
    my $filename = shift;
    my @config;

    open (my $fh, $filename) || die "Can not open $filename\n";
    chomp (@config = <$fh>); 
    close $fh;

    return @config;
}

sub writeArrayToFile {
    my $filename = shift;
    my @config = @_;

    open (my $fh, '>', $filename) || die "Can not open $filename\n";
    foreach (@config) { 
        print $fh "$_\n";
    }
    close $fh;
    
}
#
# End of Subroutines
#

if ($commitIPSec) {
    getIPSecConfig();

    #print "IPSec Changes = '$ipsecChanges' " ;
    #print "IPSec Enable = '$ipsecEnable' " ;
    #print "\n";

    if ($ipsecChanges) {
        if (isRunning('/usr/sbin/racoon')) {
            runCommand("/etc/init.d/racoon.init reload");
        } else {
            runCommand("/etc/init.d/racoon.init start");
            if ($nhrpEnable) {
                runCommand("/etc/init.d/opennhrp.init restart");
            }
        }

    } elsif ($ipsecEnable && ! isRunning('/usr/sbin/racoon')) {
        runCommand("/etc/init.d/racoon.init start");
        if ($nhrpEnable) {
            runCommand("/etc/init.d/opennhrp.init restart");
        }
    } elsif (! $ipsecEnable && isRunning('/usr/sbin/racoon')) {
        runCommand("/etc/init.d/racoon.init stop");
    }

} elsif ($commitTunnel) {
    getNHRPConfig();

    #print "NHRP Changes = '$nhrpChanges' " ;
    #print "NHRP Enable = '$nhrpEnable' " ;
    #print "\n";
    
    if ($nhrpChanges) {
        if (isRunning('/usr/sbin/opennhrp')) {
            runCommand("/etc/init.d/opennhrp.init reload");
        } else {
            runCommand("/etc/init.d/opennhrp.init start");
        }

    } elsif ($nhrpEnable && ! isRunning('/usr/sbin/opennhrp')) {
        runCommand("/etc/init.d/opennhrp.init start");
    } elsif (! $nhrpEnable && isRunning('/usr/sbin/opennhrp')) {
        runCommand("/etc/init.d/opennhrp.init stop");
    }
}

exit 0;

