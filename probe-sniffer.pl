#!/usr/bin/env perl
use v5.38;
use strict;
use warnings;
use IO::Handle;

#- CODE ATTRIBUTION: github.com/brannondorsey/sniff-probes

#— ENVIRONMENT & PRE-FLIGHT CHECKS —
my $iface        = $ENV{IFACE}
    // die "ERROR: IFACE env var must be set. Type \"ifconfig\" to view interfaces.\n";
my $output       = $ENV{OUTPUT}       // 'probes.txt';
my $channel_hop  = $ENV{CHANNEL_HOP}  // 0;

# ensure tcpdump is available
system("command -v tcpdump >/dev/null 2>&1") == 0
    or die "ERROR: tcpdump not found. Please install tcpdump.\n";

#— CHANNEL HOPPIDY-POP —
if ($channel_hop eq '1') {
    my $pid = fork();
    die "ERROR: fork failed: $!\n" unless defined $pid;
    if ($pid == 0) {
        _channel_hop($iface);
        exit 0;
    }
    # parent falls through
}

#— OPEN TCPDUMP PIPE & OUTPUT FILE —
open my $td, "-|", "sudo", "tcpdump",
    "-l", "-I", "-i", $iface,
    "-e", "-s", "256",
    "type", "mgt", "subtype", "probe-req"
  or die "ERROR: failed to run tcpdump: $!\n";

open my $out, ">>", $output
  or die "ERROR: cannot open '$output' for append: $!\n";

# turn on autoflush
STDOUT->autoflush(1);
$out  ->autoflush(1);

#— MAIN PARSING LOOP —
while (<$td>) {
    chomp;
    my $line = $_;

    # 1) strength
    my ($strength) = $line =~ /(-?\d+dBm)/;
    next unless defined $strength;

    # 2) MAC (strip leading "SA:")
    my ($mac) = $line =~ /(SA(?::[0-9a-f]{2}){6})/i;
    next unless defined $mac;
    $mac =~ s/^SA://i;

    # 3) SSID
    my ($ssid) = $line =~ /Probe Request \((.*?)\)/;
    next unless defined $ssid && length $ssid;

    # 4) TIMESTAMP (first token) w/o fractional part
    my ($ts) = split /\s+/, $line, 2;
    $ts =~ s/\.\d+$//;

    my $out_line = sprintf "%s %s %s \"%s\"", $ts, $strength, $mac, $ssid;
    say $out_line;         # STDOUT
    say $out $out_line;    # file
}

#— SUBROUTINES —
sub _channel_hop {
    my ($iface) = @_;
    my @bg = qw(1 2 3 4 5 6 7 8 9 10 11);
    for (;;) {
        for my $chan (@bg) {
            system('sudo', 'iwconfig', $iface, 'channel', $chan);
            sleep 2;
        }
    }
}

