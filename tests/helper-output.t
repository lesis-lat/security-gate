#!/usr/bin/env perl

use strict;
use warnings;
our $VERSION = '0.1.0';
use Test::More;
use Test::Exception;
use lib '../lib';
use SecurityGate::Utils::Helper;

subtest 'Helper output' => sub {
    my $helper_output = SecurityGate::Utils::Helper->new();

    like($helper_output, qr/Security\ Gate\ v0\.1\.0/xms, 'Helper output contains version');
    like($helper_output, qr/-t,\ --token/xms, 'Helper output contains token option');
    like($helper_output, qr/-r,\ --repo/xms, 'Helper output contains repo option');
    like($helper_output, qr/--dependency-alerts/xms, 'Helper output contains dependency alerts option');
    like($helper_output, qr/--secret-alerts/xms, 'Helper output contains secret scanning alerts option');
    like($helper_output, qr/--code-alerts/xms, 'Helper output contains code scanning alerts option');
};

done_testing();
