#!/usr/bin/env perl

use 5.030;
use strict;
use warnings;
our $VERSION = '0.1.0';
use lib "./lib/";
use Getopt::Long;
use SecurityGate::Component::DependencyAlerts qw(@SEVERITIES);
use SecurityGate::Network::AlertNetwork;
use SecurityGate::Utils::Helper;

sub main {
    my ($token, $repository, $dependency_alerts, $secret_alerts, $code_alerts);

    my %severity_limits = map { $_ => 0 } @SEVERITIES;

    Getopt::Long::GetOptions(
        "t|token=s"         => \$token,
        "r|repo=s"          => \$repository,
        "c|critical=i"      => \$severity_limits{critical},
        "h|high=i"          => \$severity_limits{high},
        "m|medium=i"        => \$severity_limits{medium},
        "l|low=i"           => \$severity_limits{low},
        "dependency-alerts" => \$dependency_alerts,
        "secret-alerts"     => \$secret_alerts,
        "code-alerts"       => \$code_alerts
    );

    if ($token && $repository) {
        my %alert_options = (
            dependency_alerts => $dependency_alerts,
            secret_alerts     => $secret_alerts,
            code_alerts       => $code_alerts
        );

        my $result = SecurityGate::Network::AlertNetwork -> new(
            $token,
            $repository,
            \%severity_limits,
            \%alert_options
        );
        return $result;
    }

    print SecurityGate::Utils::Helper -> new();
    return 1;
}

if ($ENV{TEST_MODE}) {
    main();
}

if (!$ENV{TEST_MODE}) {
    exit main();
}
