package SecurityGate::Network::AlertNetwork {
    use strict;
    use warnings;
    use SecurityGate::Component::DependencyAlerts;
    use SecurityGate::Component::SecretAlerts;
    use SecurityGate::Component::CodeAlerts;

    our $VERSION = '0.1.0';

    sub new {
        my (undef, $token, $repository, $severity_limits, $alert_options) = @_;
        my @checks;

        if ($alert_options -> {dependency_alerts}) {
            push @checks, sub {
                return SecurityGate::Component::DependencyAlerts -> new(
                    $token,
                    $repository,
                    $severity_limits
                );
            };
        }

        if ($alert_options -> {secret_alerts}) {
            push @checks, sub {
                return SecurityGate::Component::SecretAlerts -> new(
                    $token,
                    $repository,
                    $severity_limits
                );
            };
        }

        if ($alert_options -> {code_alerts}) {
            push @checks, sub {
                return SecurityGate::Component::CodeAlerts -> new(
                    $token,
                    $repository,
                    $severity_limits
                );
            };
        }

        my $result = 0;

        for my $check (@checks) {
            $result += $check -> ();
        }

        return $result;
    }
}

1;
