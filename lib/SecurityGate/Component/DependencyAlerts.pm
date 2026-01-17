package SecurityGate::Component::DependencyAlerts {
    use strict;
    use warnings;
    use Readonly;
    use Mojo::UserAgent;
    use Exporter 'import';

    our $VERSION = '0.1.0';

    Readonly my $HTTP_OK => 200;

    our @EXPORT_OK = qw(@SEVERITIES);
    our @SEVERITIES = ("critical", "high", "medium", "low");

    sub new {
        my (undef, $token, $repository, $severity_limits) = @_;

        my %severity_counts = map { $_ => 0 } @SEVERITIES;

        my $alerts_endpoint = "https://api.github.com/repos/$repository/dependabot/alerts";
        my $user_agent = Mojo::UserAgent -> new();
        my $alerts_request = $user_agent -> get($alerts_endpoint, {Authorization => "Bearer $token"}) -> result();

        if ($alerts_request -> code() != $HTTP_OK) {
            print "Error: Unable to fetch alerts. HTTP status code: " . $alerts_request -> code() . "\n";
            return 1;
        }

        my $alerts_data = $alerts_request -> json();

        foreach my $alert (@{$alerts_data}) {
            if ($alert -> {state} eq "open") {
                my $severity = $alert -> {security_vulnerability} -> {severity};
                $severity_counts{$severity}++;
            }
        }

        print "\n[!] Total of dependency alerts:\n\n";

        foreach my $severity (@SEVERITIES) {
            print "[-] $severity: $severity_counts{$severity}\n";
        }

        print "\n";

        my $threshold_exceeded = 0;

        foreach my $severity (@SEVERITIES) {
            if ($severity_counts{$severity} > $severity_limits -> {$severity}) {
                print "[+] More than $severity_limits -> {$severity} $severity security alerts found.\n";
                $threshold_exceeded = 1;
            }
        }

        if ($threshold_exceeded) {
            return 1;
        }

        return 0;
    }
}

1;
