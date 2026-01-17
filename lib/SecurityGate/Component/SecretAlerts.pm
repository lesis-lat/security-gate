package SecurityGate::Component::SecretAlerts {
    use strict;
    use warnings;
    use Readonly;
    use Mojo::UserAgent;

    our $VERSION = '0.1.0';

    Readonly my $HTTP_OK => 200;

    sub new {
        my (undef, $token, $repository, $severity_limits) = @_;

        my $alerts_endpoint = "https://api.github.com/repos/$repository/secret-scanning/alerts";
        my $user_agent = Mojo::UserAgent -> new();
        my $alerts_request = $user_agent -> get($alerts_endpoint, {Authorization => "Bearer $token"}) -> result();

        if ($alerts_request -> code() != $HTTP_OK) {
            print "Error: Unable to fetch secret scanning alerts. HTTP status code: " . $alerts_request -> code() . "\n";
            return 1;
        }

        my $alerts_data = $alerts_request -> json();
        my $open_alerts = 0;
        my @alert_details;

        foreach my $alert (@{$alerts_data}) {
            if ($alert -> {state} eq "open") {
                $open_alerts++;

                my $locations_endpoint = "https://api.github.com/repos/$repository/secret-scanning/alerts/" . $alert -> {number} . "/locations";

                my $locations_request = $user_agent -> get($locations_endpoint, {
                    Authorization => "Bearer $token"
                }) -> result();

                if ($locations_request -> code() == $HTTP_OK) {
                    my $locations = $locations_request -> json();

                    push @alert_details, {
                        alert_number => $alert -> {number},
                        locations    => $locations,
                    };
                }
            }
        }

        foreach my $alert_detail (@alert_details) {
            print "[-] Alert " . $alert_detail -> {alert_number} . " found in the following locations:\n";

            foreach my $location (@{$alert_detail -> {locations}}) {
                my $file_path = 'Unknown file';
                my $start_line = 'Unknown line';

                if (defined $location -> {details} -> {path}) {
                    $file_path = $location -> {details} -> {path};
                }

                if (defined $location -> {details} -> {start_line}) {
                    $start_line = $location -> {details} -> {start_line};
                }

                print "File: $file_path, Start line: $start_line\n";
            }
        }

        my $threshold = $severity_limits -> {high};

        if ($open_alerts > $threshold) {
            print "[+] More than $threshold secret scanning alerts found. Blocking pipeline.\n";
            return 1;
        }

        print "[-] Number of secret scanning alerts ($open_alerts) is within the acceptable limit ($threshold).\n";
        return 0;
    }
}

1;
