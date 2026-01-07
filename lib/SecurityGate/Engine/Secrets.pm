package SecurityGate::Engine::Secrets {
    use strict;
    use warnings;
    use Readonly;
    our $VERSION = '0.1.0';
    use Mojo::UserAgent;
    Readonly my $HTTP_OK => 200;

    sub new {
        my (undef, $token, $repository, $severity_limits) = @_;

        my $endpoint  = "https://api.github.com/repos/$repository/secret-scanning/alerts";
        my $user_agent = Mojo::UserAgent -> new();
        my $request   = $user_agent -> get($endpoint, {Authorization => "Bearer $token"}) -> result();

        if ($request -> code() == $HTTP_OK) {
            my $data        = $request -> json();
            my $open_alerts = 0;
            my @alert_details;

            foreach my $alert (@$data) {
                if ($alert -> {state} eq "open") {
                    $open_alerts++;

                    my $locations_endpoint = "https://api.github.com/repos/$repository/secret-scanning/alerts/" . $alert -> {number} . "/locations";
                    
                    my $locations_request  = $user_agent -> get($locations_endpoint, {
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

            foreach my $detail (@alert_details) {
                print "[-] Alert " . $detail -> {alert_number} . " found in the following locations:\n";

                foreach my $location (@{$detail -> {locations}}) {
                    my $file_path  = $location -> {details} -> {path} // 'Unknown file';
                    my $start_line = $location -> {details} -> {start_line} // 'Unknown line';

                    print "File: $file_path, Start line: $start_line\n";
                }
            }

            my $threshold = $severity_limits -> {high};

            if ($open_alerts > $threshold) {
                print "[+] More than $threshold secret scanning alerts found. Blocking pipeline.\n";
                return 1;
            }

            else {
                print "[-] Number of secret scanning alerts ($open_alerts) is within the acceptable limit ($threshold).\n";
                return 0;
            }
        }

        else {
            print "Error: Unable to fetch secret scanning alerts. HTTP status code: " . $request -> code() . "\n";
            return 1;
        }
    }
}

1;
