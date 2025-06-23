package SecurityGate::Utils::Helper {
    use strict;
    use warnings;
    our $VERSION = '0.1.0';

    sub new {
        return <<"EOT";

Security Gate v0.1.0
Core Commands
==============
Command                        Description
-------                        -----------
-t, --token                    GitHub token
-r, --repo                     GitHub repository
-c, --critical                 Critical severity limit
-h, --high                     High severity limit
-m, --medium                   Medium severity limit
-l, --low                      Low severity limit
--dependency-alerts            Check for dependency alerts
--secret-alerts                Check for secret scanning alerts
--code-alerts                  Check for code scanning alerts

EOT
    }
}

1;
