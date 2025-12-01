ifrequires "Getopt::Long", "2.54";
requires "Mojolicious", "9.39";

on 'test' => sub {
    requires "Test::More";
    requires "Test::Exception";
    requires "Test::MockObject";
    requires "Test::Output";
    requires "Capture::Tiny";
};
