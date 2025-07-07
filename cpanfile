requires "Getopt::Long", "2.54";
requires "Mojo::JSON", "9.41";        
requires "Mojo::UserAgent", "9.41";  

on 'test' => sub {
requires "Test::More", "1.302206";
requires "Test::Exception", "0.43";
requires "Test::MockObject", "1.20200122";
requires "Test::Output", "1.031";
requires "Capture::Tiny", "0.48";
};
