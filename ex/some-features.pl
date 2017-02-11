#!/usr/bin/env perl

use common::sense;
use File::Temp;
use Chouette;

my $chouette = Chouette->new({
    config_defaults => {
        var_dir => File::Temp::tempdir(CLEANUP => 1),
        listen => '9876',
    },

    middleware => [
        'Plack::Middleware::ContentLength',
        ['Plack::Middleware::CrossOrigin', origins => '*'],
        ['ETag', cache_control => [ 'must-revalidate', 'max-age=3600' ]],
    ],

    routes => {
        '/' => {
            GET => sub {
                my $c = shift;
                die $c->respond({ hello => 'world!' });
            },
        },
        '/asdf' => {
            GET => sub { die "403: blah" },
            POST => sub { die '200 asdf' },
        },
        '/blah/:id' => {
            GET => sub {
                my $c = shift;
                die "400: can't update ID " . $c->route_params->{id};
            },
        },
    },
});

$chouette->run;
