package Chouette;

use common::sense;

use EV;
use AnyEvent;
use AnyEvent::Util;
use AnyEvent::Task::Client;
use AnyEvent::Task::Server;
use Feersum;
use Callback::Frame;
use Log::File::Rolling;
use Cwd;
use Regexp::Assemble;
use Session::Token;
use Data::Dumper;

use Chouette::Context;

our $VERSION = '0.100';



sub new {
    my ($class, $app_spec) = @_;

    my $self = {
        app_spec => $app_spec,
    };
    bless $self, $class;

    my $config = {};

    if ($app_spec->{config_file}) {
        require YAML;
        $config = YAML::LoadFile($app_spec->{config_file});
    }

    $self->{config} = {
        %{ $app_spec->{config_defaults} },
        %$config,
    };

    $self->_validate_config();

    $self->_compile_app();

    $self->{_done_gensym} = \'';

    return $self;
}




sub _validate_config {
    my ($self) = @_;

    die "var_dir $self->{config}->{var_dir} is not a directory" if !-e $self->{config}->{var_dir};
}


sub _compile_app {
    my ($self) = @_;

    ## Middleware

    foreach my $pkg (@{ $self->{app_spec}->{middleware} }) {
        eval "require $pkg" || die "Couldn't require middleware $pkg\n\n$@";
    }


    ## Pre-route wrappers

    if (defined $self->{app_spec}->{pre_route}) {
        $self->{pre_route_cb} = $self->_load_function($self->{app_spec}->{pre_route}, "pre-route");
    }


    ## Routes

    $self->{route_regexp_assemble} = Regexp::Assemble->new->track(1);
    $self->{route_patterns} = {};

    my $routes = $self->{app_spec}->{routes};

    foreach my $route (keys %$routes) {
        my $re = '\A' . $route . '\z';

        $re =~ s{/}{\\/}g; ## Hack for Regexp::Assemble: https://github.com/ronsavage/Regexp-Assemble/issues/4

        $re =~ s{:([\w]+)}{(?<$1>[^/]+)};

        $self->{route_regexp_assemble}->add($re);

        my $methods = {};

        foreach my $method (keys %{ $routes->{$route} }) {
            $methods->{$method} = $self->_load_function($routes->{$route}->{$method}, "route: $method $route");
        }

        $self->{route_patterns}->{$re} = $methods;
    }

    $self->{route_regexp} = $self->{route_regexp_assemble}->re;


    ## Tasks

    foreach my $task_name (keys %{ $self->{app_spec}->{tasks} }) {
        die "invalid task name: $task_name" if $task_name !~ /\A\w+\z/;

        my $task = $self->{app_spec}->{tasks}->{$task_name};
        my $pkg = $task->{pkg};

        eval "require $pkg" || die "Couldn't require task package $pkg (required for task $task_name)\n\n$@";
        die "Couldn't find function new in $pkg (needed task $task_name)" if !defined &{ "${pkg}::new" };
    }
}



sub _load_function {
    my ($self, $spec, $needed_for) = @_;

    $needed_for = "(needed for $needed_for)" if defined $needed_for;

    if ($spec =~ /^(.*)::([^:]+)$/) {
        my ($pkg, $func_name) = ($1, $2);
        eval "require $pkg" || die "Couldn't require $pkg $needed_for\n\n$@";
        die "Couldn't find function $func_name in $pkg $needed_for" if !defined &{ "${pkg}::${func_name}" };
        my $func = \&{ "${pkg}::${func_name}" };
        return $func;
    } else {
        die "couldn't parse function: '$spec'";
    }
}



sub _listen {
    my ($self) = @_;

    my $listen = $self->{config}->{listen};

    my $socket;

    if ($listen =~ m{^unix:(.*)}) {
        my $socket_file = $1;

        require IO::Socket::UNIX;

        unlink($socket_file);

        $socket = IO::Socket::UNIX->new(
            Listen => 5,
            Type => SOCK_STREAM(),
            Local => $socket_file,
        ) || die "unable to listen on $listen : $!";

        $self->{_friendly_socket_desc} = "http://[unix:$socket_file]";
    } else {
        my $local_addr = '0.0.0.0';
        my $port;

        if ($listen =~ m{^(.*):(\d+)$}) {
            $local_addr = $1;
            $port = $2;
        } elsif ($listen =~ m{^(\d+)$}) {
            $port = $1;
        } else {
            die "unable to parse listen param: '$listen'";
        }

        require IO::Socket::INET;

        $socket = IO::Socket::INET->new(
            Listen => 5,
            Proto => 'tcp',
            LocalAddr => $local_addr,
            LocalPort => $port,
            ReuseAddr => 1,
        ) || die "unable to listen on $listen : $!";

        $self->{_friendly_socket_desc} = "http://$local_addr:$port";
    }

    AnyEvent::Util::fh_nonblocking($socket, 1);

    $self->{accept_socket} = $socket;
}

sub _logging {
    my ($self) = @_;

    my $log_dir = "$self->{config}->{var_dir}/logs";

    if (!-e $log_dir) {
        mkdir($log_dir) || die "couldn't mkdir($log_dir): $!";
    }

    $log_dir = Cwd::abs_path($log_dir);

    my $app_name = $self->{config}->{logging}->{file_prefix} // 'app';

    my $curr_symlink = "$log_dir/$app_name.current.log";

    $self->{raw_logger} = Log::File::Rolling->new(
                              filename => "$log_dir/$app_name.%Y-%m-%dT%H.log",
                              current_symlink => $curr_symlink,
                              timezone => ($self->{config}->{logging}->{timezone} // 'gmtime'),
                          ) || die "Error creating Log::File::Rolling logger: $!";

    $self->{_friendly_current_logfile} = $curr_symlink;
}


sub _start_task_servers {
    my ($self) = @_;

    my $task_dir = "$self->{config}->{var_dir}/tasks";

    if ($self->{app_spec}->{tasks}) {
        if (!-e $task_dir) {
            mkdir($task_dir) || die "couldn't mkdir($task_dir): $!";
        }
    }

    foreach my $task_name (keys %{ $self->{app_spec}->{tasks} }) {
        my $task = $self->{app_spec}->{tasks}->{$task_name};
        my $pkg = $task->{pkg};

        my $obj;

        my $constructor_func = \&{ "${pkg}::new" };

        my $checkout_done;
        $checkout_done = \&{ "${pkg}::CHECKOUT_DONE" } if defined &{ "${pkg}::CHECKOUT_DONE" };

        AnyEvent::Task::Server::fork_task_server(
            listen => ['unix/', "$task_dir/$task_name.socket"],

            setup => sub {
                $obj = $constructor_func->($pkg, $self->{config});
            },

            interface => sub {
                my ($method, @args) = @_;
                $obj->$method(@args);
            },

            $checkout_done ? (
                checkout_done => sub {
                    $checkout_done->($obj);
                },
            ) : (),

            %{ $task->{server} },
        );
    }
}


sub _start_task_clients {
    my ($self) = @_;

    my $task_dir = "$self->{config}->{var_dir}/tasks";

    foreach my $task_name (keys %{ $self->{app_spec}->{tasks} }) {
        my $task = $self->{app_spec}->{tasks}->{$task_name};

        $self->{task_clients}->{$task_name} = AnyEvent::Task::Client->new(
            connect => ['unix/', "$task_dir/$task_name.socket"],
            %{ $task->{client} },
        );

        $self->{task_checkout_caching}->{$task_name} = 1 if $self->{app_spec}->{tasks}->{$task_name}->{checkout_caching};
    }
}



sub serve {
    my ($self) = @_;

    $self->{_serving} = 1;

    $self->_start_task_servers();
    $self->_start_task_clients();
    $self->_listen();
    $self->_logging();

    $self->{feersum} = Feersum->endjinn;
    $self->{feersum}->use_socket($self->{accept_socket});

    $self->{feersum}->psgi_request_handler(sub {
        my $env = shift;

        return sub {
            my $responder = shift;

            my $c = Chouette::Context->new(
                        chouette => $self,
                        env => $env,
                        responder => $responder,
                    );

            $self->_handle_request($c);
        };
    });

    say "="x79;
    say;
    say "Chouette $VERSION";
    say;
    say "PID = $$";
    say "UID/GIDs = $</$(";
    say "Listening on: $self->{_friendly_socket_desc}";
    say;
    say "Follow log messages:";
    say "    log-defer-viz -F $self->{_friendly_current_logfile}";
    say;
    say "="x79;
}


sub run {
    my ($self) = @_;

    $self->serve unless $self->{_serving};

    AE::cv->recv;
}


sub _handle_request {
    my ($self, $c) = @_;

    my $req = $c->req;
    $c->logger->info("Request from " . $req->address . " : " . $req->method . " " . $req->path);

    frame_try {
        if ($self->{pre_route_cb}) {
            my $pre_route_cb = fub { $self->{pre_route_cb}->(@_) };
            $pre_route_cb->($c, fub { $self->_do_routing($c) });
        } else {
            $self->_do_routing($c);
        }
    } frame_catch {
        my $err = $@;

        return if ref($err) && ($err + 0 == $c->{chouette}->{_done_gensym} + 0);

        if ($err =~ /^(\d\d\d)\b/) {
            my $status = $1;

            $c->logger->warn($err) if $status < 200 || $status >= 400;

            $c->respond({ http_code => $status }, $status);
            return;
        }

        $c->logger->error($err);
        $c->logger->data->{stacktrace} = $_[0];

        $c->respond({ error => 'internal server error' }, 500);
    };
}


sub _do_routing {
    my ($self, $c) = @_;

    my $path = $c->{env}->{PATH_INFO};
    $path = '/' if $path eq '';

    die 404 unless $path =~ $self->{route_regexp};

    my $route_params = \%+;

    my $methods = $self->{route_patterns}->{ $self->{route_regexp_assemble}->source($^R) };

    my $method = $c->{env}->{REQUEST_METHOD};

    my $func = $methods->{$method};

    die 405 if !$func;

    $c->{route_params} = $route_params;

    $func->($c);
}



sub generate_token {
    state $generator = Session::Token->new;

    return $generator->get;
}

1;



__END__

=encoding utf-8

=head1 NAME

Chouette - REST API Framework

=head1 DESCRIPTION

L<Chouette> is a framework for making HTTP services. It is primarily designed for services that implement REST-like APIs using C<application/json> as input and C<application/x-www-form-urlencoded> as output, although this is somewhat flexible.

Why "chouette"? A L<backgammon chouette|http://www.bkgm.com/variants/Chouette.html> is a fast-paced, exciting game with lots going on at once, kind of like an asynchronous REST API server. :)

Chouette was extracted from numerous services I have made before, and its main purpose is to glue together the following modules in the way they were designed to be used:

=over

=item L<AnyEvent::Task>

Allows us to perform blocking operations without holding up other requests.

=item L<Callback::Frame>

Makes exception handling simple and convenient. You can C<die> anywhere and it will only affect the request being currently handled.

=item L<Session::Token>

For random identifiers such as session tokens (obviously).

=item L<Log::Defer>

Structured logging, properly integrated with L<AnyEvent::Task> so your tasks can log messages into the proper request log contexts.

Note that Chouette also depends on L<Log::Defer::Viz> for viewing the logs.

=item L<Log::File::Rolling>

To store the logs in files, and rotate them periodically. Also maintains a current symlink so you can simply run the following in a shell and you'll always see the latest logs as you need them:

    $ log-defer-viz -F /var/myapi/logs/lpapid.current.log

=back



=head1 CHOUETTE OBJECT

To start a server, create a C<Chouette> object. The constructor accepts a hash ref with the following parameters. See the C<bin/myapi> file below for a full example.

=over

=item C<config_file>

This path is where the config file will be read from. Its format is L<YAML>.

The only required parameters are C<var_dir> and C<listen> (though these can be defaulted with the C<config_defaults> parameter below).

=item C<config_defaults>

This hash is where you provide default config values. These values can be overridden by the config file.

You can use the config store for values specific to your application (it is accessible with the C<config> method of the context), but here are the values that C<Chouette> itself looks for:

C<var_dir> - This directory must exist and be writable. C<Chouette> will use this to store log files and L<AnyEvent::Task> sockets.

C<listen> - This is the location the Chouette server will listen on. Examples: C<8080> C<127.0.0.1:8080> C<unix:/var/myapi/myapi.socket>

C<logging.file_prefix> - The prefix for log file names (default is C<app>).

C<logging.timezone> - Either C<gmtime> or C<localtime> (C<gmtime> is default, see L<Log::File::Rolling>).

=item C<middleware>

Any array-ref of L<Plack::Middleware> packages.

    middleware => [
        'Plack::Middleware::ContentLength',
        ['Plack::Middleware::CrossOrigin', origins => '*'],
    ],

FIXME: this is not fully implemented yet...

=item C<pre_route>

A package and function that will be called with a context and callback. If the function determines the request processing should continue, it should call the callback.

See the C<lib/MyAPI/Auth.pm> file below for an example of the function.

=item C<routes>

Routes are specified when you create the C<Chouette> object.

    routes => {
        '/myapi/resource' => {
            POST => 'MyAPI::Resource::create',
            GET => 'MyAPI::Resource::get_all',
        },

        '/myapi/resource/:resource_id' => {
            GET => 'MyAPI::Resource::get_by_id',
        },
    },

For each route, it will try to C<require> the package specified, and obtain the function specified for each HTTP method. If the package or function doesn't exists, an error will be thrown.

You can use C<:name> elements in your routes to extract parameters. They are accessible via the C<route_params> method of the context (see C<lib/MyAPI/Resource.pm> below).

Note that routes are combined with L<Regexp::Assemble> so don't worry about having lots of routes, it doesn't loop over each one.

See the C<bin/myapi> file below for an example.

=item C<tasks>

This is a hash-ref of L<AnyEvent::Task> servers/clients to create.

    tasks => {
        db => {
            pkg => 'LPAPI::Task::DB',
            checkout_caching => 1,
            client => {
                timeout => 20,
            },
            server => {
                hung_worker_timeout => 60,
            },
        },
    },

C<checkout_caching> means that if a checkout is obtained and released, it will be maintained for the duration of the request and if another checkout for this task is obtained, then the original will be returned. This is useful for DBI for example, because we want the authenticate handler to run in the same transaction as the handler (for both correctness and efficiency reasons).

Additional arguments to L<AnyEvent::Task::Client> and <AnyEvent::Task::Server> can be passed in via C<client> and C<server>.

See the C<bin/myapi> and C<lib/MyAPI/Task/PasswordHasher.pm> files for an example.

=back

After the C<Chouette> object is obtained, you should call C<serve> or C<run>. They are basically the same except C<serve> returns whereas C<run> enters the L<AnyEvent> event loop. These are equivalent:

    $chouette->run;

and

    $chouette->serve;
    AE::cv->recv;



=head1 CONTEXT

There is a C<Chouette::Context> object passed into every handler. It represents the current request and various related items.

=over

=item C<respond>

The respond method sends a JSON response, which will be encoded from the first argument:

    $c->respond({ a => 1, b => 2, });

Note: After responding, this method returns and your code continues. If you call C<respond> again, an error will be logged but the second response will not be sent (it can't be -- the connection is probably already closed). If you wish to stop processing, you can C<die> with the result from C<respond> since it returns a special object for this purpose:

    die $c->respond({ a => 1, });

C<respond> takes an optional second argument which is the HTTP response code (defaults to 200):

    $c->respond({ error => "access denied" }, 403);

Note that processing continues here again. If you wish to terminate the processing right away, prefix with C<die> as above, or use the following shortcut:

    die "403: access denied";

If you are happy with the L<Feersum> default message ("Forbidden" in this case) you can just do:

    die 403;

=item C<done>

If you wish to stop processing but not send a response:

    $c->done;

You will need to send a response later, usually from an async callback. Note: If the last reference to the context is destroyed without a response being sent, a 500 "internal server error" response will be sent.

You don't need to call C<done>, you can just C<return> from the handler. C<done> is just for convenience if you are deeply nested in callbacks and don't want to worry about writing a bunch of returning logic.

=item C<respond_raw>

Similar to C<respond> except it doesn't assume JSON encoding:

    $c->respond_raw(200, 'text/plain', 'some plain text');

=item C<logger>

Returns the L<Log::Defer> object associated with the request:

    $c->logger->info("some stuff is happening");

    {
        my $timer = $c->logger->timer('doing big_computation');
        big_computation();
    }

See the L<Log::Defer> docs for more details. For viewing the log messages, check out L<Log::Defer::Viz>.

=item C<config>

Returns the C<config> hash. See the L<CHOUETTE OBJECT> section for details.

=item C<req>

Returns the L<Plack::Request> object created by this request.

    my $name = $c->req->parameters->{name};

=item C<res>

FIXME: The L<Plack::Response> object isn't used currently.

=item C<generate_token>

Generates a L<Session::Token> random string. The Session::Token generator is created when the first request comes in so as to avoid "cold" entropy pool immediately after a reboot (see L<Session::Token> docs).

=item C<task>

Returns an <AnyEvent::Task> checkout object for the task with the given name:

    $c->task('db')->selectrow_hashref(q{ SELECT * FROM sometable WHERE id = ? },
                                      undef, $id, sub {
        my ($dbh, $row) = @_;

        die $c->respond($row);
    });

See L<AnyEvent::Task> for more details.

=back





=head1 EXAMPLE

=over

=item C<bin/myapi>

    #!/usr/bin/env perl

    use common::sense;

    use Chouette;

    my $chouette = Chouette->new({
        config_file => '/etc/myapi.conf',

        config_defaults => {
            var_dir => '/var/myapi',
            listen => '8080',

            logging => {
                file_prefix => 'myapi',
                timezone => 'localtime',
            },
        },
        middleware => [
            'Plack::Middleware::ContentLength',
        ],

        pre_route => 'MyAPI::Auth::authenticate',

        routes => {
            '/myapi/unauth/login' => {
                POST => 'MyAPI::User::login',
            },

            '/myapi/resource' => {
                POST => 'MyAPI::Resource::create',
                GET => 'MyAPI::Resource::get_all',
            },

            '/myapi/resource/:resource_id' => {
                GET => 'MyAPI::Resource::get_by_id',
            },
        },

        tasks => {
            passwd => {
                pkg => 'MyAPI::Task::PasswordHasher',
            },
            db => {
                pkg => 'MyAPI::Task::DB',
                checkout_caching => 1, ## so same dbh is used in authenticate and handler
            },
        },
    });

    $chouette->run;


=item C<lib/MyAPI/Auth.pm>

    package MyAPI::Auth;

    use common::sense;

    sub authenticate {
        my ($c, $cb) = @_;

        if ($c->{env}->{PATH_INFO} =~ m{^/lpapi/unauth/}) {
            return $cb->();
        }

        my $session = $c->req->parameters->{session};

        $c->task('db')->selectrow_hashref(q{ SELECT user_id FROM session WHERE session_token = ? },
                                          undef, $session, sub {
            my ($dbh, $row) = @_;

            die 403 if !$row;

            $c->{user_id} = $row->{user_id};

            $cb->();
        });
    }

    1;


=item C<lib/MyAPI/User.pm>

    package MyAPI::User;

    use common::sense;

    sub login {
        my $c = shift;

        my $username = $c->req->parameters->{username};
        my $password = $c->req->parameters->{password};

        $c->task('db')->selectrow_hashref(q{ SELECT user_id, password_hashed FROM myuser WHERE username = ? }, undef, $username, sub {
            my ($dbh, $row) = @_;

            die 403 if !$row;

            $c->task('passwd')->verify_password($row->{password_hashed}, $password, sub {
                die 403 if !$_[1];

                my $session_token = $c->generate_token();

                $dbh->do(q{ INSERT INTO session (session_token, user_id) VALUES (?, ?) },
                         undef, $session_token, $row->{user_id}, sub {

                    $dbh->commit(sub {
                        die $c->respond({ sess => $session_token });
                    });
                });
            });
        });
    }

    1;



=item C<lib/MyAPI/Resource.pm>

    package MyAPI::Auth;

    use common::sense;

    sub create {
        my $c = shift;
        die "500 not implemented";
    }

    sub get_all {
        $c->logger->warn("denying access to get_all");
        die 403;
    }

    sub get_by_id {
        my $c = shift;
        my $resource_id = $c->route_params->{resource_id};
        die $c->respond({ resource_id => $resource_id, });
    }

    1;



=item C<lib/MyAPI/Task/PasswordHasher.pm>

    package MyAPI::Task::PasswordHasher;

    use common::sense;

    use Authen::Passphrase::BlowfishCrypt;
    use Encode;


    sub new {
        my ($class, %args) = @_;

        my $self = {};
        bless $self, $class;

        open($self->{dev_urandom}, '<:raw', '/dev/urandom') || die "open urandom: $!";

        setpriority(0, $$, 19); ## renice our process so we don't hold up more important processes

        return $self;
    }

    sub hash_password {
        my ($self, $plaintext_passwd) = @_;

        read($self->{dev_urandom}, my $salt, 16) == 16 || die "bad read from urandom";

        return Authen::Passphrase::BlowfishCrypt->new(cost => 10,
                                                      salt => $salt,
                                                      passphrase => encode_utf8($plaintext_passwd // ''))
                                                ->as_crypt;

    }

    sub verify_password {
        my ($self, $crypted_passwd, $plaintext_passwd) = @_;

        return Authen::Passphrase::BlowfishCrypt->from_crypt($crypted_passwd // '')
                                                ->match(encode_utf8($plaintext_passwd // ''));
    }

    1;



=item C<lib/MyAPI/Task/DB.pm>

    package MyAPI::Task::DB;

    use common::sense;

    use AnyEvent::Task::Logger;

    use DBI;


    sub new {
        my $config = shift;

        my $dbh = DBI->connect("dbi:Pg:dbname=myapi", '', '', {AutoCommit => 0, RaiseError => 1, PrintError => 0, })
            || die "couldn't connect to db";

        return $dbh;
    }


    sub CHECKOUT_DONE {
        my ($dbh) = @_;

        $dbh->rollback;
    }

    1;

=back



=head1 SEE ALSO

More documentation can be found in the modules linked in the L<DESCRIPTION> section.

L<Chouette github repo|https://github.com/hoytech/Chouette>

=head1 AUTHOR

Doug Hoyte, C<< <doug@hcsw.org> >>

=head1 COPYRIGHT & LICENSE

Copyright 2017 Doug Hoyte.

This module is licensed under the same terms as perl itself.
