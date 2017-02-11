package MyTask;

use AnyEvent::Task::Logger;

sub new {
    my ($class) = @_;

    my $self = {};

    bless $self, $class;

    return $self;
}

sub times7 {
    my ($self, $arg) = @_;

    logger->info("Hello from PID $$");

    sleep 1;

    return $arg * 7;
}

1;
