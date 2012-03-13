#!/usr/bin/perl

use parent 'Net::SFTP::Server::FS';
use Net::SFTP::Server::Constants qw(SSH_FX_PERMISSION_DENIED);

sub handle_command_mkdir_v3 {
    my ($self, $id) = @_;
    $self->push_status_response($id, SSH_FX_PERMISSION_DENIED, "mkdir is forbidden");
}

main->new->run();
