#!/usr/bin/perl

use strict;
use warnings;


my $server = Server->new(timeout => 15);
$server->run;
exit(0);

package Server;

use parent 'Net::SFTP::Server::FS';
use File::Temp qw(tempfile);

sub new {
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    $self->{overlay} = {};
    $self;
}

sub handle_command_open_v3 {
    my ($self, $id, $path, $flags, $attrs) = @_;
    my $writable = $flags & SSH_FXF_WRITE;
    my $perms = $attrs->{mode};
    my ($old_umask, $fh, $tfh, $old_path);
    if (defined $perms) {
	$old_umask = umask $perms;
    }
    else {
	$perms = 0666;
    }
    my $pflags = $self->sftp_open_flags_to_sysopen($flags & ~(SSH_FXF_TRUNC|SSH_FXF_CREAT));
    if (exists $self->{reverse_overlay}{$path}) {
        $path = $self->{reverse_overlay}{$path}
    }
    else {
        if ( (-f $path and $flags & SSH_FXF_TRUNC) or
            (!-f $path and $flags & SSH_FXF_CREAT) ) {
            $old_path = $path;
            ($tfh, $path) = tempfile($template, DIR => "/tmp/");
            $pflags &= ~(SSH_FXF_TRUNC|SSH_FXF_CREAT);
        }
    }
    unless (sysopen $fh, $path, $pflags, $perms) {
        $self->push_status_errno_response($id);
        umask $old_umask if defined $old_umask;
        return;
    }
    umask $old_umask if defined $old_umask;
    if ($writable) {
	Net::SFTP::Server::FS::_set_attrs($path, $attrs)
	    or $self->send_status_errno_response($id);
    }
    my $hid = $self->save_file_handler($fh, $flags, $perms, $old_path // $path);
    $self->{overlay}{$old_path} = {$path} if defined $old_path;
    $debug and $debug & 2 and _debug "file $path open as $hid (pkt id: $id)";
    $self->push_handle_response($id, $hid);
}

sub handle_command_close_v3 {
    my ($self, $id, $hid) = @_;
    my ($type, $fh) = $self->remove_handler($hid)
	or return $self->push_status_response($id, SSH_FX_FAILURE, "Bad file handler");
    if ($type eq 'dir') {
	$debug and $debug & 2 and _debug "closing dir handle $hid (id: $id)";
	closedir($fh) or return $self->push_status_errno_response($id);
    }
    elsif ($type eq 'file') {
	$debug and $debug & 2 and _debug "closing file handle $hid (id: $id)";
	close($fh) or return $self->push_status_errno_response($id);
    }
    else {
	croak "Internal error: unknown handler type $type";
    }
    $self->push_status_ok_response($id);
}
