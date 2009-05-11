package Net::SFTP::Server::FS;

use strict;
use warnings;
use Carp;

use Fcntl;
use File::Spec;
use File::Strmode;

use Net::SFTP::Server::Constants qw(:all);

use Net::SFTP::Server;
our @ISA = qw(Net::SFTP::Server);

BEGIN {
    *_debug = \&Net::SFTP::Server::_debug;
    *_debugf = \&Net::SFTP::Server::_debugf;
    *_hexdump = \&Net::SFTP::Server::_hexdump;
    *debug = \$Net::SFTP::Server::debug;
}

our $debug;

sub open_flags_to_posix {
    my ($self, $flags) = @_;
    my $posix = 0;
    if ($flags & SSH_FXF_READ) {
	if ($flags & SSH_FXF_WRITE) {
	    $posix = O_RDWR;
	}
	else {
	    $posix = O_RDONLY;
	}
    }
    elsif ($flags & SSH_FXF_WRITE) {
	$posix = O_WRONLY;
    }
    if ($flags & SSH_FXF_CREAT) {
	$posix |= O_CREAT;
    }
    if ($flags & SSH_FXF_TRUNC) {
	$posix |= O_TRUNC;
    }
    if ($flags & SSH_FXF_EXCL) {
	$posix |= O_EXCL;
    }
    $debug and $debug & 128 and _debug "flags $flags to posix $posix";
    $posix;
}

sub new {
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    $self->{next_handler_id} = 'A';
    $self->{handlers} = {};
    $self;
}

sub save_handler {
    my $self = shift;
    my $id = $self->{next_handler_id}++;
    $self->{handlers}{$id} = [@_];
    $id;
}

sub save_file_handler { shift->save_handler(file => @_) }
sub save_dir_handler { shift->save_handler(dir => @_) }

sub get_handler {
    my ($self, $id) = @_;
    my $h = $self->{handlers}{$id}
	or return;
    wantarray ? @$h : $h->[1];
}

sub get_file_handler {
    my @h = shift->get_handler(@_) or return;
    shift @h eq 'file' or return;
    wantarray ? @h : $h[0];
}

sub get_dir_handler {
    my @h = shift->get_handler(@_) or return;
    shift @h eq 'dir' or return;
    wantarray ? @h : $h[0];
}

sub remove_handler {
    my ($self, $id) = @_;
    my $h = delete $self->{handlers}{$id};
    wantarray ? (defined $h ? @$h : ()) : $h;
}

my @errno2status;
$errno2status[Errno::ENOENT] = SSH_FX_NO_SUCH_FILE;
$errno2status[Errno::EBADF] = SSH_FX_NO_SUCH_FILE;
$errno2status[Errno::ELOOP] = SSH_FX_NO_SUCH_FILE;
$errno2status[Errno::EPERM] = SSH_FX_PERMISSION_DENIED;
$errno2status[Errno::EACCES] = SSH_FX_PERMISSION_DENIED;
$errno2status[Errno::EFAULT] = SSH_FX_PERMISSION_DENIED;
$errno2status[Errno::ENAMETOOLONG] = SSH_FX_BAD_MESSAGE;
$errno2status[Errno::EINVAL] = SSH_FX_BAD_MESSAGE;
$errno2status[Errno::ENOSYS] = SSH_FX_OP_UNSUPPORTED;

sub errno_to_status {
    my ($self, $errno) = @_;
    $errno2status[$errno] // SSH_FX_FAILURE;
}

sub push_status_errno_response {
    my ($self, $id) = @_;
    $self->push_status_response($id, $self->errno_to_status($!), $!);
}

sub handle_command_open_v3 {
    my ($self, $id, $path, $flags, $attrs) = @_;
    my $perms = $attrs->{mode} // 0666;
    my $pflags = $self->open_flags_to_posix($flags);
    sysopen my $fh, $path, $pflags, $perms
	or return $self->push_status_errno_response($id);
    my $hid = $self->save_file_handler($fh, $flags, $perms);
    $debug and $debug & 2 and _debug "file $path open as $hid (pkt id: $id)";
    $self->push_handle_response($id, $hid);
}

sub handle_command_read_v3 {
    my ($self, $id, $hid, $off, $len) = @_;
    my $fh = $self->get_file_handler($hid) //
	return $self->push_status_response($id, SSH_FX_FAILURE,
					   "Bad handler");
    $len = 65536 if $len > 65536;

    sysseek($fh, $off, 0) // return $self->push_status_errno_response($id);
    my $bytes = sysread($fh, my($data), $len) //
	return $self->push_status_errno_response($id);
    $bytes == 0 and
	return $self->push_status_response($id, SSH_FX_EOF);
    # TODO: build packet on buffer_out to reduce data copying
    $self->push_packet(uint8 => SSH_FXP_DATA,
		       uint32 => $id,
		       str => $data);
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

sub handle_command_opendir_v3 {
    my ($self, $id, $path) = @_;
    opendir my $dh, $path or return $self->push_status_errno_response($id);
    my $hid = $self->save_dir_handler($dh, $path);
    $debug and $debug & 2 and _debug "dir $path open as $hid (pkt id: $id)";
    $self->push_handle_response($id, $hid);
}

our @month2name = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);

sub resolve_uid {
    my ($self, $uid) = @_;
    my $name = getpwuid $uid;
    defined $name ? $name : $uid;
}

sub resolve_gid {
    my ($self, $gid) = @_;
    my $name = getgrgid $gid;
    defined $name ? $name : $gid;
}

sub readdir_name {
    my ($self, $dir, $entry, $lstat) = @_;
    my $fn = File::Spec->catfile($dir, $entry);
    my (undef, undef, $mode, $nlink, $uid, $gid, undef, $size, $atime, $mtime) =
	($lstat ? lstat $fn : stat $fn) or return { filename => $entry };
    my (undef, $min, $hour, $mday, $mon, $year) = localtime $mtime;
    my $current_year = (localtime)[5];
    my $longname = sprintf("%10s %3d %-9s %-9s % 8d %-3s %2d % 5s %s",
			   strmode($mode),
			   $nlink,
			   $self->resolve_uid($uid),
			   $self->resolve_gid($gid),
			   $size,
			   $month2name[$mon],
			   $mday,
			   ($year == $current_year
			    ? sprintf("%02d:%02d", $hour, $min)
			    : $year + 1900),
			   $entry);

    $debug and $debug & 2 and _debug "longname: $longname (entry: $entry)";

    return {
	filename => $entry,
	longname => $longname,
	attrs => {
	    size => $size,
	    uid => $uid,
	    gid => $gid,
	    permissions => $mode,
	    atime => $atime,
	    mtime => $mtime
	}
    }
}

sub handle_command_readdir_v3 {
    my ($self, $id, $hid) = @_;
    my ($dh, $path) = $self->get_dir_handler($hid)
	or $self->push_status_response($id, SSH_FX_FAILURE, "Bad directory handler");
    my @entry;
    while (defined (my $entry = readdir $dh)) {
	push @entry, $entry;
	last if @entry > 200;
    }
    @entry or return $self->push_status_eof_response($id);
    
    $self->push_name_response($id, map $self->readdir_name($path, $_), @entry);
}

sub stat_to_attrs {
    my ($self, undef, undef, $mode, undef, $uid, $gid, undef, $size, $atime, $mtime) = @_;
    return {
	size => $size,
	uid => $uid,
	gid => $gid,
	permissions => $mode,
	atime => $atime,
	mtime => $mtime
    };
}

sub handle_command_lstat_v3 {
    my ($self, $id, $path) = @_;
    my @stat = lstat $path
	or return $self->push_status_errno_response($id);
    $self->push_attrs_response($id, $self->stat_to_attrs(@stat));
}

sub handle_command_stat_v3 {
    my ($self, $id, $path) = @_;
    my @stat = stat $path
	or return $self->push_status_errno_response($id);
    $self->push_attrs_response($id, $self->stat_to_attrs(@stat));
}

sub handle_command_fstat_v3 {
    my ($self, $id, $hid) = @_;
    my $fh = $self->get_handler($hid);
    defined $fh
	or return $self->push_status_response($id, SSH_FX_FAILURE, "Bad file handler");
    my @stat = stat $fh
	or return $self->push_status_errno_response($id);
    $self->push_attrs_response($id, $self->stat_to_attrs(@stat));
}

1;

__END__

=head1 NAME

Net::SFTP::Server::FS - SFTP server that uses the file system for storage

=head1 SYNOPSIS

  use Net::SFTP::Server::FS;

  my $server = Net::SFTP::Server::FS->new(timeout => 15);
  $server->run;

=head1 DESCRIPTION

This is a work in progress, currently only most common read operations
are supported.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Salvador FandiE<ntilde>o (sfandino@yahoo.com)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
