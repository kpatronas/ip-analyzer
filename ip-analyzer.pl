#!/usr/bin/env perl
use strict;
use warnings;
use Regexp::Common qw/net/;
use Net::IP;
use Getopt::Long;
use Data::Dumper;
use Math::BigInt;
use Data::Validate::IP;
use Text::Table;
no if $] >= 5.017011, warnings => 'experimental::smartmatch';

my $s_file			  = undef;	# The file string to be split to the @a_files array
my $s_delimeter 	= '\s';	 	# Space, the default delimiter
my $s_ip_version	= 4;		  # The default IP Version to use
my @a_files			  = undef;	# Files to be parsed
my @a_old_ips;					    # Here we store old ip addresses

# Get options functionality
GetOptions ("files=s" 		=> \$s_file,				# Files to be parsed
			      "ip-version=i"=> \$s_ip_version,	# What IP addresses version to parse
			      "delimeter=s"	=> \$s_delimeter)		# The delimiter to used in parsing
			      or die("Error in command line arguments\n");

# If ip-version is not 4 or 6
unless($s_ip_version == 4 || $s_ip_version == 6)
{
	print "Usage: ".$0." --files file1,file2,file3, ... ,file[n] --delimeter [delimeter character] --ip-version [4|6] \n";
	exit();
}

my $tb;
$tb = Text::Table->new("IP","Type","Short","Bin","Integer",
					   "Mask","Size","Last-IP","Length","Loopback",
					   "Link-Local","Multicast","Unroutable","Testnet","Anycast") if($s_ip_version eq 4);
					   
$tb = Text::Table->new("IP","Type","Short","Bin","Integer",
					   "Mask","Size","Last-IP","Length","Loopback",
					   "Link-Local","Multicast","Mapped","Discard","Special",
					   "Teredo","Orchid","Documentation","Private") 			  if($s_ip_version eq 6);
# If not file input is given exit
unless($s_file)
{
	print "Usage: ".$0." --files file1,file2,file3, ... ,file[n] --delimeter [delimeter character] --ip-version [4|6] \n";
	exit();
}

# Get the files into an array
@a_files = split(',',$s_file);

# For each file into the array
foreach my $s_file (@a_files)
{
	unless (-e $s_file)	# Inform the user that the file does not exists and go to next
	{
		print "ERROR: ".$s_file." does not exist\n";
		next;
	}

	unless (-r $s_file) # Inform the user that the file cannot be read and go to next
	{
		print "ERROR: ".$s_file." cannot be read, check file permissions\n";
		next;
	}

	unless (-T $s_file) # Inform the user that the file is not a text file and go to next
	{
		print "ERROR: ".$s_file." is not a text file\n";
		next;
	}

	open(my $s_filehandler, $s_file);	# Open the file and assign a file handler
	print "INFO: parsing ".$s_file."\n";
	print "\n";
	
	my $s_line_counter = 0;				# Count lines, for user output
	
	while (<$s_filehandler>) 			# Read the file line by line until EOF
	{
		$s_line_counter++;								# +1 for each line
		my $s_temp_text = $_;							# A dirty hack to get a copy of the current line
		
		my @a_delimeted_text = split($s_delimeter,$_); # split the line using the delimiter 
		foreach my $s_text (@a_delimeted_text)
		{
			chomp($s_text);							      # Remove \n 
			$s_text =~ s/^\s+|\s+$//g;				# Remove leading and ending spaces
			my $ip = new Net::IP($s_text);		# Get the IP object

			if($ip && $ip->version() eq $s_ip_version &&  !($ip->ip() ~~ @a_old_ips))
			{	
				my @a_data;
				push(@a_data,'NA'); eval { my $s_temp = $ip->ip(); 			    if ($s_temp) { pop(@a_data); push(@a_data,$ip->ip());}};
				push(@a_data,'NA'); eval { my $s_temp = $ip->iptype(); 		  if ($s_temp) { pop(@a_data); push(@a_data,$ip->iptype());}};
				push(@a_data,'NA'); eval { my $s_temp = $ip->short(); 		  if ($s_temp) { pop(@a_data); push(@a_data,$ip->short());}};
				push(@a_data,'NA'); eval { my $s_temp = $ip->binip(); 		  if ($s_temp) { pop(@a_data); push(@a_data,$ip->binip());}};
				push(@a_data,'NA'); eval { my $s_temp = $ip->intip(); 		  if ($s_temp) { pop(@a_data); push(@a_data,$ip->intip());}};
				push(@a_data,'NA'); eval { my $s_temp = $ip->mask(); 		    if ($s_temp) { pop(@a_data); push(@a_data,$ip->mask());}};
				push(@a_data,'NA'); eval { my $s_temp = $ip->size(); 		    if ($s_temp) { pop(@a_data); push(@a_data,$ip->size());}};
				push(@a_data,'NA'); eval { my $s_temp = $ip->last_ip(); 	  if ($s_temp) { pop(@a_data); push(@a_data,$ip->last_ip());}};
				push(@a_data,'NA'); eval { my $s_temp = $ip->prefixlen(); 	if ($s_temp) { pop(@a_data); push(@a_data,$ip->prefixlen());}};
		  				
				if($ip->version() eq 4)
				{
					if(is_loopback_ipv4($ip->ip()))   {push(@a_data,"Yes");} else {push(@a_data,"No");}
					if(is_linklocal_ipv4($ip->ip()))  {push(@a_data,"Yes");} else {push(@a_data,"No");}
					if(is_multicast_ipv4($ip->ip()))  {push(@a_data,"Yes");} else {push(@a_data,"No");}
					if(is_unroutable_ipv4($ip->ip())) {push(@a_data,"Yes");} else {push(@a_data,"No");}
					if(is_testnet_ipv4($ip->ip()))    {push(@a_data,"Yes");} else {push(@a_data,"No");}
					if(is_anycast_ipv4($ip->ip()))    {push(@a_data,"Yes");} else {push(@a_data,"No");}
				}
				else
				{
					if(is_loopback_ipv6($ip->ip()))   		{push(@a_data,"Yes");} else {push(@a_data,"No");}
					if(is_linklocal_ipv6($ip->ip()))     	{push(@a_data,"Yes");} else {push(@a_data,"No");}
					if(is_multicast_ipv6($ip->ip()))     	{push(@a_data,"Yes");} else {push(@a_data,"No");}
					if(is_ipv4_mapped_ipv6($ip->ip()))		{push(@a_data,"Yes");} else {push(@a_data,"No");}
					if(is_discard_ipv6($ip->ip()))    		{push(@a_data,"Yes");} else {push(@a_data,"No");}
					if(is_special_ipv6($ip->ip()))    		{push(@a_data,"Yes");} else {push(@a_data,"No");}
					if(is_teredo_ipv6($ip->ip()))     		{push(@a_data,"Yes");} else {push(@a_data,"No");}
					if(is_orchid_ipv6($ip->ip()))     		{push(@a_data,"Yes");} else {push(@a_data,"No");}
					if(is_documentation_ipv6($ip->ip())) 	{push(@a_data,"Yes");} else {push(@a_data,"No");}
					if(is_private_ipv6($ip->ip()))       	{push(@a_data,"Yes");} else {push(@a_data,"No");}
				}
				$tb->add(@a_data);
				push(@a_old_ips,$ip->ip());
			}
		}
	}
	close($s_filehandler);
	print $tb;
	@a_old_ips = undef;
	$tb->clear();
	print "\n";
}
