#!/usr/bin/env ruby
#-----------------------
# Proof-of-concept self-service Nexpose vulnerability scan automation 
# Author: @UmbrielSecurity
# Date  : 2015/05/07
#-----------------------
#
require 'rubygems'
require 'nexpose'
require 'net/smtp'
require 'pp'
include Nexpose

# Connection parameters
host = "nexpose.example.com"
from_name = "Vulnerability Scanner"
from_email = "vscan-noreply@example.com"
smtp = "mail.example.com"
port = "3780"
user = "nexpose_admin"
pass = "nexpo$ePa5sw0rd"
report_path = "/tmp"

# Other paramenters
site_id = 1

# Connect and authenticate
begin
  nsc = Nexpose::Connection.new(host, user, pass, port)
  nsc.login
	
  rescue ::Nexpose::APIError => e
  $stderr.puts ("Connection failed: #{e.reason}")
  exit(1)
end

# Get the target IP from the arguments
ip=ARGV[0]
email=ARGV[1]
site=Site.load(nsc,site_id)

# Add the IP to the default site and save it.
site.add_ip(ip);
site.save(nsc)

# Scan the IP
ips = [ip]
scan=nsc.scan_ips(site_id,ips)
puts "Starting Scan (id: #{scan.id})"

print "Scan is in progress ."
begin
  sleep(30)
  print "."
  status = nsc.scan_status(scan.id)
end while status == Scan::Status::RUNNING
puts ". Done!"

# Generate a report for this scan.
filename="vscan-#{ip}.pdf"
fullfilename="#{report_path}/#{filename}"
puts "Generating Report (#{fullfilename})"
adhoc = AdhocReportConfig.new('prioritized-remediations-with-details', 'pdf', site_id)
adhoc.add_filter('scan',scan.id)
data = adhoc.generate(nsc)
File.open(fullfilename, 'w') { |file| file.write(data) }
nsc.logout

# Create attachment
filecontent = File.read(fullfilename)
encodedcontent = [filecontent].pack("m")

marker = "AUNIQUEMARKER"

body = "Please find attached your vulnerability scan of #{ip}."

part1 = "From: #{from_name} <#{from_email}>
To: <#{email}>
Subject: Vulnerability Scan Results (#{ip})
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=#{marker}
--#{marker}"

part2 =<<EOF

Content-Type: text/plain
Content-Transfer-Encoding:8bit

#{body}
--#{marker}
EOF

part3 =<<EOF
Contet-Type: multipart/mixed; name=\"#{filename}\"
Content-Transfer-Encoding:base64
Content-Disposition: attachment; filename="#{filename}"

#{encodedcontent}
--#{marker}--
EOF

mailtext = part1 + part2 + part3

puts "Attempting to send email..."
puts "#{mailtext}"
begin
  Net::SMTP.start(smtp) do |smtp|
    smtp.sendmail(mailtext,from_email,email)
  end
rescue Exception => e
  print "Exception occured: " + e
end
