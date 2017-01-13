<html>
	<head>
		<title>TVM Self-Service Vulnerability Scanner</title>
		<meta http-equiv="content-type" content="text/html; charset=utf-8" />
		<meta name="description" content="" />
		<meta name="keywords" content="" />
		<link href='http://fonts.googleapis.com/css?family=Roboto:400,100,300,700,500,900' rel='stylesheet' type='text/css'>
		<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.11.0/jquery.min.js"></script>
		<script src="js/skel.min.js"></script>
		<script src="js/skel-panels.min.js"></script>
		<script src="js/init.js"></script>
		<noscript>
			<link rel="stylesheet" href="css/skel-noscript.css" />
			<link rel="stylesheet" href="css/style.css" />
			<link rel="stylesheet" href="css/style-desktop.css" />
		</noscript>
	</head>
	<body>

	<!-- Main -->
		<div id="main">
			<div id="content" class="container">
				<section>
					<header>
						<div align='center'><h2>Self-Service Vulnerability Scanner</h2></div>
						<div align='center'><span class="byline">(Proof-of-Concept: <STRONG>Not for Production Use)</STRONG></span></div>
					</header>
<script type="text/javascript">
function clearResetReadOnlyField()
{
  var state=document.getElementById("hidden");
  state.value = " ";
  var state=document.getElementById("readonly");
  state.value = " ";
}
</script>
<STYLE>
input.clear[type=text],
input.clear[type=text]:hover,
input.clear[type=text]:focus,
input.clear[type=text]:active
{
    border: 0;
    outline: none;
    outline-offset: 0;
}
</STYLE>
<FORM name='form' action='<?php echo htmlspecialchars($_SERVER["PHP_SELF"]);?>' method='post'>
<DIV ALIGN='center'>
<TABLE>
<TR><TD>Scan Engine</TD><TD><INPUT TYPE='radio' name='scan_engine' value="QualysGuard" CHECKED><IMG SRC='images/qualys_logo.png' WIDTH='100'/>
                            <INPUT TYPE='radio' name='scan_engine' value="Nexpose"><IMG SRC='images/nexpose_logo.png' WIDTH='100'/></TD></TR>
<TR><TD>IP Address</TD><TD><input type='text' name='ip_addr'></TD></TR>
<TR><TD>Email Address</TD><TD><input type='text' name='email' value='@example.com'></TD></TR>
</TABLE>
<?php

if (isset($_POST["ip_addr"])) {
  if ( preg_match("/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/",$_POST["ip_addr"])) {
    $ip_addr = test_input($_POST["ip_addr"]);
  } else {
    $ip_addr="Bad IPv4 IP address";
  }
}
if (isset($_POST["email"])) {
  #if ( preg_match("/^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/",$_POST["email"])) {
  if ( preg_match("/^[a-zA-Z0-9_.+-]+@example.com$/",$_POST["email"])) {
    $email = test_input($_POST["email"]);
  } else {
    $email="Bad email address";
  }
}
if (isset($_POST["status"])) {
  $status = test_input($_POST["status"]);
}

function test_input($data) {
  $data = trim($data);
  $data = stripslashes($data);
  $data = htmlspecialchars($data);
  return $data;
}

echo "<INPUT type='submit' name='scan' value='Scan!'>";
echo "<INPUT type='reset' name='reset' onClick='clearResetReadOnlyField();return false;'>";
echo "<P>";
echo "</DIV>";
if (($ip_addr != "Bad IPv4 IP address") && ($email != "Bad email address")) {
  if (isset($ip_addr) && isset($email)) {
    $status = "Scan started on $ip_addr.  Email will be sent to $email upon completion.";
  }
  echo "<input id='readonly' class='good_status' type='text' readonly name='statusbox' value='$status' size='80'>";

  $pid=getmypid();
  if ((!empty($ip_addr)) && (!empty($email)) && !empty($status)) {
    if ($_POST["scan_engine"] == "Nexpose") {
      $command="nohup /usr/bin/ruby /var/www/bin/scan_ip_and_email.rb ".escapeshellcmd($ip_addr)." ".escapeshellcmd($email)." > /tmp/run-$pid.log 2>&1 &";
      pclose(popen($command,"r"));
      $ip_addr='';
      $email='';
      $status='';
    } else if ($_POST["scan_engine"] == "QualysGuard") {
      $command="nohup /bin/bash /var/www/bin/qualys_scan.x ".escapeshellcmd($ip_addr)." ".escapeshellcmd($email)." > /tmp/run-$pid.log 2>&1 &";
      pclose(popen($command,"r"));
      $ip_addr='';
      $email='';
      $status='';
    } else {
     $status="Bad scan engine - No scan has been started.";
    }
  }
} else {
  $status="Bad IPv4 IP address or email address provided  No scan has been started.";
  echo "<input id='readonly' class='bad_status' type='text' readonly name='statusbox' value='$status' size='80'>";
}

echo "<input id='hidden' type='hidden' name='status' value='$status'>";
?>
<UL>
<LI>Provide and IP address to be scanned for vulnerabilities and an email address which should sent the scan report, and then click Scan!.<BR>
<LI>Report delivery time depends on scanner load.  Normal delivery time is between 10 and 90 minutes.
</UL>
</FORM>


				</section>
			</div>
		</div>
	<!-- /Main -->

	<!-- Copyright -->
		<div id="copyright">
			<div class="container">
			Brought to you by the Threat &amp; Vulnerability Management team.
			</div>
		</div>


	</body>
</html>
