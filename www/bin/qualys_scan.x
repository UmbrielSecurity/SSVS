#!/bin/bash
#
# Qualys API v2 Scan script
# Author: @UmbrielSecurity
# Date: 2015/10/20
# 
STDERR=/var/log/qualys_scan.err
STDOUT=/var/log/qualys_scan.log
COOKIEJAR=/var/www/bin/cookiejar.txt
IP_ADDR=$1
EMAIL=$2
DATE=`date +%y%m%d-%H%M%S` 
SCAN_DIR=/var/www/bin/qualys_scans
SCAN_TITLE="${DATE}_${EMAIL}_${IP_ADDR}"
SCANNER_NAME="SJ1"
OPTION_ID="811917"
CRED_FILE=/etc/qualys_credentials

# Parse the credentials file for username/password
if [ -f ${CRED_FILE} ]; then
  QUALYS_USER=`cat /etc/qualys_credentials | cut -d: -f1`
  QUALYS_PASS=`cat /etc/qualys_credentials | cut -d: -f2`
else
  echo "Credentials file not found.  Terminating"
  exit 1
fi

# Usage information
usage () {
  echo "Usage"
  echo ""
  echo "./qualys_scan.php ip_address email_address"
  echo ""
  exit 0
}

# Graceful log out and disconnect.
qualys_logout () {
  echo -n "Logging out of Qualysguard... "
  AUTH_OUTPUT=`curl -H "X-Requested-With: Curl Sample" -b ${COOKIEJAR}  -d "action=logout" "https://qualysapi.qualys.com/api/2.0/fo/session/" 2>> ${STDERR}`
  AUTH_RESULT=`echo ${AUTH_OUTPUT} | grep "<TEXT>" | sed -e 's/.*<TEXT>\(.*\)<\/TEXT>.*/\1/'`
  if [ "x${AUTH_OUTPUT}" = "xLogged out" ]; then
    echo Success!
  else
    # No logout required here... since we failed to logout.
    echo Failure!
    exit 1
  fi
  echo "Removing crumbs from the cookie jar."
  > ${COOKIEJAR}
  exit 0
}

# Sterilize EMAIL address (drop anything that's not an alphanumeric or @ or .)
EMAIL=${EMAIL//[^a-zA-Z0-9@.]/}

# Check for email, die if missing.
if [ -z ${EMAIL} ]; then
  echo "Missing argument(s)"
  echo ""
  usage
  exit 1
fi

# Sterilize IP address (drop anything that's not an numeric or .)
IP_ADDR=${IP_ADDR//[^0-9.]/}

# Check for ip address, die if missing.
if [ -z ${IP_ADDR} ]; then
  echo "Missing argument(s)"
  echo ""
  usage
  exit 1
fi

echo -n "Authenticating to Qualysguard... "
AUTH_OUTPUT=`curl -H "X-Requested-With: Curl " -c ${COOKIEJAR} -d "action=login&username=${QUALYS_USER}&password=${QUALYS_PASS}" "https://qualysapi.qualys.com/api/2.0/fo/session/" 2>> ${STDERR}`
AUTH_RESULT=`echo ${AUTH_OUTPUT} | grep "<TEXT>" | sed -e 's/.*<TEXT>\(.*\)<\/TEXT>.*/\1/'`
if [ "x${AUTH_RESULT}" = "xLogged in" ]; then
  echo Success!
  echo -n "Attempting to launch a scan ${SCAN_TITLE}... "
  SCAN_OUTPUT=`curl -H "X-Requested-With: Curl" -b ${COOKIEJAR} -X "POST" -d "action=launch&scan_title=${SCAN_TITLE}&ip=${IP_ADDR}&option_id=${OPTION_ID}&iscanner_name=${SCANNER_NAME}" "https://qualysapi.qualys.com/api/2.0/fo/scan/" 2>> ${STDERR}`
  SCAN_RESULT=`echo ${SCAN_OUTPUT} | grep "<CODE>" | sed -e 's/.*<CODE>\(.*\)<\/CODE>.*/\1/'`
  if [ "x${SCAN_RESULT}" = "x" ]; then
    echo Success!
    SCAN_REF=`echo ${SCAN_OUTPUT} | grep "<VALUE>" | sed -e 's/.*<VALUE>\(scan\/[0-9\.]*\)<\/VALUE>.*/\1/'`
    #SCAN_REF=`echo ${SCAN_OUTPUT} | grep "<VALUE>" | sed -e 's/.*<VALUE>\(scan\/[0-9]{10}\.[0-9]{5}\)<\/VALUE>.*/\1/'`
    echo Your scan reference is: ${SCAN_REF}
    echo ${SCAN_TITLE} > ${SCAN_DIR}/`echo ${SCAN_REF} | sed -e 's/scan\///'`
  else
    echo Failure!
    echo ${SCAN_OUTPUT}
    qualys_logout
    exit 1
  fi
else
  echo Failure!
  echo ${AUTH_OUTPUT}
  qualys_logout
fi

# We made it here without errors, so let's gracefully exit.
qualys_logout
