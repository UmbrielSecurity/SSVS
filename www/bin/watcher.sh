#!/bin/bash
#
# Background Qualys scan watcher.  This script creates reports for completed scans and sends emails with the results.
# Author: @UmbrielSecurity
# Date: 2015/10/20
# Location: 
#
STDERR=/var/log/watcher/watcher-app.err
STDOUT=/var/log/watcher/watcher-app.log
COOKIEJAR=/var/www/bin/cookiejar.txt
SCAN_DIR=/var/www/bin/qualys_scans
RPT_DIR=/var/www/bin/qualys_reports
RPT_TEMPLATE_ID=1878897
RPT_FORMAT=pdf
FROM_EMAIL="vscan-noreply@example.com"
CRED_FILE=/etc/qualys_credentials

# Parse the credentials file for username/password
if [ -f ${CRED_FILE} ]; then
  QUALYS_USER=`cat /etc/qualys_credentials | cut -d: -f1`
  QUALYS_PASS=`cat /etc/qualys_credentials | cut -d: -f2`
else
  echo "Credentials file not found.  Terminating"
  exit 1
fi

qualys_logout () {
  echo -n "Logging out of Qualysguard... "
  `curl -H "X-Requested-With: Curl" -b ${COOKIEJAR}  -d "action=logout" "https://qualysapi.qualys.com/api/2.0/fo/session/" 2>> ${STDERR} >> ${STDOUT}`
  if [ $? = 0 ]; then
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

echo -n "Authenticating to Qualysguard... "
AUTH_OUTPUT=`curl -H "X-Requested-With: Curl"  -c ${COOKIEJAR} -d "action=login&username=${QUALYS_USER}&password=${QUALYS_PASS}" "https://qualysapi.qualys.com/api/2.0/fo/session/" 2>> ${STDERR}`
if [ $? = 0 ]; then
  echo Success!
  for s in `ls ${SCAN_DIR}`; do
    SCAN_REF="scan/${s}"
    SCAN_LIST_OUTPUT=`curl -H "X-Requested-With: Curl" -b ${COOKIEJAR} "https://qualysapi.qualys.com/api/2.0/fo/scan/?action=list&scan_ref=${SCAN_REF}&show_ags=1&show_op=1" 2>> ${STDERR}`
    SCAN_STATUS=`echo ${SCAN_LIST_OUTPUT} | grep "<STATE>" | sed -e 's/.*<STATE>\([a-zA-Z]*\)<\/STATE>.*/\1/'`
    echo "Scan (${SCAN_REF}) status: ${SCAN_STATUS}"
    if [ x${SCAN_STATUS} = "xFinished" ]; then
      RPT_TITLE=`cat ${SCAN_DIR}/${s}`
      RPT_EMAIL=`echo ${RPT_TITLE} | cut -d_ -f2`
      echo -n "Creating report..."
      CREATE_RPT_OUTPUT=`curl -H "X-Requested-With: Curl" -d "action=launch&report_type=Scan&report_title=${RPT_TITLE}&report_refs=${SCAN_REF}&template_id=${RPT_TEMPLATE_ID}&output_format=${RPT_FORMAT}" -b ${COOKIEJAR} "https://qualysapi.qualys.com/api/2.0/fo/report/" 2>> ${STDERR}`
      if [ $? = 0 ]; then
        RPT_ID=`echo ${CREATE_RPT_OUTPUT} | grep "<VALUE>" | sed -e 's/.*<VALUE>\([0-9]*\)<\/VALUE>.*/\1/'`
        echo "Success!"
        echo "Report ID: ${RPT_ID}"
        RPT_STATE="Unknown"
        while [ x${RPT_STATE} != "xFinished" ]; do
          sleep 10 
          echo -n "Looking for state of ${RPT_ID}... "
          RPT_STATE_OUTPUT=`curl -H "X-Requested-With: Curl" -b ${COOKIEJAR} "https://qualysapi.qualys.com/api/2.0/fo/report/?action=list&id=${RPT_ID}" 2>> ${STDERR}`
          # Needs error handling
          RPT_STATE=`echo ${RPT_STATE_OUTPUT} | grep "<STATE>" | sed -e 's/.*<STATE>\([a-zA-Z]*\)<\/STATE>.*/\1/'`
          echo ${RPT_STATE}
        done
        RPT_FILE="${RPT_DIR}/${RPT_TITLE}.${RPT_FORMAT}"
        echo -n "Downloading ${RPT_FORMAT} report... "
        `curl -H "X-Requested-With: Curl" -b ${COOKIEJAR} "https://qualysapi.qualys.com/api/2.0/fo/report/?action=fetch&id=${RPT_ID}" 2>> ${STDERR} > ${RPT_FILE}`
        if [ $? = 0 ]; then
           echo Success!
           echo Report location: ${RPT_FILE}
           echo ${RPT_EMAIL}
           echo "Please find attached your vulnerability scan report." | mail ${RPT_EMAIL} -aFrom:"Vulnerability Scanner <${FROM_EMAIL}>" -s "Vulnerability Scan Report ${RPT_TITLE}" -A ${RPT_FILE}
           echo "Removing report ${RPT_FILE}."
           rm ${RPT_FILE}
           echo "Removing scan ${SCAN_REF}."
           rm ${SCAN_DIR}/${s}
        else
           echo Failure!
           qualys_logout
        fi
      else
        echo Failure!
        echo ${CREATE_RPT_OUTPUT}
        qualys_logout
    fi
    else
	echo "Skipping - scan not finished."
    fi
  done
else
  echo Failure!
  echo ${AUTH_OUTPUT}
  qualys_logout
fi
qualys_logout
