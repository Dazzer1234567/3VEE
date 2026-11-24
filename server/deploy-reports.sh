#!/bin/sh
# Put the reports service on the EliteDesk, or update it. From C:\0_CODE\3VEE_WEBSITE in Git Bash:
#
#     sh server/deploy-reports.sh
#
# Adds: user masterdaw-reports, /opt/masterdaw-reports, /srv/masterdaw-reports,
# /etc/masterdaw-reports.env (only if missing), masterdaw-reports.service on
# 127.0.0.1:8767, /usr/local/bin/mdaw-reports, and two locations in the nginx
# site (/api/reports/ and the internal /_report_fixes/), above /api/ so the
# longer prefix wins. The nginx site is backed up to 3vee.bak-reports first and
# put back if nginx -t fails. Running it again only updates reports.py.
set -e
cd "$(dirname "$0")"
tar -cf - reports.py masterdaw-reports.service reports.env.example mdaw-reports nginx-reports.conf |
ssh elitedesk 'rm -rf /tmp/rep && mkdir /tmp/rep && tar -xf - -C /tmp/rep && cd /tmp/rep && sudo sh -e -c "
id masterdaw-reports >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin masterdaw-reports
install -d -o root -g root -m 755 /opt/masterdaw-reports
install -d -o masterdaw-reports -g masterdaw-reports -m 750 /srv/masterdaw-reports
install -m 644 reports.py /opt/masterdaw-reports/reports.py
install -m 644 masterdaw-reports.service /etc/systemd/system/masterdaw-reports.service
install -m 755 mdaw-reports /usr/local/bin/mdaw-reports
[ -f /etc/masterdaw-reports.env ] || install -m 600 reports.env.example /etc/masterdaw-reports.env
usermod -aG masterdaw-reports www-data
systemctl daemon-reload
systemctl enable masterdaw-reports
systemctl restart masterdaw-reports
if ! grep -q /api/reports/ /etc/nginx/sites-available/3vee; then
  cp /etc/nginx/sites-available/3vee /etc/nginx/sites-available/3vee.bak-reports
  awk \"/# MASTERDAW beta sign-up/ { while ((getline l < \\\"nginx-reports.conf\\\") > 0) print l } { print }\" /etc/nginx/sites-available/3vee.bak-reports > /etc/nginx/sites-available/3vee
  if nginx -t; then systemctl reload nginx; else cp /etc/nginx/sites-available/3vee.bak-reports /etc/nginx/sites-available/3vee; echo nginx rolled back; exit 1; fi
fi
"
sleep 1
systemctl is-active masterdaw-reports
curl -s -H "Host: 3vee.app" http://127.0.0.1/api/reports/health; echo'
echo "Check from outside: curl https://3vee.app/api/reports/health"
