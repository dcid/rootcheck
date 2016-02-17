# Install script for rootcheck
# Daniel B. Cid <dcid@sucuri.net>
# 
# http://dcid.me/rootcheck

TMPRKPATH="/tmp/rootcheck"

cd src;

    echo "CEXTRA= -DDEFAULTDIR=\\\"${TMPRKPATH}\\\"" >> ./Config.OS
    echo "DIR=\"${TMPRKPATH}\"" > LOCATION

    echo "--> Starting rootcheck compilation. It will just take a minute..."
    echo ""
    sleep 2;
    ./Makeall rootcheck
    mv rootcheck.sh ../rootcheck
    chmod +x ../rootcheck
    echo "--> Just run './rootcheck' to execute it."
    echo "--> And wait for the results (Should not take long)"
    echo ""
    echo "* You can find more information about rootcheck here: http://dcid.me/rootcheck"
    echo "  or at our github: https://github.com/dcid/rootcheck/"
    echo ""
    mkdir ${TMPRKPATH} >/dev/null 2>&1
    cp -pr ./etc ${TMPRKPATH}
    cp -pr ./etc/rules ${TMPRKPATH}
    wget --timeout=10 -4 --quiet http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
    gunzip -fd GeoLiteCity.dat.gz >/dev/null 2>&1
    ls GeoLiteCity.dat > /dev/null 2>&1
    if [ $? = 0 ]; then
        mv GeoLiteCity.dat ${TMPRKPATH}/etc/
    fi
    mkdir -p ${TMPRKPATH}/queue/fts/fts-queue


