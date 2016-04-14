CspBuilder is a web-based collector for Content Security Policy violation reports with advanced analytics and policy generation features, supporting CSP Level 2 and some extensions.

# Licensing
CspBuilder is distributed with multiple licenses:

* Usage for personal purposes, by educational and other non-profit organisations is licensed based on the attached GPLv3 license.
* License for usage within for-profit organisations is $150 per year
* Distribution, repackaging and sale of services based on CspBuilder is licensed on per-case basis (please contact for details).

# Operations
Adding a new website is a matter of just one click on the main page. Database structures are initialized and a long number is assigned, that will uniquely identify CSP reports sent by your website. CspBuilder also outputs HTTP header for CSP with the identifier, ready to paste to most popular web servers:

```
Content-Security-Policy-Report-Only: report-uri //cspbuilder.info/report/384747463478960510/noscripteval/;
    connect-src 'none' ; child-src 'none' ; font-src 'none' ; form-action 'none' ; frame-ancestors 'none' ;
    frame-src 'none' ; img-src 'none' ; media-src 'none' ; object-src 'none' ; script-src 'none' ;
    style-src 'none' ; default-src 'none' ; strict-mixed-content-checking; reflected-xss filter;
    referrer origin-when-cross-origin; 
```
The CSP policy specified in the header is very restrictive &mdash; to be precise, it blocks *everything*. On first load of your page with the new header, your browser will send a number of CSP violation reports to CspBuilder, leaving trace for each CSP-regulated resource it loads. CspBuilder aggregates these reports and presents a pre-processed list of origins for you to allow or disallow.

Finally, CspBuilder presents a policy allowing all of the origins you allowed. The process can be iterative so if any further resources are blocked, you can whitelist them as well.


# Architecture
CspBuilder uses [CouchDB](https://couchdb.apache.org/) as the primary data storage.  The frontend is implemented using [AngularJS](https://angularjs.org/) and  speaks to a server-side API implemented in [Python 3](https://docs.python.org/3/) using [Falcon web framework](http://falconframework.org/). The latter runs under [uWSGI](http://uwsgi-docs.readthedocs.org/en/latest/) application server behind a [nginx](http://nginx.org) web server. To get an idea of the look and feel check the public instance available at [CspBuilder.info](https://cspbuilder.info/static/#/main/).

The backend is composed of three Python services:
* `api.py` &mdash; the Falcon web API responsible for receiving CSP violation reports and responding to frontend AJAX calls
* `classify.py` &mdash; processes incoming CSP reports and classifies them according to policies configured by users
* `retro.py` &mdash; on change of policy by user, retrospectively reclassify existing reports

During normal operations all three services should be running, e.g. as `init` or `systemd` services. Each can be also run manually from command line, optionally with `debug` option for verbose operations.

# Installation
First create a dedicated user `cspbuilder`. Then:
```
sudo apt-get install python3 couchdb git python-all-dev libpcre3-dev default-jre geoip-database-contrib
git clone https://github.com/kravietz/cspbuilder.git
virtualenv -p python3 cspbuilder
cd cspbuilder
. bin/activate
pip install Flask certifi jsmin netaddr requests uWSGI yuicompressor uwsgitop pip ujson
pip install git+https://github.com/kravietz/py-couchdb.git
```
At this stage you should be able to run each of the services from command line, ensure they don't throw an exception and terminate them with Ctrl-C:
```
python api.py debug
python retro.py debug
python classify.py debug
```
The web sevice `api.py` is *not* running from command-line in production but uses high-performance application server [uWSGI](http://uwsgi-docs.readthedocs.org/en/latest/) instead. Test if it starts correctly:
```
uwsgi uwsgi.ini
```
If everything works fine, install the `initctl` tasks:
```
cp initctl/*.conf /etc/init
initctl reload-configuration
initctl start retro
initctl start classify
initctl start cspbuilder
tail -f /var/log/upstart/{retro,classify,cspbuilder}.conf
```
The `nginx` subdirectory contains Nginx configuration currently used by [CspBuilder.info](https://cspbuilder.info). You will need to customize the domain and TLS certificates, the rest should work out of the box.

# Bugs
Please report any bugs [here](https://github.com/kravietz/cspbuilder/issues). Currently known bugs or limitations:
* Yes, it requires a working JRE, as silly as it sounds. It's required by `yuicompressor` library, but this will be soon replaced by `jsmin`.
