/**
 * Created by pawelkrawczyk on 04/09/2014.
 */

"use strict";

/*
    For blocked_uri like 'http://webcookies.info/dajaxice/register_site.status/'
    returns array of
    ['http://webcookies.info/dajaxice/register_site.status','http://webcookies.info/dajaxice',http://webcookies.info']
 */
function gen_uri_variants(blocked_uri) {
    console.log('gen_uri_variants');
    var variants = [];
    blocked_uri = blocked_uri.split('?')[0];
    var parts = blocked_uri.split('/');

    for (var i = parts.length; i >= 3; i--) {
        variants.push(parts.slice(0,i).join('/'));
    }
    variants.reverse();
    if(variants.length > 3) {
        // get only a few shortest variants, more is too much
        variants = variants.slice(0, 5);
    }
    console.log('variants=' + variants);
    return {'message':'Choose URI pattern to allow. Shorter patterns will allow all the longer patterns as well.', 'sources':variants};

}

function null_url_guesswork(csp) {
    console.log('null_url_guesswork');

    var blocked_type = csp['violated-directive'].split(' ')[0];
    var violated_directive = csp['violated-directive'];
    var eval_first = ['\'unsafe-eval\'', '\'unsafe-inline\''];
    var inline_first = ['\'unsafe-inline\'', '\'unsafe-eval\''];

    // styles
    if (blocked_type === 'style-src') {

        // check if inline was already allowed on blocked page
        if (violated_directive.indexOf('unsafe-inline') > 0) {
            // yes, it must have been eval()
            return {'message':'In CSP 1.0 there is no good way to distinguish eval() and inline reports, but in this case we guess you should allow eval().', 'sources':eval_first};
        } else {
            // no, try inline first
            return {'message':'In CSP 1.0 there is no good way to distinguish eval() and inline reports, but in this case we guess you should allow inline.', 'sources':inline_first};
        }

    // scripts
    } else if (blocked_type === 'script-src') {

        // the same heuristics as above
        if (violated_directive.indexOf('unsafe-inline') > 0) {
            return {'message':'In CSP 1.0 there is no good way to distinguish eval() and inline reports, but in this case we guess you should allow eval().', 'sources':eval_first};
        } else {
            return {'message':'In CSP 1.0 there is no good way to distinguish eval() and inline reports, but in this case we guess you should allow inline.', 'sources':inline_first};
        }

    // something else?
    } else {
        console.warn('Unrecognized \'null\' source for type ' + blocked_type + ' in:' + JSON.stringify(csp));
    }

    // this might be for object-src where inline makes more sense...
    return {'message':'Normally this directive should not generate inline and/or eval() reports, please inspect it carefully before allowing.', 'sources':inline_first};
} // null_url_guesswork

// for 'http://url.com:80/path/path' return 'http://url.com:80'
function base_uri(uri) {
    return uri.match(/^(https?:\/\/[^?#/]+)/)[1];
}

// convert blocked-uri from CSP report to a statement that can be used in new policy
function source_to_policy_statement(csp) {
    console.log('source_to_policy_statement');

    var blocked_uri = csp['blocked-uri'];
    var document_uri = csp['document-uri'];

    // for 'data:image/png' return 'data:'
    if (blocked_uri.lastIndexOf('data', 0) === 0) {
        return {'message':null, 'sources':['data:']};
    }

    // for 'http://url.com:80/path/path' return 'http://url.com:80/'
    if (/^https?:\/\/[a-zA-Z0-9.:-]+/.test(blocked_uri)) {

        // extract base website URLs
        var blocked_site = base_uri(blocked_uri);
        var document_site = base_uri(document_uri);

        // check if blocked URI was not in the same domain as CSP website
        if (blocked_site === document_site) {
            // yes, return 'self'
            return {'message':null, 'sources':['\'self\'']};
        } else {
            // no, return URI variants
            return gen_uri_variants(blocked_uri);
        }
    }

    // for null URIs we need to do some guesswork and return variants
    if (blocked_uri === 'null') {
        return null_url_guesswork(csp);
    }

    console.log('policy statement ' + blocked_uri + ' for ' + JSON.stringify(csp));

    return  {'message':null, 'sources':[blocked_uri]};
} // source_to_policy_statement


 // TODO: add various types from https://www.owasp.org/index.php/Content_Security_Policy
        // https://w3c.github.io/webappsec/specs/content-security-policy/#csp-request-header
        function ror_generator() {
            // TODO: https://github.com/twitter/secureheaders
            return null;
        }

        function django_generator() {
            // TODO: https://github.com/kravietz/django-security
            return null;
        }

function empty_approved_list() {
    var approved_list = [];
            // report-uri and default-src will be added automatically
            var types = ['connect-src', 'child-src', 'font-src', 'form-action', 'frame-ancestors', 'frame-src',
                'img-src', 'media-src', 'object-src', 'script-src', 'style-src'];
            types.forEach(function (type) {
                approved_list.push(
                    {'type': type, 'sources': {'\'none\'': true}}
                );
            });
    return approved_list;
} // empty_approved_list

function default_csp_config() {
   return {
            'enforce': false,
            'default': false, // TODO: this setting should be taken into account by policy generator
            'referrer': 'none',
            'reflected_xss': 'block',
            'header_format': 'standard',
            'plugin_types': [
                'application/pdf',
                'application/x-shockwave-flash',
                'application/java'
            ],
            'plugin_choice': []
        } ;
} // default_csp_config

function policy_generator(owner_id, format, csp_config, approved_list) {
    console.log('policy_generator owner_id=' + owner_id);

    // select CSP header format
            switch (csp_config.header_format) {
                case 'xcsp':
                    var header = 'X-Content-Security-Policy';
                    break;
                case 'webkit':
                    var header = 'X-WebKit-CSP';
                    break;
                default:
                    var header = 'Content-Security-Policy';
            }

            // append RO if enforcenement is not selected
            if ( ! csp_config.enforce) {
                header += '-Report-Only';
            }

            var policy = 'report-uri http://cspbuilder.info/report/' + owner_id + '/; ';

            for (var i = 0; i < approved_list.length; i++) {
                var src_list = approved_list[i];
                policy += src_list.type + ' ';
                var sources = Object.keys(src_list.sources);
                for (var j = 0; j < sources.length; j++) {
                    if (src_list.sources[sources[j]]) {
                        policy += ' ' + sources[j];
                    }
                }
                policy += '; ';
            }

            // TODO: not working currently
            // https://w3c.github.io/webappsec/specs/content-security-policy/#directive-reflected-xss
            switch(csp_config.reflected_xss) {
                case 'block':
                    policy += 'reflected-xss block; ';
                    break;
                case 'filter':
                    policy += 'reflected-xss filter; ';
                    break;
                case 'allow':
                    policy += 'reflected-xss allow; ';
                    break;
            }

            // https://w3c.github.io/webappsec/specs/content-security-policy/#directive-referrer
            switch(csp_config.referrer) {
                case 'no-referrer':
                    policy += 'referrer no-referrer; '
                    break;
                case 'no-referrer-when-downgrade':
                    policy += 'referrer no-referrer-when-downgrade; '
                    break;
                case 'origin':
                    policy += 'referrer origin; '
                    break;
                case 'origin-when-cross-origin':
                    policy += 'referrer origin-when-cross-origin; '
                    break;
                case 'unsafe-url':
                    policy += 'referrer unsafe-url; '
                    break;
                default: // none
                    // do nothing, do not add the directive
            }

            // https://w3c.github.io/webappsec/specs/content-security-policy/#directive-plugin-types
            if(csp_config.plugin_choice.length) {
                policy += 'plugin-types ';
                for (var i = 0; i < csp_config.plugin_choice.length; i++) {
                    policy += csp_config.plugin_choice[i];
                    policy += ' ';
                }
                policy += '; ';
            }

            // add default source
            policy += 'default-src \'none\';';

            var policy_text = '';
            var policy_message = '';
            // produce final formatted output depending on requested format
            switch (format) {
                case 'nginx':
                    policy_text = 'add_header ' + header + ' "' + policy + '";';
                    break;
                case 'apache':
                    policy_text = 'Header set ' + header + ' "' + policy + '"';
                    break;
                case 'php':
                    policy_text = 'header("' + header + ': ' + policy + '");';
                    break;
                case 'ror':
                    policy_message = 'Use <a href="https://github.com/twitter/secureheaders">secureheaders</a>.';
                    policy = ror_generator();
                    break;
                case 'django':
                    policy_message = 'Use <a href="https://github.com/kravietz/django-security">django-security</a>.';
                    policy_text = django_generator();
                default:
                    policy_text = header + ': ' + policy;
            }

            return [policy_text, policy_message];
} // policy_generator


