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
    var parts = blocked_uri.split('/');

    for (var i = parts.length - 1; i >= 3; i--) {
        variants.push(parts.slice(0,i).join('/'));
    }
    console.log('variants=' + variants);
    return variants;

}

function null_url_guesswork(csp) {
    console.log('null_url_guesswork');

    var blocked_uri = csp['blocked-uri'];
    var blocked_type = csp['violated-directive'].split(' ')[0];
    var violated_directive = csp['violated-directive'];

    // styles
    if (blocked_type === 'style-src') {

        // check if inline was already allowed on blocked page
        if (violated_directive.indexOf('unsafe-inline') > 0) {
            // yes, it must have been eval()
            blocked_uri = '\'unsafe-eval\'';
        } else {
            // no, try inline first
            blocked_uri = '\'unsafe-inline\'';
        }

    // scripts
    } else if (blocked_type === 'script-src') {

        // the same heuristics as above
        if (violated_directive.indexOf('unsafe-inline') > 0) {
            blocked_uri = '\'unsafe-eval\'';
        } else {
            blocked_uri = '\'unsafe-inline\'';
        }

    // something else?
    } else {
        console.warn('Unrecognized \'null\' source for type ' + blocked_type + ' in:' + JSON.stringify(csp));
    }

    return blocked_uri;
} // null_url_guesswork

// convert blocked-uri from CSP report to a statement that can be used in new policy
function source_to_policy_statement(csp) {
    console.log('source_to_policy_statement');

    var blocked_uri = csp['blocked-uri'];
    var document_uri = csp['document-uri'];

    // for 'data:image/png' return 'data:'
    if (blocked_uri.lastIndexOf('data', 0) === 0) {
        return 'data:';
    }

    // for 'http://url.com:80/path/path' return 'http://url.com:80/'
    if (/^https?:\/\/[a-zA-Z0-9.:-]+/.test(blocked_uri)) {

        // extract base website URL
        var blocked_site = blocked_uri.match(/^(https?:\/\/[a-zA-Z0-9.:-]+\/)/)[1];

        // check if blocked URI was not in the same domain as CSP website
        if (blocked_site === document_uri) {
            // yes, return 'self'
            return '\'self\'';
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

    return blocked_uri;
} // source_to_policy_statement


