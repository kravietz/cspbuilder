/**
 * Created by pawelkrawczyk on 04/09/2014.
 */

"use strict";

// convert blocked-uri from CSP report to a statement that can be used in new policy
function source_to_policy_statement(csp) {
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
            // no, return that URI
            return blocked_site;
        }
    }

    console.warn('unable to determine policy statement for ' + JSON.stringify(csp));

    return blocked_uri;
}

function null_url_guesswork(csp) {
    var blocked_uri = csp['blocked-uri'];
    var blocked_type = csp['violated-directive'].split(' ')[0];

    // distinguishing between unsafe-inline and unsafe-eval is a guess work...
    if (blocked_uri === 'null') {

        var violated_directive = csp['violated-directive'];

        if (blocked_type === 'style-src') {

            // check if inline was already allowed on blocked page
            if (violated_directive.indexOf('unsafe-inline') > 0) {
                // otherwise it must have been eval()
                blocked_uri = '\'unsafe-eval\'';
            } else {
                // so the blocked resource was an inline script
                blocked_uri = '\'unsafe-inline\'';
            }

            // guesswork needed for scripts
        } else if (blocked_type === 'script-src') {

            // the same heuristics is used for script-src
            if (violated_directive.indexOf('unsafe-inline') > 0) {
                blocked_uri = '\'unsafe-eval\'';
            } else {
                blocked_uri = '\'unsafe-inline\'';
            }

        } else {
            console.warn('Unrecognized \'null\' source for type ' + blocked_type + ' in:' + JSON.stringify(csp));
        }
    }
    return blocked_uri;
}
