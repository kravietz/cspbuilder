/**
 * Created by pawelkrawczyk on 04/09/2014.
 */

"use strict";

/*
 This function returns variants of a blocked URI for the user to choose. Example:
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
        variants.push(parts.slice(0, i).join('/'));
    }
    variants.reverse();
    if (variants.length > 3) {
        // get only a few shortest variants, more is too much
        variants = variants.slice(0, 5);
    }
    console.log('variants=' + variants);
    return {'message': 'Choose URI pattern to allow. Shorter patterns will cover all the longer patterns as well.',
        'sources': variants};

}

/*
 This function attempts to guess the best way to handle reports with blocked-uri: null. These
 are usually generated for eval() or inline objects, but in CSP 1.0 there's no way to distinguish them.
 We're using all available hints and heuristics to suggest the best solution.
 */
function null_url_guesswork(csp) {
    console.log('null_url_guesswork');

    var blocked_type = csp['violated-directive'].split(' ')[0];
    var violated_directive = csp['violated-directive'];
    var script_sample = csp['script-sample'];

    // response templates
    var eval_first = ['\'unsafe-eval\'', '\'unsafe-inline\''];
    var inline_first = eval_first.reverse();

    // response message templates
    var msg = 'In CSP 1.0 there is no good way to distinguish eval() and inline reports. ';
    var eval_msg = 'We guess you should allow eval(). ';
    var inline_msg = 'We guess you should allow inline code. ';

    // heuristics for style-src
    if (blocked_type === 'style-src') {

        // check if inline was already allowed on blocked page
        if (violated_directive.indexOf('unsafe-inline') > 0) {
            // inline was allowed, so it must have been eval()
            var hint = 'Your policy already allows inline styles and we still see empty blocked-uri.';
            return { 'message': msg + eval_msg + hint, 'sources': eval_first};
        } else {
            // no, try inline first
            var hint = 'Inline styles are what usually results in these messages in the first place.';
            return {'message': msg + inline_msg + hint, 'sources': inline_first};
        }

        // heuristics for script-src
    } else if (blocked_type === 'script-src') {

        if (script_sample && script_sample.indexOf('eval()') > 0) {
            // "script-sample": "call to eval() or related function blocked by CSP",
            // Mozilla/5.0 (Windows NT 5.1; rv:32.0) Gecko/20100101 Firefox/32.0
            var hint = 'Browser hint suggests this in script-sample field. '
            return { 'message': msg + eval_msg + hint, 'sources': eval_first};
        }

        // the same heuristics as above
        if (violated_directive.indexOf('unsafe-inline') > 0) {
            var hint = 'Your policy already allows inline scripts and we still see empty blocked-uri.';
            return {'message': msg + eval_msg + hint, 'sources': eval_first};
        } else {
            var hint = 'Inline scripts are  what usually results in these messages in the first place.';
            return {'message': msg + inline_msg + hint, 'sources': inline_first};
        }

        // heuristics for object-src
    } else if (blocked_type === 'object-src') {
        // The only case where I saw this was Savings Slider PUP
        // http://stackoverflow.com/questions/14618646/has-my-app-been-hacked-mysterious-dom-manipulation-injects-flash
        var object_msg = 'This inline object (usually SWF) is most likely loaded by an extension, potentially malware. Be careful.';
        return {'message': object_msg, 'sources': ['\'unsafe-inline\'']};
    } else {
        console.warn('Unrecognized \'null\' source for type ' + blocked_type + ' in:' + JSON.stringify(csp));
    }

    // this might be for object-src where inline makes more sense...
    return {'message': 'Normally this directive should not generate inline and/or eval() reports, please inspect it carefully before allowing.', 'sources': inline_first};
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
        return {'message': 'The source type of data: is usually for images or fonts stored inline in the HTML code.',
            'sources': ['data:']};
    }

    // at least Firefox/32 is sending "blocked-uri: self"
    if (blocked_uri == 'self') {
        // return 'self'
        return {'message': 'Content loaded from own domain is usually safe.', 'sources': ['\'self\'']};
    }

    // for 'http://url.com:80/path/path' return 'http://url.com:80/'
    if (/^https?:\/\/[a-zA-Z0-9.:-]+/.test(blocked_uri)) {

        // extract base website URLs
        var blocked_site = base_uri(blocked_uri);
        var document_site = base_uri(document_uri);

        // check if blocked URI was not in the same domain as CSP website
        if (blocked_site === document_site) {
            // yes, return 'self'
            return {'message': 'Content loaded from own domain is usually safe.', 'sources': ['\'self\'']};
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

    return  {'message': 'Please review this source and decide if it\'s trusted.', 'sources': [blocked_uri]};
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
    // return dict like
    // { 'script-src': { 'none': true }... }
    var approved_list = {};
    // report-uri and default-src will be added automatically
    var types = ['connect-src', 'child-src', 'font-src', 'form-action', 'frame-ancestors', 'frame-src',
        'img-src', 'media-src', 'object-src', 'script-src', 'style-src'];
    types.forEach(function (type) {
        approved_list[type] = { "'none'": true };
    });
    return approved_list;
} // empty_approved_list

function default_csp_config() {
    return {
        'enforce': false,
        'default': false,
        'referrer': 'none',
        'reflected_xss': 'block',
        'header_format': 'standard',
        'plugin_types': [
            'application/pdf',
            'application/x-shockwave-flash',
            'application/java'
        ],
        'plugin_choice': []
    };
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
    if (!csp_config.enforce) {
        header += '-Report-Only';
    }

    // initialize the policy string putting report-uri in front
    var policy = 'report-uri //cspbuilder.info/report/' + owner_id + '/; ';

    console.log('approved_list type', typeof approved_list);
    console.log('approved_list', JSON.stringify(approved_list));

    // overwrite default-src with 'none'
    approved_list['default-src'] = {};
    approved_list['default-src']["'none'"] = true;

    // cycle through the items on 'approved' list creating a policy
    // statement for each of them
    Object.keys(approved_list).forEach(function (type) {
        // iterating through 'type1', 'type2'...
        policy += type + ' ';
        console.log('type ', typeof type, type);

        // handle empty types - they should have a 'none' entry
        if (Object.keys[type].length == 0) {
            approved_list[type]["'none'"] = true;
        }

        // cycle through sources in each type and build policy entry out of them
        Object.keys(approved_list[type]).forEach(function (src) {
            // iterating through 'source1', 'source2'...
            policy += src + ' ';
        });
        policy += '; ';
    });

    // https://w3c.github.io/webappsec/specs/content-security-policy/#directive-reflected-xss
    switch (csp_config.reflected_xss) {
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
    switch (csp_config.referrer) {
        case 'no-referrer':
            policy += 'referrer no-referrer; ';
            break;
        case 'no-referrer-when-downgrade':
            policy += 'referrer no-referrer-when-downgrade; ';
            break;
        case 'origin':
            policy += 'referrer origin; ';
            break;
        case 'origin-when-cross-origin':
            policy += 'referrer origin-when-cross-origin; ';
            break;
        case 'unsafe-url':
            policy += 'referrer unsafe-url; ';
            break;
        default: // none
        // do nothing, do not add the directive
    }

    // https://w3c.github.io/webappsec/specs/content-security-policy/#directive-plugin-types
    if (csp_config.plugin_choice.length) {
        policy += 'plugin-types ';
        for (var i = 0; i < csp_config.plugin_choice.length; i++) {
            policy += csp_config.plugin_choice[i];
            policy += ' ';
        }
        policy += '; ';
    }

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


