/**
 * Created by Paweł Krawczyk on 04/09/2014.
 */

"use strict";

/*
 This function returns variants of a blocked URI for the user to choose. Example:
 For blocked_uri like 'http://webcookies.info/dajaxice/register_site.status/'
 returns array of
 ['http://webcookies.info/dajaxice/register_site.status','http://webcookies.info/dajaxice','http://webcookies.info']
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
function null_url_guesswork(csp, meta) {
    console.log('null_url_guesswork');

    // first check tag, which is an authoritative source
    var tag = meta['tag'];
    if (tag == 'noscripteval') {
        return { 'message': 'CSP report URL indicates blocked eval() call.', 'sources': ['\'unsafe-eval\'']};
    }
    if (tag == 'noscriptinline') {
        return { 'message': 'CSP report URL indicates blocked inline code.', 'sources': ['\'unsafe-inline\'']};
    }

    // no tag, try heuristics
    var blocked_type = csp['effective-directive'] ? csp['effective-directive'] : csp['violated-directive'].split(' ')[0];
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
    if (uri.match(/^http/)) {
        return uri.match(/^(https?:\/\/[^?#/]+)/)[1];
    } else {
        return uri;
    }
}

// convert blocked-uri from CSP report to a statement that can be used in new policy
function source_to_policy_statement(csp, meta) {
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
        return null_url_guesswork(csp, meta);
    }

    console.log('policy statement ' + blocked_uri + ' for ' + JSON.stringify(csp));

    return  {'message': 'Please review this source and decide if it\'s trusted.', 'sources': [blocked_uri]};
} // source_to_policy_statement

function empty_approved_list() {
    // return dict like
    // { 'script-src': { 'none': true }... }
    var approved_list = {};
    // report-uri and default-src will be added automatically
    // TODO: list of CSP directives should be defined globally
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
        'tagged_headers': true,
        'referrer': 'origin-when-cross-origin',
        'reflected_xss': 'filter',
        'header_format': 'standard',
        'experimental': true,
        'strict_mixed_content_checking': true,
        'plugin_types': [
            'application/pdf',
            'application/x-shockwave-flash',
            'application/java'
        ],
        'plugin_choice': []
    };
} // default_csp_config

function generate_csp_strings(owner_id, format, approved_list, csp_config) {

    if (csp_config.tagged_headers) {
        // produce two tagged headers
        var policy_string1 = generate_csp(owner_id, csp_config, approved_list, 'noscripteval');
        var formatted1 = generate_formatted(format, csp_config, policy_string1);
        var policy_string2 = generate_csp(owner_id, csp_config, approved_list, 'noscriptinline');
        var formatted2 = generate_formatted(format, csp_config, policy_string2);
        var formatted = formatted1 + '\n\n' + formatted2;
        var message = 'Tagged headers are enabled so we generate two CSP headers, each with distinct reporting URL. ' +
            'This allows CspBuilder to distinguish between the eval()/inline events that are otherwise ' +
            '<a target="_blank" href="/static/#/faq#inline-eval-detection">identical</a>. ' +
            'One headers is tagged \'noscripteval\' and its script-src statement does ' +
            'not allow the eval(). The other one is tagged \'noscriptinline\' and this in turn disallows ' +
            'inline JavaScript. Because each class of events is then reported to distinct URL, CspBuilder ' +
            'has much easier job with distinguishing one from another.';

    } else {
        // produce standard single header

        var policy_string = generate_csp(owner_id, csp_config, approved_list, '');
        var formatted = generate_formatted(format, csp_config, policy_string);
        var message = '';
    }

    return [formatted, message];

} // generate_csp_strings

// pack the generic CSP string into appropriate header
function generate_formatted(format, csp_config, policy_string) {

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

    // produce final formatted output depending on requested format
    var policy_text = '';
    switch (format) {
        case 'raw':
            policy_text = policy_string;
            break
        case 'nginx':
            // http://nginx.org/en/docs/http/ngx_http_headers_module.html
            policy_text = 'add_header ' + header + ' "' + policy_string + '";';
            break;
        case 'apache':
            // https://httpd.apache.org/docs/2.2/mod/mod_headers.html
            policy_text = 'Header set ' + header + ' "' + policy_string + '"';
            break;
        case 'php':
            // http://php.net/manual/en/function.header.php
            policy_text = 'header("' + header + ': ' + policy_string + '");';
            break;
        case 'http':
        default:
            policy_text = header + ': ' + policy_string;
    }

    return policy_text;

} // generate_formatted

function generate_csp(owner_id, csp_config, approved_list, tag) {
    console.log('generate_csp owner_id=' + owner_id);

    var report_uri = '//cspbuilder.info/report/' + owner_id + '/';

    if (tag) {
        report_uri += tag + '/';
    }

    // initialize the policy string putting report-uri in front
    var policy = 'report-uri ' + report_uri + '; ';

    // overwrite default-src with 'none'
    approved_list['default-src'] = {};
    approved_list['default-src']["'none'"] = true;

    // cycle through the items on 'approved' list creating a policy
    // statement for each of them
    Object.keys(approved_list).forEach(function (type) {
        // iterating through 'type1', 'type2'...
        policy += type + ' ';

        // cycle through sources in each type and build policy entry out of them
        Object.keys(approved_list[type]).forEach(function (src) {
            // iterating through 'source1', 'source2'...

            // support inline/eval tagging
            if (type == 'script-src') {
                if (tag == 'noscripteval' && src == "'unsafe-eval'") {
                    src = '';
                }
                if (tag == 'noscriptinline' && src == "'unsafe-inline'") {
                    src = '';
                }
            }

            // actually append the source
            policy += src + ' ';
        });
        policy += '; ';
    });

    // https://w3c.github.io/webappsec/specs/mixedcontent/#strict-mode
    if (csp_config.experimental && csp_config.strict_mixed_content_checking) {
        policy += 'strict-mixed-content-checking; ';
    }

    // https://w3c.github.io/webappsec/specs/content-security-policy/#directive-reflected-xss
    switch (csp_config.experimental && csp_config.reflected_xss) {
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
    switch (csp_config.experimental && csp_config.referrer) {
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
    if (csp_config.experimental && csp_config.plugin_choice.length) {
        policy += 'plugin-types ';
        for (var i = 0; i < csp_config.plugin_choice.length; i++) {
            policy += csp_config.plugin_choice[i];
            policy += ' ';
        }
        policy += '; ';
    }

    return policy;
} // generate_csp


