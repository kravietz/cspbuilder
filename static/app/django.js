/**
 * Created by Paweł Krawczyk on 09/12/14.
 */

function django_generator(owner_id, csp_config, approved_list) {
    // Output policy dictionary compatible with https://github.com/kravietz/django-security
    console.log('django_generator owner_id=' + owner_id);
    var policy = "CSP_MODE = '" + (csp_config.enforce ? 'enforce' : 'report-only') + "'\n";

    policy += "CSP_DICT = {\n";

    policy += '\t"report-uri": //cspbuilder.info/report/' + owner_id + '/,\n';

    // cycle through the items on 'approved' list creating a policy
    // statement for each of them
    Object.keys(approved_list).forEach(function (type) {
        // iterating through 'type1', 'type2'...
        var sources = [];

        //  cycle through sources in each type and build policy entry out of them
        Object.keys(approved_list[type]).forEach(function (src) {
            // iterating through 'source1', 'source2'...
            // append to sources list
            sources.push(src);
        });

        // append to policy
        policy += '\t"' + type + '": ' + JSON.stringify(sources) + ',\n';


    });

    // https://w3c.github.io/webappsec/specs/content-security-policy/#directive-reflected-xss
    switch (csp_config.reflected_xss) {
        case 'block':
            policy += '\t"reflected-xss": "block",\n';
            break;
        case 'filter':
            policy += '\t"reflected-xss": "filter",\n';
            break;
        case 'allow':
            policy += '\t"reflected-xss": "allow"\n';
            break;
    }

    // https://w3c.github.io/webappsec/specs/content-security-policy/#directive-referrer
    switch (csp_config.referrer) {
        case 'no-referrer':
            policy += '\t"referrer": "no-referrer",\n';
            break;
        case 'no-referrer-when-downgrade':
            policy += '\t"referrer": "no-referrer-when-downgrade",\n';
            break;
        case 'origin':
            policy += '\t"referrer": "origin",\n';
            break;
        case 'origin-when-cross-origin':
            policy += '\t"referrer": "origin-when-cross-origin",\n';
            break;
        case 'unsafe-url':
            policy += '\t"referrer": "unsafe-url",\n';
            break;
        default: // none
        // do nothing, do not add the directive
    }

    policy += "}";

    var policy_message = 'This format is intended to be directly usable with <a href="https://github.com/kravietz/django-security">django-security</a>.'
    ' It <strong>does not</strong> support the CSP 1.1 directives';

    return [policy, policy_message];
}