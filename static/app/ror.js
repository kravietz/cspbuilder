/**
 * Created by Paweł Krawczyk on 09/12/14.
 */

// https://w3c.github.io/webappsec/specs/content-security-policy/#csp-request-header
function ror_generator(owner_id, csp_config, approved_list) {
    "use strict";
    // Designed to be compatible with https://github.com/twitter/secureheaders
    console.log('ror_generator owner_id=' + owner_id);

    var policy = ":csp => {\n";

    // :enforce => true,
    policy += "\t:enforce => " + csp_config.enforce + ",\n";

    // :report_uri => '//cspbuilder.info/report/123/',
    policy += "\t:report_uri => '//cspbuilder.info/report/" + owner_id + "/',\n";

    // cycle through the items on 'approved' list creating a policy
    // statement for each of them
    Object.keys(approved_list).forEach(function (type) {
        // iterating through 'type1', 'type2'...
        // img-src becomes img_src
        var ror_type = type.replace('-', '_');
        var sources = "";

        // handle 'nones' as they need to be written as 'nil'
        if ("'none'" in approved_list[type]) {
            policy += "\t:" + ror_type + " => nil,\n";
        } else {
            // otherwise cycle through sources in each type and build policy entry out of them
            Object.keys(approved_list[type]).forEach(function (src) {
                // iterating through 'source1', 'source2'...

                // convert to RoR syntax
                if (src == "'unsafe-inline'") {
                    src = 'inline';
                }
                if (src == "'unsafe-eval'") {
                    src = 'eval';
                }
                if (src == "'self'") {
                    src = 'self';
                }

                // append to sources list
                sources += src + " ";
            });

            // append to policy
            policy += "\t:" + ror_type + " => '" + sources + "',\n";
        }

    });

    policy += "}";

    var policy_message = 'This format is intended to be directly usable with <a href="https://github.com/twitter/secureheaders">secureheaders</a>.'
    ' It <strong>does not</strong> support the CSP 1.1 directives';

    return [policy, policy_message];
}