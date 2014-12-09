/**
 * Created by pawelkrawczyk on 09/12/14.
 */

// https://w3c.github.io/webappsec/specs/content-security-policy/#csp-request-header
function ror_generator(owner_id, format, csp_config, approved_list) {
    "use strict";
    // Designed to be compatible with https://github.com/twitter/secureheaders
    console.log('ror_generator owner_id=' + owner_id);

    var policy = ":csp => {\n";

    // :enforce => true,
    policy += "\t:enforce => " + csp_config.enforce + ",\n";

    // :report_uri => '//cspbuilder.info/report/123/',
    policy += "\t:report_uri => '//cspbuilder.info/report/" + owner_id + "/',\n";
    policy += "\t:default_src => nil,\n";

    // cycle through the items on 'approved' list creating a policy
    // statement for each of them
    Object.keys(approved_list).forEach(function (type) {
        // iterating through 'type1', 'type2'...
        // img-src becomes img_src
        var ror_type = type.replace('-', '_');
        var sources = "";

        // handle empty types - they should have a 'none' entry
        if (Object.keys(approved_list[type]).length == 0) {
            approved_list[type]["'none'"] = true;
        }

        // cycle through sources in each type and build policy entry out of them
        Object.keys(approved_list[type]).forEach(function (src) {
            // iterating through 'source1', 'source2'...

            // convert to RoR syntax
            if (src == "'unsafe-inline'") {
                src = 'inline';
            }
            if (src == "'unsafe-eval'") {
                src = 'eval';
            }

            // append to sources list
            sources += src + " ";
        });

        // append to policy
        policy += "\t :" + ror_type + " => '" + sources + "',\n";

    });

    policy += "}";

    var policy_message = 'This format is intended to be directly usable with <a href="https://github.com/twitter/secureheaders">secureheaders</a>.'
    ' Note that secureheaders does not support various CSP headers.';

    return [policy, policy_message];
}