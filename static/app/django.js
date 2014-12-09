/**
 * Created by pawelkrawczyk on 09/12/14.
 */

function django_generator(owner_id, csp_config, approved_list) {
    // Output policy dictionary compatible with https://github.com/kravietz/django-security
    console.log('django_generator owner_id=' + owner_id);
    var policy = "CSP_MODE = '" + csp_config.enforce ? 'enforce' : 'report-only' + "'\n";

    policy += "CSP_DICT = {\n";

    policy += "\t'report-uri': '//cspbuilder.info/report/" + owner_id + "/',\n";

    // cycle through the items on 'approved' list creating a policy
    // statement for each of them
    Object.keys(approved_list).forEach(function (type) {
        // iterating through 'type1', 'type2'...
        var sources = [];

        //  cycle through sources in each type and build policy entry out of them
        Object.keys(approved_list[type]).forEach(function (src) {
            // iterating through 'source1', 'source2'...
            // append to sources list
            sources.append(src);
        });

        // append to policy
        policy += "\t''" + type + "': " + JSON.stringify(sources) + ",\n";


    });

    policy += "}";

    var policy_message = 'This format is intended to be directly usable with <a href="https://github.com/kravietz/django-security">django-security</a>.';

    return [policy, policy_message];
}