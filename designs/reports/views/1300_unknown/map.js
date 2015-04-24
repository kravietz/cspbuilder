/**
 * Created by Paweł Krawczyk on 24/04/15.
 *
 * View used by retro.py
 */

(function (doc) {
    if (doc.owner_id && doc['csp-report']) {
        if (!doc.review || doc.review.decision == 'unknown') {
            var violated_directive;
            if (doc['csp-report']['effective-directive']) {
                violated_directive = doc['csp-report']['effective-directive'];
            } else {
                violated_directive = doc['csp-report']['violated-directive'].split(' ')[0];
            }
            var blocked_uri = doc['csp-report']['blocked-uri'];
            emit([doc.owner_id, violated_directive, blocked_uri], null);
        }
    }
});
