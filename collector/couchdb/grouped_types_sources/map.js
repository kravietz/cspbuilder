/**
 * Created by pawelkrawczyk on 09/09/2014.
 */
function (doc) {
    if (doc['owner_id'] && doc['csp-report'] && doc['csp-report']['blocked-uri'] && !doc.reviewed) {
        blocked_uri = doc['csp-report']['blocked-uri'];
        if (/^data:/.test(blocked_uri)) {
            // truncate the BASE64 encoded data from URI
            blocked_uri = 'data:';
        }
        if (/^https?/.test(blocked_uri)) {
            // truncate URI to exclude params after ? or #
            blocked_uri = blocked_uri.match(/^(https?:\/\/[^?#]+)/)[1];
        }

        emit([ doc['owner_id'], doc['csp-report']['violated-directive'].split(' ')[0], blocked_uri, ], 1);

    }
}