/**
 * Created by pawelkrawczyk on 10/09/2014.
 */
function (doc) {
    if (doc.owner_id && doc['csp-report'] && doc['csp-report']['violated-directive'] && doc['csp-report']['blocked-uri']) {
        if (doc.reviewed === 'accepted') {
            emit([doc.owner_id, doc['csp-report']['violated-directive'].split(' ')[0],
                doc['csp-report']['blocked-uri'].match('^[^?#]+')], null);
        }
    }
}