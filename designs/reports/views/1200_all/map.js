/**
 * Created by Paweł Krawczyk on 25/04/15.
 *
 * View used by test.py, main.py (delete API) and CspReportsController.
 */
(function (doc) {
    if (doc.owner_id && doc['csp-report']) {
        emit(doc.owner_id, null);
    }
});
