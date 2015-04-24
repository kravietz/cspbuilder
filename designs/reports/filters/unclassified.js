/**
 * Created by Paweł Krawczyk on 24/04/15.
 *
 * Filter used by classifier.py
 */

(function (doc, req) {
    if (doc['csp-report'] && !doc.review) {
        return true;
    } else {
        return false;
    }
});
