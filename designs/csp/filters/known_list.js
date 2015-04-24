/**
 * Created by Paweł Krawczyk on 24/04/15.
 *
 * Filter used by retro.py
 */

(function (doc, req) {
    if (doc.review_type && doc.review_source && doc.review_action && doc.owner_id) {
        return true;
    } else {
        return false;
    }
});