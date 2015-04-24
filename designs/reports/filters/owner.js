/**
 * Created by  Paweł Krawczyk on 24/04/15.
 *
 * Filter used by CspLiveController.
 */

(function (doc, req) {
    if (doc.owner_id && doc.owner_id == req.query.owner_id) {
        return true;
    } else {
        return false;
    }
});