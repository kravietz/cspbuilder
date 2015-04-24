/**
 * Created by Paweł Krawczyk on 24/04/15.
 */

(function (doc) {
    if (doc['review_action'] && doc['review_action'] == 'accept') {
        emit([doc['review_type'], doc['review_source']], 1)
    }
});