/**
 * Created by Paweł Krawczyk on 25/04/15.
 */
(function (doc) {
    if (doc['review_action'] && doc['review_action'] == 'reject') {
        emit([doc['review_type'], doc['review_source']], 1)
    }
});
