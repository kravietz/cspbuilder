/**
 * Created by pawelkrawczyk on 09/09/2014.
 */
function (doc) {
    if (doc['owner_id'] && doc['review_type'] && doc['review_source'] && doc['review_action']) {
        emit([doc['owner_id']], [doc['review_type'], doc['review_source'], doc['review_action'],
            , null])
    }
}