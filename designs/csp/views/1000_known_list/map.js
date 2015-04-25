/**
 * Created by Paweł Krawczyk on 25/04/15.
 *
 * Used by KnownList object in classifier.py and retro.py
 * as well as in CspKnownController and CspPolicyController
 */

(function (doc) {
    if (doc['owner_id'] && doc['review_type'] && doc['review_source'] && doc['review_action']) {
        emit(doc['owner_id'], [doc['review_type'], doc['review_source'], doc['review_action']])
    }
});
