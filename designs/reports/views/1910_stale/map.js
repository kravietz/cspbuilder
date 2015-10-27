/**
 * Created by Paweł Krawczyk  on 25/04/15.
 *
 * Used by util.py cleanup function.
 */
(function (doc) {
    if (doc.meta && doc.meta.expires && doc.meta.expires > Date.now()) {
            emit(doc._id, null);
        }

});