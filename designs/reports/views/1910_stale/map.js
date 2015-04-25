/**
 * Created by Paweł Krawczyk  on 25/04/15.
 *
 * Used by util.py cleanup function.
 */
(function (doc) {
    if (doc.meta && doc.meta.timestamp) {
        var doc_date = new Date(doc.meta.timestamp.split('T')[0]);
        var week_ago = new Date(Date.now() - 86400000);
        if (doc_date < week_ago) {
            emit(doc.meta.timestamp, null);
        }
    }
});