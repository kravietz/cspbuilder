/**
 * Created by pawelkrawczyk on 09/09/2014.
 */
function(doc) {
  if(doc['owner_id'] && doc['known_uri'] && doc['known_type'] && doc['action']) {
    emit([doc['owner_id'], doc['known_type'], doc['known_uri'], doc['action']]
	, null)
}
}