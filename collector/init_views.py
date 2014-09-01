import couchdb
from couchdb.design import ViewDefinition

MAP1 = """
function(doc) {
  if(doc['owner_id'] && doc['csp-report'] && doc['csp-report']['blocked-uri'] && doc['csp-report']['violated-directive']) {
  emit( [ doc['owner_id'],
          doc['csp-report']['blocked-uri'],
         doc['csp-report']['violated-directive'].split(' ')[0] ],
	 null );
 }
}
"""
REDUCE1 = """
function(k,v,re) { return true; }
"""

MAP2 = """
function(doc) {
  if(doc['owner_id'] && doc['csp-report'] && doc['meta']) {
  emit( doc['owner_id'], null );
 }
}
"""

db = couchdb.Server('http://127.0.0.1:5984/')['csp']
ViewDefinition('csp', 'sources_key_owner', map_fun=MAP1, reduce_fun=REDUCE1).sync(db)
ViewDefinition('csp', 'all_by_owner', map_fun=MAP2).sync(db)
