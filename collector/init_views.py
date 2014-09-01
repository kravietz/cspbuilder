import couchdb
from couchdb.design import ViewDefinition

SOURCES_KEY_OWNER_MAP = """
function(doc) {
  if(doc['owner_id'] && doc['csp-report'] && doc['csp-report']['blocked-uri'] && doc['csp-report']['violated-directive']) {
  emit( [ doc['owner_id'],
          doc['csp-report']['blocked-uri'],
         doc['csp-report']['violated-directive'].split(' ')[0] ],
	 null );
 }
}
"""
SOURCES_KEY_OWNER_RED = """
function(k,v,re) { return true; }
"""

ALL_BY_OWNER = """
function(doc) {
  if(doc['owner_id'] && doc['csp-report'] && doc['meta']) {
  emit( doc['owner_id'], null );
 }
}
"""

APPROVED_SOURCES_OWNER_MAP="""
function(doc) {
  if(doc.approved_uri && doc.approved_type) {
	emit([doc.owner_id, doc.approved_type, doc.approved_uri], null);
  }
}
"""
APPROVED_SOURCES_OWNER_RED="""
function(k,v,r) {
return true;
}
"""

BY_SOURCE_TYPE_MAP="""
function(doc) {
  if(doc['owner_id'] && doc['csp-report'] && doc['csp-report']['blocked-uri'] && doc['csp-report']['violated-directive']) {
  emit( [ doc['owner_id'],
          doc['csp-report']['blocked-uri'],
          doc['csp-report']['violated-directive'].split(' ')[0] ],
	  null );
 }
}
"""


db = couchdb.Server('http://127.0.0.1:5984/')['csp']
ViewDefinition('csp', 'sources_key_owner', map_fun=SOURCES_KEY_OWNER_MAP, reduce_fun=SOURCES_KEY_OWNER_RED).sync(db)
ViewDefinition('csp', 'all_by_owner', map_fun=ALL_BY_OWNER).sync(db)
ViewDefinition('csp', 'approved_sources_owner', map_fun=APPROVED_SOURCES_OWNER_MAP, reduce_fun=APPROVED_SOURCES_OWNER_RED).sync(db)
ViewDefinition('csp', 'by_source_type', map_fun=BY_SOURCE_TYPE_MAP).sync(db)