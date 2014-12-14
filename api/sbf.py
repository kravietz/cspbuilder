__author__ = 'pawelkrawczyk'

from io import BytesIO

from pybloom import ScalableBloomFilter
import pycouchdb


class SBF(object):
    doc_id = 'bloom_filter'
    file_name = 'sbf.dat'
    db = None
    f = None
    error_rate = 0.01

    def _save_sbf(self):
        buf = BytesIO()
        self.f.tofile(buf)
        buf.seek(0)
        try:
            doc = self.db.get(self.doc_id)
        except pycouchdb.exceptions.NotFound:
            _doc = {'_id': self.doc_id}
            doc = self.db.save(_doc)
        self.db.put_attachment(doc, buf, filename=self.file_name, content_type='application/octet-stream')

    def save(self):
        self._save_sbf()

    def _load_sbf(self):
        ret = None
        try:
            doc = self.db.get(self.doc_id)
            ret = self.db.get_attachment(doc, self.file_name)
        except pycouchdb.exceptions.NotFound:
            pass

        if ret:
            buf = BytesIO(ret)
            ret = self.sbf.fromfile(buf)

        return ret

    def __init__(self, db, doc_id='bloom_filter', file_name='sbf.dat'):
        self.doc_id = doc_id
        self.file_name = file_name
        self.db = db
        self.f = ScalableBloomFilter()
        self.f = self._load_sbf()
        if not self.f:
            # need to create new SBF
            self.f = ScalableBloomFilter(mode=ScalableBloomFilter.LARGE_SET_GROWTH, error_rate=self.error_rate)
            self._save_sbf()
