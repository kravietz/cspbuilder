__author__ = 'pawelkrawczyk'

from io import BytesIO

from pybloom import ScalableBloomFilter
import pycouchdb


class SBF(object):
    SBF_DOC_ID = '_internal/bloom_filter'
    SBF_FILE_NAME = 'sbf.dat'
    db = None
    sbf = None

    def _save_sbf(self):
        buf = BytesIO()
        self.sbf.tofile(buf)
        buf.seek(0)
        _doc = {'_id': self.SBF_DOC_ID}
        doc = self.db.save(_doc)
        self.db.put_attachment(doc, buf, filename=self.SBF_FILE_NAME)

    def _load_sbf(self):
        ret = None
        try:
            doc = self.db.get(self.SBF_DOC_ID)
            ret = self.db.get_attachment(doc, self.SBF_FILE_NAME)
        except pycouchdb.exceptions.NotFound:
            pass

        if ret:
            buf = BytesIO(ret)
            ret = self.sbf.fromfile(buf)

        return ret

    def __init__(self, db):
        self.db = db
        self.sbf = ScalableBloomFilter()
        self.sbf = self._load_sbf()
        if not self.sbf:
            # need to create new SBF
            self.sbf = ScalableBloomFilter(mode=ScalableBloomFilter.LARGE_SET_GROWTH, error_rate=0.01)
            self._save_sbf()