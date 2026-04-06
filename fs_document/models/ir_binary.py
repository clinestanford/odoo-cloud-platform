# Copyright 2026 JobXcel
# License LGPL-3.0 or later (https://www.gnu.org/licenses/lgpl).

from odoo import models

from odoo.addons.fs_attachment.fs_stream import FsStream


class IrBinary(models.AbstractModel):
    _inherit = "ir.binary"

    def _record_to_stream(self, record, field_name):
        """Bridge between Documents and fs_attachment.

        The Enterprise Documents module overrides _record_to_stream and calls
        Stream.from_attachment() directly for documents.document records,
        bypassing fs_attachment's FsStream handling. This causes a
        FileNotFoundError when the attachment is stored in an external
        filesystem (e.g. S3) because Stream.from_attachment() only knows
        how to read from the local filestore.

        This override intercepts the call before Documents does, checks if
        the document's attachment lives in a filesystem storage, and routes
        it through FsStream so the file is fetched from S3 instead.
        """
        if (
            record._name == "documents.document"
            and field_name in ("raw", "datas", "db_datas")
            and record.attachment_id
            and record.attachment_id.fs_filename
        ):
            return FsStream.from_fs_attachment(record.attachment_id.sudo())
        return super()._record_to_stream(record, field_name)
