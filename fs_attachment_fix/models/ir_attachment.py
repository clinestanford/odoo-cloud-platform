# Copyright 2026 JobXcel
# License LGPL-3.0 or later (https://www.gnu.org/licenses/lgpl).

from odoo import api, models


class IrAttachment(models.Model):
    _inherit = "ir.attachment"

    def _get_datas_related_values(self, data, mimetype):
        """Clear fs_filename when force_db rules redirect storage to the database.

        When an attachment that was previously stored in an external filesystem
        (e.g. S3) is re-written with data small enough to match the
        force_db_for_default_attachment_rules, the base fs_attachment module
        correctly sets store_fname=False and puts the data into db_datas.

        However it does NOT clear fs_filename. This causes ir.binary to believe
        the file still lives on the filesystem storage (because it checks
        fs_filename to decide the serving path), resulting in a 500 error when
        the file is requested via /web/image.

        This override adds fs_filename=False to the returned values so that the
        serving code falls back to the standard db_datas path.

        OCA bug: https://github.com/OCA/storage — not yet reported/fixed as of
        April 2026.
        """
        values = super()._get_datas_related_values(data, mimetype)
        # When the parent decided to store in DB, store_fname will be False
        # and db_datas will contain the binary data. In that case we must also
        # clear fs_filename to prevent the serving code from trying to read
        # from a non-existent filesystem path.
        if values.get("db_datas") and not values.get("store_fname"):
            values["fs_filename"] = False
        return values
