import logging
from odoo import models

_logger = logging.getLogger(__name__)


class LseLdapsTlsLicense(models.AbstractModel):
    _name = 'lse.ldaps_tls.license'
    _description = 'lse_ldaps_tls license registration'

    def _register_hook(self):
        super()._register_hook()
        self.env.cr.execute("SELECT to_regclass('public.lse_license')")
        if self.env.cr.fetchone()[0] is not None:
            self.env['lse.license'].sudo().register(
                'lse_ldaps_tls',
                'Enterprise LDAPS for Odoo 19',
            )
        else:
            _logger.debug('lse_ldaps_tls: lse_license table not yet created, registration deferred')
