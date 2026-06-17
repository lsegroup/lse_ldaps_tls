from odoo import fields, models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'
    # Module activation field
    module_lse_ldaps_tls = fields.Boolean(
        string='LSE LDAP TLS 1.3'
    )
    # LDAP server relation
    ldaps = fields.One2many(
        related='company_id.ldap_ids',
        readonly=False,
        string='LDAPS Servers'
    )

