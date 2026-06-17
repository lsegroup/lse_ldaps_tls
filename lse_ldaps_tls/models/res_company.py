from odoo import models, fields

class ResCompany(models.Model):
    _inherit = 'res.company'
    # LDAP configurations relation - THIS WAS THE MISSING PIECE!
    ldap_ids = fields.One2many(
        'res.company.ldap.lse',  # Updated model reference
        'company',
        string='LDAP Servers',
        help='LDAP server configurations for this company'
    )
