from odoo import models, fields, api
class ResLdapOu(models.Model):
    _name = 'res.ldap.ou'
    _description = 'LDAP Organizational Unit'
    _rec_name = 'name'
    sequence = fields.Integer(string='Sequence', default=10)
    name = fields.Char(string='OU Name', required=True)
    dn = fields.Char(string='Distinguished Name')
    ldap_config_id = fields.Many2one('res.company.ldap.lse', string='LDAP Configuration')
    color = fields.Integer(string='Color', default=4)