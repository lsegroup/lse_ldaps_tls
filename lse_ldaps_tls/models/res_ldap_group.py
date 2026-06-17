from odoo import models, fields, api
class ResLdapGroup(models.Model):
    _name = 'res.ldap.group'
    _description = 'LDAP Group'
    _rec_name = 'name'
    sequence = fields.Integer(string='Sequence', default=10)
    name = fields.Char(string='Group Name', required=True)
    dn = fields.Char(string='Distinguished Name')
    ldap_config_id = fields.Many2one('res.company.ldap.lse', string='LDAP Configuration')
    color = fields.Integer(string='Color', compute='_compute_color', store=True)
    @api.depends('name')
    def _compute_color(self):
        for record in self:
            if 'ou=' in record.name.lower() or 'organizational unit' in record.name.lower():
                record.color = 4
            else:
                record.color = 2