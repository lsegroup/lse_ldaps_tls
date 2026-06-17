from odoo import models, fields, api
class ResLdapOdooMapping(models.Model):
    _name = 'res.ldap.odoo.mapping'
    _description = 'LDAP to Odoo Group Mapping'
    _order = 'sequence, id'
    sequence = fields.Integer(string='Sequence', default=10)
    ldap_config_id = fields.Many2one('res.company.ldap.lse', string='LDAP Configuration', required=True, ondelete='cascade')
    ldap_groups = fields.Many2many('res.ldap.group', 'ldap_odoo_mapping_ldap_group_rel', 'mapping_id', 'ldap_group_id', string='LDAP Groups')
    odoo_groups = fields.Many2many('res.groups', 'ldap_odoo_mapping_odoo_group_rel', 'mapping_id', 'group_id', string='Odoo Groups')
    active = fields.Boolean(string='Active', default=True)