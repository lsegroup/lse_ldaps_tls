from odoo import models, fields, api
class ResOdooLdapMapping(models.Model):
    _name = 'res.odoo.ldap.mapping'
    _description = 'Odoo to LDAP Group Mapping'
    _order = 'sequence, id'
    sequence = fields.Integer(string='Sequence', default=10)
    ldap_config_id = fields.Many2one('res.company.ldap.lse', string='LDAP Configuration', required=True, ondelete='cascade')
    odoo_groups = fields.Many2many('res.groups', 'odoo_ldap_mapping_odoo_group_rel', 'mapping_id', 'group_id', string='Odoo Groups')
    ldap_groups = fields.Many2many('res.ldap.group', 'odoo_ldap_mapping_ldap_group_rel', 'mapping_id', 'ldap_group_id', string='LDAP Groups')
    target_ou = fields.Many2one('res.ldap.ou', string='Target OU', help='LDAP Organizational Unit where users will be created')
    active = fields.Boolean(string='Active', default=True)