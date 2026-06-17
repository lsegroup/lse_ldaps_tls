from odoo import models, fields, api
import logging
import ldap
_logger = logging.getLogger(__name__)
class ResUsers(models.Model):
    _inherit = 'res.users'
    ldap_uid = fields.Char(string='LDAP UID', readonly=True)
    ldap_last_auth = fields.Datetime(string='Last LDAP Auth', readonly=True)
    @api.model
    def create(self, vals):
        user = super().create(vals)
        if not self.env.context.get('skip_ldap_sync'):
            try:
                self._trigger_ldap_sync(user, 'create', vals)
            except Exception as e:
                _logger.error(f"LSE LDAP: Error during user creation sync for {user.login}: {e}")
        return user
    def write(self, vals):
        result = super().write(vals)
        if self.env.context.get('skip_ldap_sync') or not vals:
            return result
        if self._should_trigger_ldap_sync(vals):
            for user in self:
                try:
                    self._trigger_ldap_sync(user, 'update', vals)
                except Exception as e:
                    _logger.error(f"LSE LDAP: Error during user update sync for {user.login}: {e}")
        return result
    def _should_trigger_ldap_sync(self, vals):
        sync_fields = ['name', 'email', 'groups_id', 'active', 'password']
        return any(field in vals for field in sync_fields)
    def _trigger_ldap_sync(self, user, operation, vals=None):
        if not user.login or user.login in ['admin', '__system__']:
            return
        ldap_configs = self.env['res.company.ldap.lse'].search([
            ('active', '=', True),
            ('auto_create_ldap_users', '=', True)
        ])
        for ldap_config in ldap_configs:
            try:
                if operation == 'create':
                    _logger.info(f"LSE LDAP: Triggering LDAP sync for new user {user.login}")
                    password = vals.get('password') if vals else None
                    ldap_config.sync_odoo_user_to_ldap(user, password)
                elif operation == 'update':
                    if 'password' in vals:
                        _logger.info(f"LSE LDAP: Triggering LDAP password sync for user {user.login}")
                        if ldap_config._user_exists_in_ldap(user.login):
                            ldap_config._update_ldap_user_password(user, vals['password'])
                        else:
                            _logger.info(f"LSE LDAP: User {user.login} not in LDAP, creating user with new password")
                            ldap_config.sync_odoo_user_to_ldap(user, vals['password'])
                    if 'groups_id' in vals:
                        _logger.info(f"LSE LDAP: Triggering LDAP group sync for user {user.login}")
                        ldap_config._map_odoo_groups_to_ldap(user)
                    if any(field in vals for field in ['name', 'email']):
                        _logger.info(f"LSE LDAP: Triggering LDAP profile sync for user {user.login}")
                        self._sync_profile_to_ldap(user, ldap_config, vals)
            except Exception as e:
                _logger.error(f"LSE LDAP: LDAP sync failed for user {user.login}: {e}")
    def _sync_profile_to_ldap(self, user, ldap_config, vals):
        conn = ldap_config._connect()
        if not conn:
            _logger.error(f"LSE LDAP: Cannot connect to sync profile for user {user.login}")
            return
        try:
            if ldap_config.ldap_binddn:
                conn.simple_bind_s(ldap_config.ldap_binddn, ldap_config.ldap_password or '')
            search_filter = ldap_config.ldap_filter % user.login
            results = conn.search_s(
                ldap_config.ldap_base,
                ldap.SCOPE_SUBTREE,
                search_filter,
                ['dn']
            )
            if not results:
                _logger.warning(f"LSE LDAP: User {user.login} not found in LDAP for profile sync")
                return
            user_dn = results[0][0]
            mod_attrs = []
            if 'name' in vals:
                name_parts = user.name.split(' ', 1)
                given_name = name_parts[0] if name_parts else user.login
                surname = name_parts[1] if len(name_parts) > 1 else given_name
                mod_attrs.extend([
                    (ldap.MOD_REPLACE, 'cn', [user.name.encode('utf-8')]),
                    (ldap.MOD_REPLACE, 'givenName', [given_name.encode('utf-8')]),
                    (ldap.MOD_REPLACE, 'sn', [surname.encode('utf-8')]),
                    (ldap.MOD_REPLACE, 'displayName', [user.name.encode('utf-8')])
                ])
            if 'email' in vals:
                email = user.email or user.login
                mod_attrs.append((ldap.MOD_REPLACE, 'mail', [email.encode('utf-8')]))
            if mod_attrs:
                conn.modify_s(user_dn, mod_attrs)
                _logger.info(f"LSE LDAP: Successfully updated LDAP profile for user {user.login}")
        except Exception as e:
            _logger.error(f"LSE LDAP: Error syncing profile to LDAP for user {user.login}: {e}")
            import traceback
            _logger.error(f"LSE LDAP: Traceback: {traceback.format_exc()}")
        finally:
            if conn:
                conn.unbind_s()
