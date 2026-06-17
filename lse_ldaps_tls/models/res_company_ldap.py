from odoo import models, fields, api, _
import ldap
import logging
import time
import argon2
import re
_logger = logging.getLogger(__name__)
class ResCompanyLdap(models.Model):
    _name = 'res.company.ldap.lse'
    _description = 'LSE LDAP Configuration'
    _order = 'sequence, id'
    sequence = fields.Integer(string='Sequence', default=10)
    company = fields.Many2one('res.company', string='Company', required=True, default=lambda self: self.env.company)
    active = fields.Boolean(string='Active', default=True)
    ldap_server = fields.Char(string='LDAP Server', required=True)
    ldap_server_port = fields.Integer(string='LDAP Port', default=636)
    ldap_tls_version = fields.Selection([
        ('1.2', 'TLS 1.2'),
        ('1.3', 'TLS 1.3'),
    ], string='TLS Version', default='1.3', required=True)
    ldap_cert_validation = fields.Selection([
        ('never', 'Never'),
        ('allow', 'Allow'),
        ('try', 'Try'),
        ('demand', 'Demand'),
    ], string='Certificate Validation', default='demand', required=True)
    ldap_binddn = fields.Char(string='LDAP Bind DN')
    ldap_password = fields.Char(string='LDAP Password')
    ldap_base = fields.Char(string='LDAP Base')
    ldap_filter = fields.Char(string='LDAP Filter', default='(mail=%s)')
    create_user = fields.Boolean(string='Create User', default=True)
    user = fields.Many2one('res.users', string='Template User')
    last_sync = fields.Datetime(string='Last Sync', readonly=True)
    auto_create_users = fields.Boolean(string='Auto-create Users', default=False)
    auto_create_ldap_users = fields.Boolean(string='Auto-create LDAP Users', default=False)
    ldap_argon2_enabled = fields.Boolean(string='LDAP Argon2 Password', default=False)
    creation_filter = fields.Char(string='Creation Filter')
    delete_missing_users = fields.Boolean(string='Delete users not found in LDAP', default=False)
    connection_tested = fields.Boolean(string='Connection Tested', default=False)
    ldap_odoo_mappings = fields.One2many('res.ldap.odoo.mapping', 'ldap_config_id', string='LDAP Odoo Mappings')
    odoo_ldap_mappings = fields.One2many('res.odoo.ldap.mapping', 'ldap_config_id', string='Odoo LDAP Mappings')
    def _connect(self):
        try:
            uri = f"ldaps://{self.ldap_server}:{self.ldap_server_port}"
            cert_demand = {
                'never': ldap.OPT_X_TLS_NEVER,
                'allow': ldap.OPT_X_TLS_ALLOW,
                'try': ldap.OPT_X_TLS_TRY,
                'demand': ldap.OPT_X_TLS_DEMAND,
            }
            tls_min = 772 if self.ldap_tls_version == '1.3' else 771
            cert_opt = cert_demand[self.ldap_cert_validation]
            # Set TLS options globally BEFORE initialize(), then commit with NEWCTX
            # Required for both OpenSSL and WolfSSL backends (GnuTLS does not need NEWCTX)
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, cert_opt)
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, '/etc/ssl/certs/ca-certificates.crt')
            ldap.set_option(ldap.OPT_X_TLS_PROTOCOL_MIN, tls_min)
            conn = ldap.initialize(uri)
            conn.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
            conn.set_option(ldap.OPT_REFERRALS, 0)
            conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
            return conn
        except Exception as e:
            _logger.error(f"LSE LDAP: Connection failed: {e}")
            return None
    def test_connection(self):
        if not self.ldap_server or not self.ldap_server_port or not self.ldap_base:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Connection Test'),
                    'message': _('Please fill in Server, Port and LDAP Base before testing'),
                    'type': 'warning',
                }
            }
        conn = self._connect()
        if not conn:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Connection Test'),
                    'message': _('Connection failed: Unable to establish LDAPS connection'),
                    'type': 'danger',
                }
            }
        try:
            if self.ldap_binddn:
                conn.simple_bind_s(self.ldap_binddn, self.ldap_password or '')
            # Root DSE query - always available on any LDAP server regardless of base DN or content
            conn.search_s('', ldap.SCOPE_BASE, '(objectClass=*)', ['namingContexts', 'supportedLDAPVersion'])
            _logger.info("LSE LDAP: Connection test successful")
            try:
                conn.unbind_s()
            except Exception:
                pass
            self.write({'connection_tested': True})
            return {
                'type': 'ir.actions.act_window',
                'res_model': 'res.company.ldap.lse',
                'res_id': self.id,
                'view_mode': 'form',
                'target': 'current',
            }
        except ldap.SERVER_DOWN:
            _logger.error("LSE LDAP: Connection test failed: server unreachable")
            try:
                conn.unbind_s()
            except Exception:
                pass
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Connection Test'),
                    'message': _('Cannot reach LDAP server %s:%s - check host, port, firewall and TLS certificate') % (self.ldap_server, self.ldap_server_port),
                    'type': 'danger',
                }
            }
        except ldap.INVALID_CREDENTIALS:
            _logger.error("LSE LDAP: Connection test failed: invalid credentials")
            try:
                conn.unbind_s()
            except Exception:
                pass
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Connection Test'),
                    'message': _('Invalid credentials - check Bind DN and password'),
                    'type': 'danger',
                }
            }
        except Exception as e:
            _logger.error(f"LSE LDAP: Connection test failed: {e}")
            try:
                conn.unbind_s()
            except Exception:
                pass
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Connection Test'),
                    'message': _('Connection failed: %s') % str(e),
                    'type': 'danger',
                }
            }
    def _retry_with_backoff(self, func, *args, **kwargs):
        max_retries = 3
        base_delay = 0.1
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if 'serialization' in str(e).lower() and attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    _logger.warning(f"LSE LDAP: Serialization failure, retry {attempt + 1}/{max_retries} after {delay}s")
                    time.sleep(delay)
                    continue
                raise e
    def authenticate(self, login, password):
        if not login or not password:
            return False
        conn = self._connect()
        if not conn:
            return False
        try:
            if self.ldap_binddn:
                conn.simple_bind_s(self.ldap_binddn, self.ldap_password or '')
            search_filter = self.ldap_filter % login
            results = conn.search_s(
                self.ldap_base,
                ldap.SCOPE_SUBTREE,
                search_filter,
                ['cn', 'mail', 'uid', 'userPassword']
            )
            if not results:
                _logger.info(f"LSE LDAP: User {login} not found")
                return False
            user_dn, user_attrs = results[0]
            stored_password = user_attrs.get('userPassword', [b''])[0]
            if isinstance(stored_password, bytes):
                stored_password = stored_password.decode('utf-8')
            _logger.info(f"LSE LDAP: Password format: {stored_password[:20]}...")
            if stored_password.startswith('{ARGON2}'):
                hash_only = stored_password[8:]
                _logger.info(f"LSE LDAP: Argon2 hash: {hash_only[:30]}...")
                ph = argon2.PasswordHasher()
                try:
                    ph.verify(hash_only, password)
                    _logger.info(f"LSE LDAP: Argon2 authentication successful for {login}")
                except argon2.exceptions.VerifyMismatchError:
                    _logger.warning(f"LSE LDAP: Argon2 password mismatch for {login}")
                    return False
            else:
                try:
                    user_conn = self._connect()
                    user_conn.simple_bind_s(user_dn, password)
                    user_conn.unbind_s()
                except ldap.INVALID_CREDENTIALS:
                    _logger.warning(f"LSE LDAP: Invalid credentials for {login}")
                    return False
            try:
                self._retry_with_backoff(self._update_last_sync)
            except:
                _logger.warning("LSE LDAP: Failed to update last_sync, continuing...")
            return user_attrs
        except Exception as e:
            _logger.error(f"LSE LDAP: Authentication error for {login}: {str(e)}")
            _logger.error(f"LSE LDAP: Exception type: {type(e)}")
            import traceback
            _logger.error(f"LSE LDAP: Traceback: {traceback.format_exc()}")
            return False
        finally:
            if conn:
                conn.unbind_s()
    def _update_last_sync(self):
        self.write({'last_sync': fields.Datetime.now()})
    def refresh_ldap_groups(self):
        if not self.connection_tested:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('LDAP Groups Refresh'),
                    'message': _('Please test connection first before refreshing groups'),
                    'type': 'warning',
                }
            }
        conn = self._connect()
        if not conn:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('LDAP Groups Refresh'),
                    'message': _('Failed to connect to LDAP server'),
                    'type': 'danger',
                }
            }
        try:
            if self.ldap_binddn:
                conn.simple_bind_s(self.ldap_binddn, self.ldap_password or '')
            groups = conn.search_s(
                self.ldap_base,
                ldap.SCOPE_SUBTREE,
                '(objectClass=groupOfNames)',
                ['cn', 'dn']
            )
            self.env['res.ldap.group'].search([('ldap_config_id', '=', self.id)]).unlink()
            for group_dn, group_attrs in groups:
                if 'cn' in group_attrs:
                    group_name = group_attrs['cn'][0].decode('utf-8')
                    self.env['res.ldap.group'].create({
                        'name': group_name,
                        'dn': group_dn,
                        'ldap_config_id': self.id
                    })
                    _logger.info(f"LSE LDAP: Created LDAP group record: {group_name}")
            ous = conn.search_s(
                self.ldap_base,
                ldap.SCOPE_SUBTREE,
                '(objectClass=organizationalUnit)',
                ['ou', 'dn']
            )
            self.env['res.ldap.ou'].search([('ldap_config_id', '=', self.id)]).unlink()
            for ou_dn, ou_attrs in ous:
                if 'ou' in ou_attrs:
                    ou_name = ou_attrs['ou'][0].decode('utf-8')
                    self.env['res.ldap.ou'].create({
                        'name': ou_name,
                        'dn': ou_dn,
                        'ldap_config_id': self.id
                    })
                    _logger.info(f"LSE LDAP: Created LDAP OU record: {ou_name}")
            group_count = len(groups)
            ou_count = len(ous)
            _logger.info(f"LSE LDAP: Refreshed {group_count} groups and {ou_count} OUs from LDAP directory")
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('LDAP Groups Refresh'),
                    'message': _('Found %d groups and %d OUs in LDAP directory') % (group_count, ou_count),
                    'type': 'success',
                }
            }
        except Exception as e:
            _logger.error(f"LSE LDAP: Error refreshing groups: {e}")
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('LDAP Groups Refresh'),
                    'message': _('Error refreshing groups: %s') % str(e),
                    'type': 'danger',
                }
            }
        finally:
            if conn:
                conn.unbind_s()
    def open_ldap_form(self):
        return {
            'type': 'ir.actions.act_window',
            'name': 'LDAP Server Configuration',
            'res_model': 'res.company.ldap.lse',
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'current',
        }
    def _get_user_ldap_groups(self, login):
        conn = self._connect()
        if not conn:
            return []
        try:
            if self.ldap_binddn:
                conn.simple_bind_s(self.ldap_binddn, self.ldap_password or '')
            search_filter = self.ldap_filter % login
            user_results = conn.search_s(
                self.ldap_base,
                ldap.SCOPE_SUBTREE,
                search_filter,
                ['dn']
            )
            if not user_results:
                return []
            user_dn = user_results[0][0]
            _logger.info(f"LSE LDAP: Found user DN: {user_dn}")
            group_results = conn.search_s(
                self.ldap_base,
                ldap.SCOPE_SUBTREE,
                f'(&(objectClass=groupOfNames)(member={user_dn}))',
                ['cn']
            )
            groups = []
            for group_dn, group_attrs in group_results:
                if 'cn' in group_attrs:
                    group_name = group_attrs['cn'][0].decode('utf-8')
                    groups.append(group_name)
            _logger.info(f"LSE LDAP: User {login} belongs to LDAP groups: {groups}")
            return groups
        except Exception as e:
            _logger.error(f"LSE LDAP: Error getting user groups: {e}")
            return []
        finally:
            if conn:
                conn.unbind_s()
    def _map_ldap_groups_to_odoo(self, ldap_group_names):
        all_mapped_groups = self.env['res.groups']
        for mapping in self.ldap_odoo_mappings:
            mapping_ldap_groups = mapping.ldap_groups.mapped('name')
            if any(ldap_group in ldap_group_names for ldap_group in mapping_ldap_groups):
                _logger.info(f"LSE LDAP: Found mapping match for LDAP groups {mapping_ldap_groups}")
                all_mapped_groups |= mapping.odoo_groups
        # Identify user type groups by XML ID — reliable across all Odoo versions
        # (names changed in Odoo 19: 'Internal User'→'Role / User', 'Portal'→'Role / Portal', etc.)
        group_user   = self.env.ref('base.group_user',   raise_if_not_found=False)
        group_portal = self.env.ref('base.group_portal', raise_if_not_found=False)
        group_public = self.env.ref('base.group_public', raise_if_not_found=False)
        user_type_ids = {g.id for g in [group_user, group_portal, group_public] if g}
        user_type_groups = all_mapped_groups.filtered(lambda g: g.id in user_type_ids)
        regular_groups   = all_mapped_groups.filtered(lambda g: g.id not in user_type_ids)
        # Select exactly one user type with priority: Internal User > Portal > Public
        final_user_type = self.env['res.groups']
        for candidate in [group_user, group_portal, group_public]:
            if candidate and candidate in user_type_groups:
                final_user_type = candidate
                break
        if not final_user_type and group_user:
            final_user_type = group_user
        is_portal_or_public = final_user_type and final_user_type in (group_portal, group_public)
        if is_portal_or_public:
            # Portal/Public users get only their user type — no module permission groups
            final_groups = final_user_type
        else:
            # Internal users: user type + all non-user-type groups from the mapping
            final_groups = final_user_type | regular_groups
        user_type_name = (final_user_type.name.get('en_US', '') if isinstance(final_user_type.name, dict)
                          else str(final_user_type.name)) if final_user_type else 'None'
        final_names = [(g.name.get('en_US', '') if isinstance(g.name, dict) else str(g.name)) for g in final_groups]
        _logger.info(f"LSE LDAP: Selected user type: {user_type_name}")
        _logger.info(f"LSE LDAP: Final groups ({len(final_groups)}): {final_names}")
        return final_groups
    def _user_exists_in_ldap(self, login):
        conn = self._connect()
        if not conn:
            return False
        try:
            if self.ldap_binddn:
                conn.simple_bind_s(self.ldap_binddn, self.ldap_password or '')
            search_filter = self.ldap_filter % login
            results = conn.search_s(
                self.ldap_base,
                ldap.SCOPE_SUBTREE,
                search_filter,
                ['cn']
            )
            return len(results) > 0
        except Exception as e:
            _logger.error(f"LSE LDAP: Error checking if user exists: {e}")
            return False
        finally:
            if conn:
                conn.unbind_s()
    def _get_next_uid_number(self):
        conn = self._connect()
        if not conn:
            return 10000
        try:
            if self.ldap_binddn:
                conn.simple_bind_s(self.ldap_binddn, self.ldap_password or '')
            results = conn.search_s(
                self.ldap_base,
                ldap.SCOPE_SUBTREE,
                '(objectClass=posixAccount)',
                ['uidNumber']
            )
            uid_numbers = []
            for dn, attrs in results:
                if 'uidNumber' in attrs:
                    uid_numbers.append(int(attrs['uidNumber'][0]))
            return max(uid_numbers) + 1 if uid_numbers else 10000
        except Exception as e:
            _logger.error(f"LSE LDAP: Error getting next UID number: {e}")
            return 10000
        finally:
            if conn:
                conn.unbind_s()
    def _get_next_gid_number(self):
        conn = self._connect()
        if not conn:
            return 10000
        try:
            if self.ldap_binddn:
                conn.simple_bind_s(self.ldap_binddn, self.ldap_password or '')
            results = conn.search_s(
                self.ldap_base,
                ldap.SCOPE_SUBTREE,
                '(objectClass=posixGroup)',
                ['gidNumber']
            )
            gid_numbers = []
            for dn, attrs in results:
                if 'gidNumber' in attrs:
                    gid_numbers.append(int(attrs['gidNumber'][0]))
            return max(gid_numbers) + 1 if gid_numbers else 10000
        except Exception as e:
            _logger.error(f"LSE LDAP: Error getting next GID number: {e}")
            return 10000
        finally:
            if conn:
                conn.unbind_s()
    def _get_user_ou_from_mapping(self, odoo_user=None):
        if odoo_user and self.odoo_ldap_mappings:
            # groups_id removed in Odoo 19 — fetch via SQL
            self.env.cr.execute(
                "SELECT gid FROM res_groups_users_rel WHERE uid = %s",
                (odoo_user.id,)
            )
            user_group_ids = {row[0] for row in self.env.cr.fetchall()}
            for mapping in self.odoo_ldap_mappings:
                if any(g.id in user_group_ids for g in mapping.odoo_groups):
                    if mapping.target_ou:
                        return mapping.target_ou.dn
        return f"ou=people,{self.ldap_base}"
    def _create_ldap_user(self, odoo_user, password=None):
        if not self.auto_create_ldap_users:
            return False
        conn = self._connect()
        if not conn:
            _logger.error(f"LSE LDAP: Cannot connect to create user {odoo_user.login}")
            return False
        try:
            if self.ldap_binddn:
                conn.simple_bind_s(self.ldap_binddn, self.ldap_password or '')
            if self._user_exists_in_ldap(odoo_user.login):
                _logger.info(f"LSE LDAP: User {odoo_user.login} already exists in LDAP")
                return True
            user_ou = self._get_user_ou_from_mapping(odoo_user)
            user_dn = f"uid={odoo_user.login},{user_ou}"
            _logger.info(f"LSE LDAP: Attempting to create user with DN: {user_dn}")
            _logger.info(f"LSE LDAP: Detected user OU: {user_ou}")
            name_parts = odoo_user.name.split(' ', 1)
            given_name = name_parts[0] if name_parts else odoo_user.login
            surname = name_parts[1] if len(name_parts) > 1 else given_name
            uid_number = self._get_next_uid_number()
            gid_number = self._get_next_gid_number()
            user_attrs = {
                'objectClass': [b'inetOrgPerson', b'posixAccount', b'shadowAccount'],
                'uid': [odoo_user.login.encode('utf-8')],
                'cn': [odoo_user.name.encode('utf-8')],
                'givenName': [given_name.encode('utf-8')],
                'sn': [surname.encode('utf-8')],
                'mail': [odoo_user.email.encode('utf-8')] if odoo_user.email else [odoo_user.login.encode('utf-8')],
                'displayName': [odoo_user.name.encode('utf-8')],
                'uidNumber': [str(uid_number).encode('utf-8')],
                'gidNumber': [str(gid_number).encode('utf-8')],
                'homeDirectory': [f'/home/{odoo_user.login}'.encode('utf-8')],
                'loginShell': [b'/bin/bash'],
            }
            if password and self.ldap_argon2_enabled:
                ph = argon2.PasswordHasher()
                hashed_password = ph.hash(password)
                argon2_password = f"{{ARGON2}}{hashed_password}"
                user_attrs['userPassword'] = [argon2_password.encode('utf-8')]
            conn.add_s(user_dn, list(user_attrs.items()))
            _logger.info(f"LSE LDAP: Successfully created LDAP user {odoo_user.login} with DN: {user_dn}")
            try:
                verify_results = conn.search_s(user_dn, ldap.SCOPE_BASE, '(objectClass=*)', ['uid'])
                if verify_results:
                    _logger.info(f"LSE LDAP: Verified user creation - found user at DN: {user_dn}")
                else:
                    _logger.error(f"LSE LDAP: User creation verification failed - user not found at DN: {user_dn}")
                    return False
            except Exception as verify_error:
                _logger.error(f"LSE LDAP: User creation verification failed: {verify_error}")
                return False
            return True
        except Exception as e:
            _logger.error(f"LSE LDAP: Error creating LDAP user {odoo_user.login}: {e}")
            import traceback
            _logger.error(f"LSE LDAP: Traceback: {traceback.format_exc()}")
            return False
        finally:
            if conn:
                conn.unbind_s()
    def _update_ldap_user_password(self, odoo_user, password):
        if not password or not self.ldap_argon2_enabled:
            return False
        conn = self._connect()
        if not conn:
            return False
        try:
            if self.ldap_binddn:
                conn.simple_bind_s(self.ldap_binddn, self.ldap_password or '')
            search_filter = self.ldap_filter % odoo_user.login
            results = conn.search_s(
                self.ldap_base,
                ldap.SCOPE_SUBTREE,
                search_filter,
                ['dn', 'userPassword']
            )
            if not results:
                _logger.warning(f"LSE LDAP: User {odoo_user.login} not found for password update")
                return False
            user_dn = results[0][0]
            user_attrs = results[0][1]
            stored_password = user_attrs.get('userPassword', [b''])[0]
            if isinstance(stored_password, bytes):
                stored_password = stored_password.decode('utf-8')
            if stored_password.startswith('{ARGON2}'):
                ph_check = argon2.PasswordHasher()
                try:
                    ph_check.verify(stored_password[8:], password)
                    _logger.info(f"LSE LDAP: LDAP password already matches for {odoo_user.login}, skipping update")
                    return True
                except argon2.exceptions.VerifyMismatchError:
                    _logger.info(f"LSE LDAP: LDAP password mismatch for {odoo_user.login}, updating")
            ph = argon2.PasswordHasher()
            hashed_password = ph.hash(password)
            argon2_password = f"{{ARGON2}}{hashed_password}"
            mod_attrs = [(ldap.MOD_REPLACE, 'userPassword', [argon2_password.encode('utf-8')])]
            conn.modify_s(user_dn, mod_attrs)
            _logger.info(f"LSE LDAP: Successfully updated password for LDAP user {odoo_user.login}")
            return True
        except Exception as e:
            _logger.error(f"LSE LDAP: Error updating password for LDAP user {odoo_user.login}: {e}")
            return False
        finally:
            if conn:
                conn.unbind_s()
    def _map_odoo_groups_to_ldap(self, odoo_user):
        if not self.auto_create_ldap_users:
            return False
        # groups_id removed in Odoo 19 — fetch via SQL
        self.env.cr.execute(
            "SELECT gid FROM res_groups_users_rel WHERE uid = %s",
            (odoo_user.id,)
        )
        user_group_ids = {row[0] for row in self.env.cr.fetchall()}
        mapped_ldap_groups = []
        for mapping in self.odoo_ldap_mappings:
            if any(g.id in user_group_ids for g in mapping.odoo_groups):
                mapped_ldap_groups.extend(mapping.ldap_groups.mapped('name'))
        if not mapped_ldap_groups:
            _logger.info(f"LSE LDAP: No LDAP group mappings found for Odoo user {odoo_user.login}")
            return True
        return self._update_ldap_group_membership(odoo_user, mapped_ldap_groups)
    def _update_ldap_group_membership(self, odoo_user, ldap_group_names):
        conn = self._connect()
        if not conn:
            return False
        try:
            if self.ldap_binddn:
                conn.simple_bind_s(self.ldap_binddn, self.ldap_password or '')
            search_filter = self.ldap_filter % odoo_user.login
            user_results = conn.search_s(
                self.ldap_base,
                ldap.SCOPE_SUBTREE,
                search_filter,
                ['dn']
            )
            if not user_results:
                _logger.warning(f"LSE LDAP: User {odoo_user.login} not found for group membership update")
                return False
            user_dn = user_results[0][0]
            for group_name in ldap_group_names:
                group_results = conn.search_s(
                    self.ldap_base,
                    ldap.SCOPE_SUBTREE,
                    f'(&(objectClass=groupOfNames)(cn={group_name}))',
                    ['member']
                )
                if group_results:
                    group_dn, group_attrs = group_results[0]
                    current_members = [member.decode('utf-8') for member in group_attrs.get('member', [])]
                    if user_dn not in current_members:
                        mod_attrs = [(ldap.MOD_ADD, 'member', [user_dn.encode('utf-8')])]
                        conn.modify_s(group_dn, mod_attrs)
                        _logger.info(f"LSE LDAP: Added user {odoo_user.login} to LDAP group {group_name}")
            return True
        except Exception as e:
            _logger.error(f"LSE LDAP: Error updating group membership for {odoo_user.login}: {e}")
            return False
        finally:
            if conn:
                conn.unbind_s()
    def sync_odoo_user_to_ldap(self, odoo_user, password=None):
        if not self.auto_create_ldap_users:
            return False
        try:
            if not self._user_exists_in_ldap(odoo_user.login):
                _logger.info(f"LSE LDAP: Creating new LDAP user for {odoo_user.login}")
                if self._create_ldap_user(odoo_user, password):
                    self._map_odoo_groups_to_ldap(odoo_user)
            else:
                _logger.info(f"LSE LDAP: Updating existing LDAP user {odoo_user.login}")
                if password:
                    self._update_ldap_user_password(odoo_user, password)
                self._map_odoo_groups_to_ldap(odoo_user)
            return True
        except Exception as e:
            _logger.error(f"LSE LDAP: Error syncing Odoo user {odoo_user.login} to LDAP: {e}")
            return False

