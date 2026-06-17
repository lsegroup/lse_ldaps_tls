from odoo import http, SUPERUSER_ID, api, fields
from odoo.http import request
from odoo.addons.web.controllers.home import Home
import logging

_logger = logging.getLogger(__name__)

class LSEAuthController(Home):
    @http.route('/web/login', type='http', auth="none", methods=['GET', 'POST'], csrf=False)
    def web_login(self, redirect=None, **kw):
        if request.httprequest.method == 'POST':
            login = kw.get('login')
            password = kw.get('password')
            if login and password:
                _logger.info(f"LSE LDAP: Intercepting authentication for {login}")
                try:
                    env = api.Environment(request.env.cr, SUPERUSER_ID, {})
                    ldap_configs = env['res.company.ldap.lse'].search([('active', '=', True)])
                    for ldap_config in ldap_configs:
                        if ldap_config._user_exists_in_ldap(login):
                            _logger.info(f"LSE LDAP: User {login} found in LDAP directory")
                            user_ldap_groups = ldap_config._get_user_ldap_groups(login)
                            _logger.info(f"LSE LDAP: User {login} belongs to LDAP groups: {user_ldap_groups}")
                            odoo_groups = ldap_config._map_ldap_groups_to_odoo(user_ldap_groups)
                            _logger.info(f"LSE LDAP: Mapped to Odoo groups: {[(g.name.get('en_US', '') if isinstance(g.name, dict) else str(g.name)) for g in odoo_groups]}")
                            user = env['res.users'].search([('login', '=', login)], limit=1)
                            if not user:
                                _logger.info(f"LSE LDAP: Creating new user {login}")
                                user = env['res.users'].create({
                                    'login': login,
                                    'email': login,
                                    'name': login,
                                    'active': True,
                                })
                                env.cr.flush()
                                group_user   = env.ref('base.group_user',   raise_if_not_found=False)
                                group_portal = env.ref('base.group_portal', raise_if_not_found=False)
                                group_public = env.ref('base.group_public', raise_if_not_found=False)
                                user_type_ids = tuple(g.id for g in [group_user, group_portal, group_public] if g)
                                if user_type_ids:
                                    env.cr.execute(
                                        "DELETE FROM res_groups_users_rel WHERE uid = %s AND gid IN %s",
                                        (user.id, user_type_ids)
                                    )
                                for group_id in odoo_groups.ids:
                                    env.cr.execute(
                                        "INSERT INTO res_groups_users_rel (gid, uid) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                                        (group_id, user.id)
                                    )
                            else:
                                _logger.info(f"LSE LDAP: Updating existing user {login} with group mappings")
                                user.write({'active': True})
                                all_managed_ids = set()
                                for mapping in ldap_config.ldap_odoo_mappings:
                                    all_managed_ids.update(mapping.odoo_groups.ids)
                                env.cr.flush()
                                if all_managed_ids:
                                    env.cr.execute(
                                        "DELETE FROM res_groups_users_rel WHERE uid = %s AND gid IN %s",
                                        (user.id, tuple(all_managed_ids))
                                    )
                                for group_id in odoo_groups.ids:
                                    env.cr.execute(
                                        "INSERT INTO res_groups_users_rel (gid, uid) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                                        (group_id, user.id)
                                    )
                            env['res.users'].invalidate_model()
                            ldap_entry = ldap_config.authenticate(login, password)
                            if ldap_entry:
                                _logger.info(f"LSE LDAP: Authentication successful for {login}")
                                # Update profile WITHOUT password to avoid ORM password
                                # setter triggering group reset via _set_password()
                                user.write({
                                    'name': ldap_entry.get('cn', [b''])[0].decode('utf-8') if ldap_entry.get('cn') else login,
                                    'ldap_uid': ldap_entry.get('uid', [b''])[0].decode('utf-8') if ldap_entry.get('uid') else '',
                                    'ldap_last_auth': fields.Datetime.now(),
                                })
                                # Update password directly via SQL only if it doesn't already match
                                crypt_context = env['res.users']._crypt_context()
                                env.cr.execute(
                                    "SELECT password FROM res_users WHERE id = %s", (user.id,)
                                )
                                current_hash = env.cr.fetchone()
                                password_needs_update = True
                                if current_hash and current_hash[0]:
                                    try:
                                        crypt_context.verify(password, current_hash[0])
                                        password_needs_update = False
                                        _logger.info(f"LSE LDAP: Odoo password already matches for {login}, skipping SQL update")
                                    except Exception:
                                        pass
                                if password_needs_update:
                                    hashed_password = crypt_context.hash(password)
                                    env.cr.execute(
                                        "UPDATE res_users SET password = %s, write_date = now() AT TIME ZONE 'UTC' WHERE id = %s",
                                        (hashed_password, user.id)
                                    )
                                    _logger.info(f"LSE LDAP: Password updated via direct SQL for {login}")
                                env.cr.flush()
                                env.cr.commit()
                                env.invalidate_all()
                                _logger.info(f"LSE LDAP: User {login} created/updated and committed")
                                if ldap_config.auto_create_ldap_users:
                                    try:
                                        ldap_config.sync_odoo_user_to_ldap(user, password)
                                        _logger.info(f"LSE LDAP: Odoo→LDAP sync completed for {login}")
                                    except Exception as sync_error:
                                        _logger.error(f"LSE LDAP: Odoo→LDAP sync failed for {login}: {sync_error}")
                                break
                            else:
                                _logger.warning(f"LSE LDAP: Authentication failed for {login}")
                                env.cr.rollback()
                        else:
                            _logger.info(f"LSE LDAP: User {login} not found in LDAP directory")
                            user = env['res.users'].search([('login', '=', login)], limit=1)
                            if user and ldap_config.auto_create_ldap_users:
                                try:
                                    ldap_config.sync_odoo_user_to_ldap(user, password)
                                    _logger.info(f"LSE LDAP: Successfully synced Odoo user {login} to LDAP")
                                except Exception as sync_error:
                                    _logger.error(f"LSE LDAP: Failed to sync Odoo user {login} to LDAP: {sync_error}")
                except Exception as e:
                    _logger.error(f"LSE LDAP: Error during LDAP pre-auth: {e}")
                    try:
                        request.env.cr.rollback()
                    except Exception:
                        pass
        return super().web_login(redirect=redirect, **kw)
