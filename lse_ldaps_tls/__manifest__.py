{
    'name': 'Enterprise LDAPS',
    'version': '19.0.0.2.0',
    'category': 'Authentication',
    'summary': 'TLS 1.3-only LDAPS authentication — WolfSSL hardened, PCI DSS compliant, Argon2 hashing',
    'author': 'LSE Group',
    'website': 'https://lumanet.info',
    'maintainer': 'LSE Group <support@lumanet.info>',
    'license': 'OPL-1',
    'depends': ['base', 'base_setup'],
    'data': [
        'security/ir.model.access.csv',
        'views/res_company_ldap_views.xml',
        'views/res_config_settings_views.xml',
        'data/data.xml',
    ],
    'assets': {
        'web.assets_backend': [
            'lse_ldaps_tls/static/src/css/custom_widget.css',
            'lse_ldaps_tls/static/src/js/custom_widget.js',
        ],
    },
    'external_dependencies': {
        'python': ['ldap', 'argon2-cffi'],
    },
    'installable': True,
    'auto_install': False,
    'application': False,
    'sequence': 1,
    'images': ['static/description/banner.png'],
    'price': 349.00,
    'currency': 'USD',
    'live_test_url': 'https://lumanet.info',
}