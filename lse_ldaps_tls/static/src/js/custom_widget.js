/** @odoo-module **/
import { registry } from "@web/core/registry";
import { Many2ManyTagsField } from "@web/views/fields/many2many_tags/many2many_tags_field";
export class LdapMany2ManyTagsField extends Many2ManyTagsField {
    setup() {
        super.setup();
    }
    get displayName() {
        return super.displayName;
    }
    getTagProps(record) {
        const props = super.getTagProps(record);
        const colorClass = this.getColorClass(record);
        if (colorClass) {
            props.class = `${props.class || ''} ${colorClass}`.trim();
        }
        return props;
    }
    getColorClass(record) {
        if (!record || !record.data) {
            return null;
        }
        const fieldName = this.props.name;
        if (fieldName === 'ldap_groups') {
            if (this.isOU(record)) {
                return 'ldap-ou-color';
            } else {
                return 'ldap-group-color';
            }
        }
        if (fieldName === 'odoo_groups') {
            if (this.isUserType(record)) {
                return 'odoo-usertype-color';
            } else {
                return 'odoo-other-color';
            }
        }
        return null;
    }
    isOU(record) {
        if (!record || !record.data || !record.data.display_name) {
            return false;
        }
        const name = record.data.display_name.toString();
        return name.toLowerCase().includes('ou=') || name.toLowerCase().includes('organizational unit');
    }
    isUserType(record) {
        if (!record || !record.data || !record.data.display_name) {
            return false;
        }
        const name = record.data.display_name.toString();
        const userTypeNames = ['portal', 'internal user', 'public'];
        return userTypeNames.some(type => 
            name.toLowerCase().includes(type.toLowerCase())
        );
    }
}
registry.category("fields").add("ldap_many2many_tags", {
    component: LdapMany2ManyTagsField,
    supportedTypes: Many2ManyTagsField.supportedTypes,
    extractProps: Many2ManyTagsField.extractProps,
});
