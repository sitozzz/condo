/**
 * Generated by `createschema contact.Contact 'property:Relationship:Property:SET_NULL; name:Text; phone:Text; unitName?:Text; email?:Text;'`
 */

const { Text, Relationship } = require('@keystonejs/fields')
const { Json } = require('@core/keystone/fields')
const { GQLListSchema } = require('@core/keystone/schema')
const { historical, versioned, uuided, tracked, softDeleted } = require('@core/keystone/plugins')
const { SENDER_FIELD, DV_FIELD } = require('@condo/domains/common/schema/fields')
const access = require('@condo/domains/contact/access/Contact')
const { normalizePhone } = require('@condo/domains/common/utils/phone')


const Contact = new GQLListSchema('Contact', {
    schemaDoc: 'Contact information of a person. Currently it will be related to a ticket, but in the future, it will be associated with more things',
    fields: {
        dv: DV_FIELD,
        sender: SENDER_FIELD,

        property: {
            schemaDoc: 'Property, that is a subject of an issue, reported by this person in first ticket. Meaning of this field will be revised in the future',
            type: Relationship,
            ref: 'Property',
            isRequired: true,
            knexOptions: { isNotNullable: true }, // Required relationship only!
            kmigratorOptions: { null: false, on_delete: 'models.PROTECT' },
        },

        unitName: {
            schemaDoc: 'Property unit, that is a subject of an issue, reported by this person in first ticket. Meaning of this field will be revised in the future',
            type: Text,
            isRequired: false,
        },

        email: {
            schemaDoc: 'Normalized contact email of this person',
            type: Text,
            isRequired: false,
            hooks: {
                resolveInput: async ({ resolvedData }) => {
                    return resolvedData['email'] && resolvedData['email'].toLowerCase()
                },
            },
        },

        phone: {
            schemaDoc: 'Normalized contact phone of this person in E.164 format without spaces',
            type: Text,
            isRequired: true,
            hooks: {
                resolveInput: async ({ resolvedData }) => (
                    normalizePhone(resolvedData['phone'])
                ),
            },
        },

        name: {
            schemaDoc: 'Name or full name of this person',
            type: Text,
            isRequired: true,
        },

    },
    plugins: [uuided(), versioned(), tracked(), softDeleted(), historical()],
    access: {
        read: access.canReadContacts,
        create: access.canManageContacts,
        update: access.canManageContacts,
        delete: false,
        auth: true,
    },
})

module.exports = {
    Contact,
}
