/**
 * Generated by `createschema ticket.Ticket organization:Text; statusReopenedCounter:Integer; statusReason?:Text; status:Relationship:TicketStatus:PROTECT; number?:Integer; client?:Relationship:User:SET_NULL; clientName:Text; clientEmail:Text; clientPhone:Text; operator:Relationship:User:SET_NULL; assignee?:Relationship:User:SET_NULL; classifier:Relationship:TicketClassifier:PROTECT; details:Text; meta?:Json;`
 */

const { Text, Relationship, Integer, DateTimeUtc, Checkbox } = require('@keystonejs/fields')
const { GQLListSchema } = require('@core/keystone/schema')
const { Json, AutoIncrementInteger } = require('@core/keystone/fields')
const { historical, versioned, uuided, tracked, softDeleted } = require('@core/keystone/plugins')

const { SENDER_FIELD, DV_FIELD } = require('@condo/domains/common/schema/fields')
const access = require('@condo/domains/ticket/access/Ticket')
const { triggersManager } = require('@core/triggers')
const { OMIT_TICKET_CHANGE_TRACKABLE_FIELDS } = require('../constants')
const { buildSetOfFieldsToTrackFrom } = require('@condo/domains/common/utils/serverSchema/changeTrackable')
const { storeChangesIfUpdated } = require('@condo/domains/common/utils/serverSchema/changeTrackable')
const { ORGANIZATION_OWNED_FIELD } = require('../../../schema/_common')
const { hasRequestAndDbFields } = require('@condo/domains/common/utils/validation.utils')
const { JSON_EXPECT_OBJECT_ERROR, DV_UNKNOWN_VERSION_ERROR, STATUS_UPDATED_AT_ERROR, JSON_UNKNOWN_VERSION_ERROR } = require('@condo/domains/common/constants/errors')
const { createTicketChange, ticketChangeDisplayNameResolversForSingleRelations, relatedManyToManyResolvers } = require('../utils/serverSchema/TicketChange')

const Ticket = new GQLListSchema('Ticket', {
    schemaDoc: 'Users request or contact with the user',
    fields: {
        dv: DV_FIELD,
        sender: SENDER_FIELD,

        // TODO(pahaz): no needed to check organization access!
        organization: ORGANIZATION_OWNED_FIELD,

        // statusDeadline
        // statusDeferredDate
        // statusDeferredBy
        // TODO(pahaz): server side autogen
        statusReopenedCounter: {
            schemaDoc: 'Counter showing the number of changes `status` to `new_or_reopened`',
            type: Integer,
            isRequired: true,
            defaultValue: 0,
            access: {
                read: true,
                update: false,
                create: false,
            },
        },
        // TODO(Dimitreee): server side auto generation
        statusUpdatedAt: {
            schemaDoc: 'Status updated at time',
            type: DateTimeUtc,
        },
        statusReason: {
            schemaDoc: 'Text reason for status changes. Sometimes you should describe the reason why you change the `status`',
            type: Text,
        },
        status: {
            schemaDoc: 'Status is the step of the ticket processing workflow. Companies may have different ticket processing workflows',
            type: Relationship,
            ref: 'TicketStatus',
            knexOptions: { isNotNullable: true }, // Required relationship only!
            kmigratorOptions: { null: false, on_delete: 'models.PROTECT' },
        },

        number: {
            schemaDoc: 'Autogenerated ticket human readable ID',
            type: AutoIncrementInteger,
            isRequired: false,
            kmigratorOptions: { unique: true, null: false },
        },

        client: {
            schemaDoc: 'Inhabitant/customer/person who has a problem or want to improve/order something. Not null if we have a registered client',
            type: Relationship,
            ref: 'User',
            kmigratorOptions: { null: true, on_delete: 'models.SET_NULL' },
        },
        clientName: {
            schemaDoc: 'Inhabitant/customer/person who has a problem. Sometimes we get a problem from an unregistered client, in such cases we have a null inside the `client` and just have something here. Or sometimes clients want to change it',
            type: Text,
        },
        clientEmail: {
            schemaDoc: 'Inhabitant/customer/person who has a problem. Sometimes we get a problem from an unregistered client, in such cases we have a null inside the `client` and just have something here. Or sometimes clients want to change it',
            type: Text,
        },
        clientPhone: {
            schemaDoc: 'Inhabitant/customer/person who has a problem. Sometimes we get a problem from an unregistered client, in such cases we have a null inside the `client` and just have something here. Or sometimes clients want to change it',
            type: Text,
        },

        operator: {
            schemaDoc: 'Staff/person who created the issue (submitter). This may be a call center operator or an employee who speaks to a inhabitant/client and filled out an issue for him',
            type: Relationship,
            ref: 'User',
            kmigratorOptions: { null: true, on_delete: 'models.SET_NULL' },
        },
        // operatorMeta: {
        //     type: Json,
        //     schemaDoc: 'For external analytics about the operator who created the issue. Example: geolocation, contact type, ...',
        // },

        // Integrations!?
        // hookStatus
        // hookResult

        // department?
        // who close
        // who accept

        assignee: {
            schemaDoc: 'Assignee/responsible employee/user who must ensure that the issue is fulfilled',
            type: Relationship,
            ref: 'User',
            kmigratorOptions: { null: true, on_delete: 'models.SET_NULL' },
        },
        executor: {
            schemaDoc: 'Executor employee/user who perform the issue',
            type: Relationship,
            ref: 'User',
            kmigratorOptions: { null: true, on_delete: 'models.SET_NULL' },
        },
        watchers: {
            schemaDoc: 'Staff/person who want to watch ticket changes',
            type: Relationship,
            ref: 'User',
            many: true,
        },
        // classifierMeta
        classifier: {
            schemaDoc: 'Typification / classification / types of work',
            type: Relationship,
            ref: 'TicketClassifier',
            isRequired: true,
            knexOptions: { isNotNullable: true }, // Required relationship only!
            kmigratorOptions: { null: false, on_delete: 'models.PROTECT' },
        },

        // description / title
        details: {
            schemaDoc: 'Text description of the issue. Maybe written by a user or an operator',
            type: Text,
            isRequired: true,
        },
        related: {
            schemaDoc: 'Sometimes, it is important for us to show related issues. For example, to show related issues',
            type: Relationship,
            ref: 'Ticket',
            kmigratorOptions: { null: true, on_delete: 'models.SET_NULL' },
        },
        isPaid: {
            schemaDoc: 'Indicates the ticket is paid',
            type: Checkbox,
            defaultValue: false,
            isRequired: true,
        },
        isEmergency: {
            schemaDoc: 'Indicates the ticket is emergency',
            type: Checkbox,
            defaultValue: false,
            isRequired: true,
        },
        meta: {
            schemaDoc: 'Extra analytics not related to remote system',
            type: Json,
            isRequired: false,
            hooks: {
                validateInput: ({ resolvedData, fieldPath, addFieldValidationError }) => {
                    if (!resolvedData.hasOwnProperty(fieldPath)) return // skip if on value
                    const value = resolvedData[fieldPath]
                    if (value === null) return // null is OK
                    if (typeof value !== 'object') {return addFieldValidationError(`${JSON_EXPECT_OBJECT_ERROR}${fieldPath}] ${fieldPath} field type error. We expect JSON Object`)}
                    const { dv } = value
                    if (dv === 1) {
                        // TODO(pahaz): need to checkIt!
                    } else {
                        return addFieldValidationError(`${JSON_UNKNOWN_VERSION_ERROR}${fieldPath}] Unknown \`dv\` attr inside JSON Object`)
                    }
                },
            },
        },

        // Where?
        // building/community
        // entrance/section
        // floor
        // premise/unit
        // placeDetail (behind the radiator, on the fifth step of the stairs)
        // Intercom code
        property: {
            schemaDoc: 'Property related to the Ticket',
            type: Relationship,
            ref: 'Property',
            isRequired: true,
            knexOptions: { isNotNullable: true }, // Relationship only!
            kmigratorOptions: { null: false, on_delete: 'models.PROTECT' },
        },

        entranceName: {
            schemaDoc: 'Entrance name/number of an apartment building (property). You need to take from Property.map',
            type: Text,
        },
        floorName: {
            schemaDoc: 'Floor of an apartment building (property). You need to take from Property.map',
            type: Text,
        },
        // TODO(pahaz): make a link to property domain fields
        unitName: {
            schemaDoc: 'Flat number / door number of an apartment building (property). You need to take from Property.map',
            type: Text,
        },


        source: {
            schemaDoc: 'Ticket source channel/system. Examples: call, email, visit, ...',
            type: Relationship,
            ref: 'TicketSource',
            isRequired: true,
            knexOptions: { isNotNullable: true }, // Relationship only!
            kmigratorOptions: { null: false, on_delete: 'models.PROTECT' },
        },
        sourceMeta: {
            schemaDoc: 'In the case of remote system sync, you can store some extra analytics. Examples: email, name, phone, ...',
            type: Json,
        },
    },
    plugins: [uuided(), versioned(), tracked(), softDeleted(), historical()],
    hooks: {
        resolveInput: async ({ operation, listKey, context, resolvedData, existingItem }) => {
            await triggersManager.executeTrigger({ operation, data: { resolvedData, existingItem }, listKey }, context)

            return resolvedData
        },
        validateInput: ({ resolvedData, existingItem, addValidationError, operation }) => {
            if (!hasRequestAndDbFields(['dv', 'sender'], ['organization', 'source', 'status', 'classifier', 'details'], resolvedData, existingItem, addValidationError)) return
            const { dv } = resolvedData
            if (dv === 1) {
                // NOTE: version 1 specific translations. Don't optimize this logic
                if (resolvedData.statusUpdatedAt) {
                    if (existingItem.statusUpdatedAt) {
                        if (new Date(resolvedData.statusUpdatedAt) <= new Date(existingItem.statusUpdatedAt)) {
                            return addValidationError(`${ STATUS_UPDATED_AT_ERROR }statusUpdatedAt] Incorrect \`statusUpdatedAt\``)
                        }
                    } else {
                        if (new Date(resolvedData.statusUpdatedAt) <= new Date(existingItem.createdAt)) {
                            return addValidationError(`${ STATUS_UPDATED_AT_ERROR }statusUpdatedAt] Incorrect \`statusUpdatedAt\``)
                        }
                    }
                }
            } else {
                return addValidationError(`${ DV_UNKNOWN_VERSION_ERROR }dv] Unknown \`dv\``)
            }
        },
        // `beforeChange` cannot be used, because data can be manipulated during updating process somewhere inside a ticket
        // We need a final result after update
        afterChange: async (...args) => {
            /**
             * Creates a new TicketChange item.
             * 👉 When a new "single" or "many" relation field will be added to Ticket,
             * new resolver should be implemented in `ticketChangeDisplayNameResolversForSingleRelations` and `relatedManyToManyResolvers`
             */
            await storeChangesIfUpdated(
                buildSetOfFieldsToTrackFrom(Ticket.schema, { except: OMIT_TICKET_CHANGE_TRACKABLE_FIELDS }),
                createTicketChange,
                ticketChangeDisplayNameResolversForSingleRelations,
                relatedManyToManyResolvers
            )(...args)
        },
    },
    access: {
        read: access.canReadTickets,
        create: access.canManageTickets,
        update: access.canManageTickets,
        delete: false,
        auth: true,
    },
})

module.exports = {
    Ticket,
}
