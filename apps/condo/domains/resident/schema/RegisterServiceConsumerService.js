/**
 * Generated by `createservice resident.RegisterServiceConsumerService --type mutations`
 */

const { AcquiringIntegrationContext } = require('@condo/domains/acquiring/utils/serverSchema')
const { getById, GQLCustomSchema } = require('@core/keystone/schema')
const access = require('@condo/domains/resident/access/RegisterServiceConsumerService')
const { BillingIntegrationOrganizationContext, BillingAccount } = require('@condo/domains/billing/utils/serverSchema')
const { ServiceConsumer, Resident } = require('../utils/serverSchema')
const { NOT_FOUND_ERROR, REQUIRED_NO_VALUE_ERROR } = require('@condo/domains/common/constants/errors')
const { Meter } = require('@condo/domains/meter/utils/serverSchema')
const { Organization } = require('@condo/domains/organization/utils/serverSchema')

const get = require('lodash/get')

async function getResidentBillingAccount (context, billingIntegrationContext, accountNumber, unitName) {
    let applicableBillingAccounts = await BillingAccount.getAll(context, {
        context: { id: billingIntegrationContext.id },
        unitName: unitName,
    })
    if (!Array.isArray(applicableBillingAccounts)) {
        return [] // No accounts are found for this user
    }
    applicableBillingAccounts = applicableBillingAccounts.filter(
        (billingAccount) => {
            return accountNumber === billingAccount.number || accountNumber === billingAccount.globalId
        }
    )
    return applicableBillingAccounts
}

const RegisterServiceConsumerService = new GQLCustomSchema('RegisterServiceConsumerService', {
    types: [
        {
            access: true,
            type: 'input RegisterServiceConsumerInput { dv: Int!, sender: SenderFieldInput!, residentId: ID!, accountNumber: String!, organizationId: ID! }',
        },
    ],

    mutations: [
        {
            schemaDoc: 'This mutation creates service consumer with default data, and automatically populates the optional data fields, such as `billingAccount`.' +
                ' To be successfully created accountNumber and unitName should at least have billingAccount with same data or Meter with same data',
            access: access.canRegisterServiceConsumer,
            schema: 'registerServiceConsumer(data: RegisterServiceConsumerInput!): ServiceConsumer',
            resolver: async (parent, args, context = {}) => {
                const { data: { dv, sender, residentId, accountNumber, organizationId } } = args

                if (!accountNumber || accountNumber.length === 0) { throw new Error(`${REQUIRED_NO_VALUE_ERROR}accountNumber] Account number null or empty: ${accountNumber}`) }

                const [ resident ] = await Resident.getAll(context, { id: residentId })
                if (!resident) {
                    throw new Error(`${NOT_FOUND_ERROR}resident] Resident not found for this user`)
                }

                const [ organization ] = await Organization.getAll(context, { id: organizationId })
                if (!organization) {
                    throw new Error(`${NOT_FOUND_ERROR}organization] Organization not found for this id`)
                }
                //TODO(zuch): Ask about wrong logic - resident unit name do not match billing account unitName
                const unitName = get(resident, ['unitName'])

                const attrs = {
                    dv,
                    sender,
                    resident: { connect: { id: residentId } },
                    accountNumber: accountNumber,
                    organization: { connect: { id: organization.id } },
                }

                const [ billingIntegrationContext ] = await BillingIntegrationOrganizationContext.getAll(context, { organization: { id: organization.id, deletedAt: null }, deletedAt: null })
                if (billingIntegrationContext) {

                    const [acquiringIntegrationContext] = await AcquiringIntegrationContext.getAll(context, { organization: { id: organization.id, deletedAt: null }, deletedAt: null })
                    const [billingAccount] = await getResidentBillingAccount(context, billingIntegrationContext, accountNumber, unitName)
                    attrs.billingAccount = billingAccount ? { connect: { id: billingAccount.id } } : null
                    attrs.billingIntegrationContext = billingAccount ? { connect: { id: billingIntegrationContext.id } } : null
                    attrs.acquiringIntegrationContext = billingAccount && acquiringIntegrationContext ? { connect: { id: acquiringIntegrationContext.id } } : null
                }
                if (!attrs.billingAccount) {
                    const meters = await Meter.getAll(context, { accountNumber: accountNumber, unitName: unitName, organization: { id: organizationId, deletedAt: null }, deletedAt: null })
                    if (meters.length < 1) {
                        throw (`${NOT_FOUND_ERROR}accountNumber] Can't find billingAccount and any meters with this accountNumber, unitName and organization combination`)
                    }
                }

                const [existingServiceConsumer] = await ServiceConsumer.getAll(context, {
                    resident: { id: residentId },
                    accountNumber: accountNumber,
                })

                let id
                if (existingServiceConsumer) {
                    await ServiceConsumer.update(context, existingServiceConsumer.id, {
                        ...attrs,
                        deletedAt: null,
                    })
                    id = existingServiceConsumer.id
                } else {
                    const serviceConsumer = await ServiceConsumer.create(context, attrs)
                    id = serviceConsumer.id
                }

                // Hack that helps to resolve all subfields in result of this mutation
                return await getById('ServiceConsumer', id)
            },
        },
    ],
})

module.exports = {
    RegisterServiceConsumerService,
}
