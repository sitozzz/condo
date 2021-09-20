/**
 * Generated by `createschema subscription.ServiceSubscription 'type:Select:default,sbbol; isTrial:Checkbox; organization:Relationship:Organization:CASCADE; startAt:DateTimeUtc; finishAt:DateTimeUtc;'`
 * In most cases you should not change it by hands
 * Please, don't remove `AUTOGENERATE MARKER`s
 */
const faker = require('faker')

const { generateServerUtils, execGqlWithoutAccess } = require('@condo/domains/common/utils/codegeneration/generate.server.utils')

const { generateGQLTestUtils, throwIfError } = require('@condo/domains/common/utils/codegeneration/generate.test.utils')

const { ServiceSubscription: ServiceSubscriptionGQL } = require('@condo/domains/subscription/gql')
/* AUTOGENERATE MARKER <IMPORT> */

const ServiceSubscription = generateGQLTestUtils(ServiceSubscriptionGQL)
/* AUTOGENERATE MARKER <CONST> */

async function createTestServiceSubscription (client, organization, extraAttrs = {}) {
    if (!client) throw new Error('no client')
    if (!organization || !organization.id) throw new Error('no organization.id')
    const sender = { dv: 1, fingerprint: faker.random.alphaNumeric(8) }

    // TODO(codegen): write createTestServiceSubscription logic for generate fields

    const attrs = {
        dv: 1,
        sender,
        organization: { connect: { id: organization.id } },
        ...extraAttrs,
    }
    const obj = await ServiceSubscription.create(client, attrs)
    return [obj, attrs]
}

async function updateTestServiceSubscription (client, id, extraAttrs = {}) {
    if (!client) throw new Error('no client')
    if (!id) throw new Error('no id')
    const sender = { dv: 1, fingerprint: faker.random.alphaNumeric(8) }

    // TODO(codegen): check the updateTestServiceSubscription logic for generate fields

    const attrs = {
        dv: 1,
        sender,
        ...extraAttrs,
    }
    const obj = await ServiceSubscription.update(client, id, attrs)
    return [obj, attrs]
}

/* AUTOGENERATE MARKER <FACTORY> */

module.exports = {
    ServiceSubscription, createTestServiceSubscription, updateTestServiceSubscription,
/* AUTOGENERATE MARKER <EXPORTS> */
}