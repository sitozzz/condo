/**
 * Generated by `createschema billing.BillingOrganization 'context:Relationship:BillingIntegrationOrganizationContext:CASCADE; tin:Text; iec:Text; bic:Text; checkNumber:Text;'`
 */

const { makeOrganizationIntegrationManager, createTestBillingIntegrationOrganizationContext, makeContextWithOrganizationAndIntegrationAsAdmin } = require('../utils/testSchema')
const { makeLoggedInAdminClient, makeClient } = require('@core/keystone/test.utils')
const { BillingOrganization, createTestBillingOrganization, updateTestBillingOrganization } = require('@condo/domains/billing/utils/testSchema')
const { makeClientWithNewRegisteredAndLoggedInUser } = require('@condo/domains/user/utils/testSchema')
const { expectToThrowAccessDeniedErrorToObj, expectToThrowAccessDeniedErrorToObjects } = require('@condo/domains/common/utils/testSchema')


describe('BillingOrganization', () => {
    test('admin: create BillingOrganization', async () => {
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [org, attrs] = await createTestBillingOrganization(admin, context)
        expect(org.context.id).toEqual(attrs.context.connect.id)
    })

    test('user: create BillingOrganization', async () => {
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const client = await makeClientWithNewRegisteredAndLoggedInUser()

        await expectToThrowAccessDeniedErrorToObj(async () => {
            await createTestBillingOrganization(client, context)
        })
    })

    test('anonymous: create BillingOrganization', async () => {
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const client = await makeClient()

        await expectToThrowAccessDeniedErrorToObj(async () => {
            await createTestBillingOrganization(client, context)
        })
    })

    test('organization integration manager: create BillingOrganization', async () => {
        const { organization, integration, managerUserClient } = await makeOrganizationIntegrationManager()
        const [context] = await createTestBillingIntegrationOrganizationContext(managerUserClient, organization, integration)
        const [org, attrs] = await createTestBillingOrganization(managerUserClient, context)
        expect(org.context.id).toEqual(attrs.context.connect.id)
    })

    test('admin: read BillingOrganization', async () => {
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [org] = await createTestBillingOrganization(admin, context)
        const orgs = await BillingOrganization.getAll(admin, { id: org.id })

        expect(orgs).toHaveLength(1)
    })

    test('user: read BillingOrganization', async () => {
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        await createTestBillingOrganization(admin, context)
        const client = await makeClientWithNewRegisteredAndLoggedInUser()
        const orgs = await BillingOrganization.getAll(client)

        expect(orgs).toHaveLength(0)
    })

    test('anonymous: read BillingOrganization', async () => {
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        await createTestBillingOrganization(admin, context)
        const client = await makeClient()

        await expectToThrowAccessDeniedErrorToObjects(async () => {
            await BillingOrganization.getAll(client)
        })
    })

    test('organization integration manager: read BillingOrganization', async () => {
        const { organization, integration, managerUserClient } = await makeOrganizationIntegrationManager()
        const [context] = await createTestBillingIntegrationOrganizationContext(managerUserClient, organization, integration)
        const [org] = await createTestBillingOrganization(managerUserClient, context)

        const props = await BillingOrganization.getAll(managerUserClient, { id: org.id })
        expect(props).toHaveLength(1)
    })

    test('admin: update BillingOrganization', async () => {
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [org] = await createTestBillingOrganization(admin, context)

        const payload = {
            tin: '12345',
        }
        const [updated] = await updateTestBillingOrganization(admin, org.id, payload)

        expect(updated.tin).toEqual('12345')
    })

    test('user: update BillingOrganization', async () => {
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingOrganization(admin, context)
        const client = await makeClientWithNewRegisteredAndLoggedInUser()
        const payload = {
            tin: '12345',
        }
        await expectToThrowAccessDeniedErrorToObj(async () => {
            await updateTestBillingOrganization(client, property.id, payload)
        })
    })

    test('organization integration manager: update BillingOrganization', async () => {
        const { organization, integration, managerUserClient } = await makeOrganizationIntegrationManager()
        const [context] = await createTestBillingIntegrationOrganizationContext(managerUserClient, organization, integration)
        const [property] = await createTestBillingOrganization(managerUserClient, context)
        const payload = {
            tin: '12345',
        }
        const [updated] = await updateTestBillingOrganization(managerUserClient, property.id, payload)

        expect(updated.tin).toEqual('12345')
    })

    test('anonymous: update BillingOrganization', async () => {
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingOrganization(admin, context)
        const client = await makeClient()
        const payload = {
            tin: '12345',
        }

        await expectToThrowAccessDeniedErrorToObj(async () => {
            await updateTestBillingOrganization(client, property.id, payload)
        })
    })

    test('admin: delete BillingOrganization', async () => {
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingOrganization(admin, context)

        await expectToThrowAccessDeniedErrorToObj(async () => {
            await BillingOrganization.delete(admin, property.id)
        })
    })

    test('user: delete BillingOrganization', async () => {
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingOrganization(admin, context)
        const client = await makeClientWithNewRegisteredAndLoggedInUser()

        await expectToThrowAccessDeniedErrorToObj(async () => {
            await BillingOrganization.delete(client, property.id)
        })
    })

    test('anonymous: delete BillingOrganization', async () => {
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingOrganization(admin, context)
        const client = await makeClient()

        await expectToThrowAccessDeniedErrorToObj(async () => {
            await BillingOrganization.delete(client, property.id)
        })
    })

    test('organization integration manager: delete BillingOrganization', async () => {
        const { organization, integration, managerUserClient } = await makeOrganizationIntegrationManager()
        const [context] = await createTestBillingIntegrationOrganizationContext(managerUserClient, organization, integration)
        const [property] = await createTestBillingOrganization(managerUserClient, context)

        await expectToThrowAccessDeniedErrorToObj(async () => {
            await BillingOrganization.delete(managerUserClient, property.id)
        })
    })
})