/**
 * Generated by `createschema billing.BillingAccountMeterReading 'context:Relationship:BillingIntegrationOrganizationContext:CASCADE; importId?:Text; property:Relationship:BillingProperty:CASCADE; account:Relationship:BillingAccount:CASCADE; meter:Relationship:BillingAccountMeter:CASCADE; period:CalendarDay; value1:Integer; value2:Integer; value3:Integer; date:DateTimeUtc; raw:Json; meta:Json' --force`
 */
const faker = require('faker')
const { createTestBillingIntegrationOrganizationContext } = require('@condo/domains/billing/utils/testSchema')
const { makeOrganizationIntegrationManager } = require('@condo/domains/billing/utils/testSchema')
const { makeContextWithOrganizationAndIntegrationAsAdmin } = require('@condo/domains/billing/utils/testSchema')
const { makeClientWithNewRegisteredAndLoggedInUser } = require('@condo/domains/user/utils/testSchema')
const { createTestBillingMeterResource } = require('@condo/domains/billing/utils/testSchema')
const { createTestBillingAccountMeter } = require('@condo/domains/billing/utils/testSchema')
const { createTestBillingAccount } = require('@condo/domains/billing/utils/testSchema')
const { createTestBillingProperty } = require('@condo/domains/billing/utils/testSchema')
const { makeLoggedInAdminClient, makeClient } = require('@core/keystone/test.utils')
const { BillingAccountMeterReading, createTestBillingAccountMeterReading, updateTestBillingAccountMeterReading } = require('@condo/domains/billing/utils/testSchema')
const { expectToThrowAuthenticationErrorToObjects, expectToThrowAuthenticationErrorToObj, expectToThrowAccessDeniedErrorToObj } = require('@condo/domains/common/utils/testSchema')

describe('BillingAccountMeterReading', () => {
    test('admin: create BillingAccountMeterReading', async () => {
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingProperty(admin, context)
        const [billingAccount] = await createTestBillingAccount(admin, context, property)
        const [resource] = await createTestBillingMeterResource(admin)
        const [meter] = await createTestBillingAccountMeter(admin, context, property, billingAccount, resource)
        const [obj] = await createTestBillingAccountMeterReading(admin, context, property, billingAccount, meter)

        expect(obj.context.id).toEqual(context.id)
        expect(obj.property.id).toEqual(property.id)
        expect(obj.account.id).toEqual(billingAccount.id)
        expect(obj.meter.id).toEqual(meter.id)
    })

    test('organization integration manager: create BillingAccountMeterReading', async () => {
        const admin = await makeLoggedInAdminClient()
        const { organization, integration, managerUserClient } = await makeOrganizationIntegrationManager()
        const [context] = await createTestBillingIntegrationOrganizationContext(managerUserClient, organization, integration)
        const [property] = await createTestBillingProperty(managerUserClient, context)
        const [billingAccount] = await createTestBillingAccount(managerUserClient, context, property)
        const [resource] = await createTestBillingMeterResource(admin)
        const [meter] = await createTestBillingAccountMeter(managerUserClient, context, property, billingAccount, resource)
        const [obj] = await createTestBillingAccountMeterReading(managerUserClient, context, property, billingAccount, meter)

        expect(obj.context.id).toEqual(context.id)
        expect(obj.property.id).toEqual(property.id)
        expect(obj.account.id).toEqual(billingAccount.id)
        expect(obj.meter.id).toEqual(meter.id)
    })

    test('user: create BillingAccountMeterReading', async () => {
        const client = await makeClientWithNewRegisteredAndLoggedInUser()
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingProperty(admin, context)
        const [billingAccount] = await createTestBillingAccount(admin, context, property)
        const [resource] = await createTestBillingMeterResource(admin)
        const [meter] = await createTestBillingAccountMeter(admin, context, property, billingAccount, resource)

        await expectToThrowAccessDeniedErrorToObj(async () => {
            await createTestBillingAccountMeterReading(client, context, property, billingAccount, meter)
        })
    })

    test('anonymous: create BillingAccountMeterReading', async () => {
        const client = await makeClient()
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingProperty(admin, context)
        const [billingAccount] = await createTestBillingAccount(admin, context, property)
        const [resource] = await createTestBillingMeterResource(admin)
        const [meter] = await createTestBillingAccountMeter(admin, context, property, billingAccount, resource)

        await expectToThrowAuthenticationErrorToObj(async () => {
            await createTestBillingAccountMeterReading(client, context, property, billingAccount, meter)
        })
    })

    test('admin: read BillingAccountMeterReading', async () => {
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingProperty(admin, context)
        const [billingAccount] = await createTestBillingAccount(admin, context, property)
        const [resource] = await createTestBillingMeterResource(admin)
        const [meter] = await createTestBillingAccountMeter(admin, context, property, billingAccount, resource)
        const [billingAccountMeterReading] = await createTestBillingAccountMeterReading(admin, context, property, billingAccount, meter)
        const objs = await BillingAccountMeterReading.getAll(admin, { id: billingAccountMeterReading.id })

        expect(objs).toHaveLength(1)
    })

    test('organization integration manager: read BillingAccountMeterReading', async () => {
        const admin = await makeLoggedInAdminClient()
        const { organization, integration, managerUserClient } = await makeOrganizationIntegrationManager()
        const [context] = await createTestBillingIntegrationOrganizationContext(managerUserClient, organization, integration)
        const [property] = await createTestBillingProperty(managerUserClient, context)
        const [billingAccount] = await createTestBillingAccount(managerUserClient, context, property)
        const [resource] = await createTestBillingMeterResource(admin)
        const [meter] = await createTestBillingAccountMeter(managerUserClient, context, property, billingAccount, resource)
        const [billingAccountMeterReading] = await createTestBillingAccountMeterReading(managerUserClient, context, property, billingAccount, meter)
        const objs = await BillingAccountMeterReading.getAll(managerUserClient, { id: billingAccountMeterReading.id })

        expect(objs).toHaveLength(1)
    })

    test('user: read BillingAccountMeterReading', async () => {
        const client = await makeClientWithNewRegisteredAndLoggedInUser()
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingProperty(admin, context)
        const [billingAccount] = await createTestBillingAccount(admin, context, property)
        const [resource] = await createTestBillingMeterResource(admin)
        const [meter] = await createTestBillingAccountMeter(admin, context, property, billingAccount, resource)
        await createTestBillingAccountMeterReading(admin, context, property, billingAccount, meter)
        const objs = await BillingAccountMeterReading.getAll(client)

        expect(objs).toHaveLength(0)
    })

    test('anonymous: read BillingAccountMeterReading', async () => {
        const client = await makeClient()
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingProperty(admin, context)
        const [billingAccount] = await createTestBillingAccount(admin, context, property)
        const [resource] = await createTestBillingMeterResource(admin)
        const [meter] = await createTestBillingAccountMeter(admin, context, property, billingAccount, resource)
        await createTestBillingAccountMeterReading(admin, context, property, billingAccount, meter)

        await expectToThrowAuthenticationErrorToObjects(async () => {
            await BillingAccountMeterReading.getAll(client)
        })
    })

    test('admin: update BillingAccountMeterReading', async () => {
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingProperty(admin, context)
        const [billingAccount] = await createTestBillingAccount(admin, context, property)
        const [resource] = await createTestBillingMeterResource(admin)
        const [meter] = await createTestBillingAccountMeter(admin, context, property, billingAccount, resource)
        const [billingAccountMeterReading] = await createTestBillingAccountMeterReading(admin, context, property, billingAccount, meter)

        const dv1 = faker.datatype.number()
        const dv2 = faker.datatype.number()
        const dv3 = faker.datatype.number()
        const payload = {
            value1: billingAccountMeterReading.value1 + dv1,
            value2: billingAccountMeterReading.value2 + dv2,
            value3: billingAccountMeterReading.value3 + dv3,
        }
        const [updatedBillingAccountMeterReading] = await updateTestBillingAccountMeterReading(admin, billingAccountMeterReading.id, payload)

        expect(updatedBillingAccountMeterReading.id).toEqual(billingAccountMeterReading.id)
        expect(updatedBillingAccountMeterReading.value1).toEqual(billingAccountMeterReading.value1 + dv1)
        expect(updatedBillingAccountMeterReading.value2).toEqual(billingAccountMeterReading.value2 + dv2)
        expect(updatedBillingAccountMeterReading.value3).toEqual(billingAccountMeterReading.value3 + dv3)
    })

    test('organization integration manager: update BillingAccountMeterReading', async () => {
        const admin = await makeLoggedInAdminClient()
        const { organization, integration, managerUserClient } = await makeOrganizationIntegrationManager()
        const [context] = await createTestBillingIntegrationOrganizationContext(managerUserClient, organization, integration)
        const [property] = await createTestBillingProperty(managerUserClient, context)
        const [billingAccount] = await createTestBillingAccount(managerUserClient, context, property)
        const [resource] = await createTestBillingMeterResource(admin)
        const [meter] = await createTestBillingAccountMeter(managerUserClient, context, property, billingAccount, resource)
        const [billingAccountMeterReading] = await createTestBillingAccountMeterReading(managerUserClient, context, property, billingAccount, meter)

        const dv1 = faker.datatype.number()
        const dv2 = faker.datatype.number()
        const dv3 = faker.datatype.number()
        const payload = {
            value1: billingAccountMeterReading.value1 + dv1,
            value2: billingAccountMeterReading.value2 + dv2,
            value3: billingAccountMeterReading.value3 + dv3,
        }
        const [updatedBillingAccountMeterReading] = await updateTestBillingAccountMeterReading(managerUserClient, billingAccountMeterReading.id, payload)

        expect(updatedBillingAccountMeterReading.id).toEqual(billingAccountMeterReading.id)
        expect(updatedBillingAccountMeterReading.value1).toEqual(billingAccountMeterReading.value1 + dv1)
        expect(updatedBillingAccountMeterReading.value2).toEqual(billingAccountMeterReading.value2 + dv2)
        expect(updatedBillingAccountMeterReading.value3).toEqual(billingAccountMeterReading.value3 + dv3)
    })

    test('user: update BillingAccountMeterReading', async () => {
        const client = await makeClientWithNewRegisteredAndLoggedInUser()
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingProperty(admin, context)
        const [billingAccount] = await createTestBillingAccount(admin, context, property)
        const [resource] = await createTestBillingMeterResource(admin)
        const [meter] = await createTestBillingAccountMeter(admin, context, property, billingAccount, resource)
        const [billingAccountMeterReading] = await createTestBillingAccountMeterReading(admin, context, property, billingAccount, meter)

        const payload = {}
        await expectToThrowAccessDeniedErrorToObj(async () => {
            await updateTestBillingAccountMeterReading(client, billingAccountMeterReading.id, payload)
        })
    })

    test('anonymous: update BillingAccountMeterReading', async () => {
        const client = await makeClient()
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingProperty(admin, context)
        const [billingAccount] = await createTestBillingAccount(admin, context, property)
        const [resource] = await createTestBillingMeterResource(admin)
        const [meter] = await createTestBillingAccountMeter(admin, context, property, billingAccount, resource)
        const [billingAccountMeterReading] = await createTestBillingAccountMeterReading(admin, context, property, billingAccount, meter)

        const payload = {}
        await expectToThrowAuthenticationErrorToObj(async () => {
            await updateTestBillingAccountMeterReading(client, billingAccountMeterReading.id, payload)
        })
    })

    test('admin: delete BillingAccountMeterReading', async () => {
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingProperty(admin, context)
        const [billingAccount] = await createTestBillingAccount(admin, context, property)
        const [resource] = await createTestBillingMeterResource(admin)
        const [meter] = await createTestBillingAccountMeter(admin, context, property, billingAccount, resource)
        const [billingAccountMeterReading] = await createTestBillingAccountMeterReading(admin, context, property, billingAccount, meter)

        await expectToThrowAccessDeniedErrorToObj(async () => {
            await BillingAccountMeterReading.delete(admin, billingAccountMeterReading.id)
        })
    })

    test('organization integration manager: delete BillingAccountMeterReading', async () => {
        const admin = await makeLoggedInAdminClient()
        const { organization, integration, managerUserClient } = await makeOrganizationIntegrationManager()
        const [context] = await createTestBillingIntegrationOrganizationContext(managerUserClient, organization, integration)
        const [property] = await createTestBillingProperty(managerUserClient, context)
        const [billingAccount] = await createTestBillingAccount(managerUserClient, context, property)
        const [resource] = await createTestBillingMeterResource(admin)
        const [meter] = await createTestBillingAccountMeter(managerUserClient, context, property, billingAccount, resource)
        const [billingAccountMeterReading] = await createTestBillingAccountMeterReading(managerUserClient, context, property, billingAccount, meter)

        await expectToThrowAccessDeniedErrorToObj(async () => {
            await BillingAccountMeterReading.delete(managerUserClient, billingAccountMeterReading.id)
        })
    })

    test('user: delete BillingAccountMeterReading', async () => {
        const client = await makeClientWithNewRegisteredAndLoggedInUser()
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingProperty(admin, context)
        const [billingAccount] = await createTestBillingAccount(admin, context, property)
        const [resource] = await createTestBillingMeterResource(admin)
        const [meter] = await createTestBillingAccountMeter(admin, context, property, billingAccount, resource)
        const [billingAccountMeterReading] = await createTestBillingAccountMeterReading(admin, context, property, billingAccount, meter)

        await expectToThrowAccessDeniedErrorToObj(async () => {
            await BillingAccountMeterReading.delete(client, billingAccountMeterReading.id)
        })
    })

    test('anonymous: delete BillingAccountMeterReading', async () => {
        const client = await makeClient()
        const admin = await makeLoggedInAdminClient()
        const { context } = await makeContextWithOrganizationAndIntegrationAsAdmin()
        const [property] = await createTestBillingProperty(admin, context)
        const [billingAccount] = await createTestBillingAccount(admin, context, property)
        const [resource] = await createTestBillingMeterResource(admin)
        const [meter] = await createTestBillingAccountMeter(admin, context, property, billingAccount, resource)
        const [billingAccountMeterReading] = await createTestBillingAccountMeterReading(admin, context, property, billingAccount, meter)

        await expectToThrowAccessDeniedErrorToObj(async () => {
            await BillingAccountMeterReading.delete(client, billingAccountMeterReading.id)
        })
    })
})
