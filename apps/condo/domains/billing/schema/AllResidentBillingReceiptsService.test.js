/**
 * Generated by `createservice billing.BillingReceiptsService --type queries`
 */

const { catchErrorFrom } = require('@condo/domains/common/utils/testSchema')
const { createTestOrganization } = require('@condo/domains/organization/utils/testSchema')
const { addResidentAccess, makeClientWithResidentUser, makeClientWithSupportUser, makeLoggedInClient } = require('@condo/domains/user/utils/testSchema')
const { createTestBillingIntegration, createTestBillingReceipt, updateTestBillingReceipt, ResidentBillingReceipt } = require('../utils/testSchema')
const { registerServiceConsumerByTestClient, updateTestServiceConsumer, registerResidentByTestClient, createTestResident, ServiceConsumer } = require('@condo/domains/resident/utils/testSchema')
const { makeClientWithProperty, createTestProperty } = require('@condo/domains/property/utils/testSchema')
const { createTestBillingAccount, createTestBillingProperty, createTestBillingIntegrationOrganizationContext, createTestBillingIntegrationAccessRight } = require('@condo/domains/billing/utils/testSchema')
const { makeLoggedInAdminClient } = require('@core/keystone/test.utils')

describe('AllResidentBillingReceipts', () => {

    describe('resident should be able to get all needed fields', () => {
        let mutationResult
        beforeAll(async () => {
            const userClient = await makeClientWithProperty()
            const support = await makeClientWithSupportUser()

            const [integration] = await createTestBillingIntegration(support)
            const [billingContext] = await createTestBillingIntegrationOrganizationContext(userClient, userClient.organization, integration)

            const integrationClient = await makeLoggedInClient()
            await createTestBillingIntegrationAccessRight(support, integration, integrationClient.user)
            const [billingProperty] = await createTestBillingProperty(integrationClient, billingContext, {
                address: userClient.property.address,
            })
            const [billingAccount, billingAccountAttrs] = await createTestBillingAccount(integrationClient, billingContext, billingProperty)

            const residentUser = await makeClientWithResidentUser()
            const [resident] = await registerResidentByTestClient(residentUser, {
                address: userClient.property.address,
                addressMeta: userClient.property.addressMeta,
                unitName: billingAccountAttrs.unitName,
            })
            await registerServiceConsumerByTestClient(residentUser, {
                residentId: resident.id,
                accountNumber: billingAccountAttrs.number,
                organizationId: userClient.organization.id,
            })
            await createTestBillingReceipt(integrationClient, billingContext, billingProperty, billingAccount)
            mutationResult = await ResidentBillingReceipt.getAll(residentUser)
        })

        // TODO(DOMA-1768): add more tests
        test('receipts currencyCode', async () => {
            expect(mutationResult).toBeDefined()
            expect(mutationResult).not.toHaveLength(0)
            mutationResult.forEach(receipt => {
                expect(receipt).toHaveProperty('currencyCode')
                expect(receipt.currencyCode).not.toBeNull()
            })
        })
    })

    test('user with valid serviceAccount can read BillingReceipt without raw data', async () => {
        const userClient = await makeClientWithProperty()
        const adminClient = await makeLoggedInAdminClient()

        const [integration] = await createTestBillingIntegration(adminClient)
        const [context] = await createTestBillingIntegrationOrganizationContext(adminClient, userClient.organization, integration)
        const [billingProperty] = await createTestBillingProperty(adminClient, context)
        const [billingAccount, billingAccountAttrs] = await createTestBillingAccount(adminClient, context, billingProperty)
        const [billingAccount2] = await createTestBillingAccount(adminClient, context, billingProperty)

        await addResidentAccess(userClient.user)

        const [resident] = await createTestResident(adminClient, userClient.user, userClient.organization, userClient.property, { unitName: billingAccountAttrs.unitName })
        const payload = {
            residentId: resident.id,
            accountNumber: billingAccountAttrs.number,
            organizationId: userClient.organization.id,
        }

        await registerServiceConsumerByTestClient(userClient, payload)
        const [receipt] = await createTestBillingReceipt(adminClient, context, billingProperty, billingAccount)
        await createTestBillingReceipt(adminClient, context, billingProperty, billingAccount2)

        const objs = await ResidentBillingReceipt.getAll(userClient)
        expect(objs).toHaveLength(1)
        expect(objs[0].raw).toEqual(undefined)
        expect(objs[0].id).toEqual(receipt.id)
    })

    test('user with valid serviceAccount can read BillingReceipt without raw data even if there are other Resident with this service consumer', async () => {
        /**
         * Story: Husband and Wife live in the same flat,
         *        They have the same accountNumber and unitName, but different Residents and serviceConsumers
         *        Both Wife and Husband should be able to read BillingReceipts
         */

        const adminClient = await makeLoggedInAdminClient()
        const [organization] = await createTestOrganization(adminClient)
        const [property] = await createTestProperty(adminClient, organization)

        const husbandClient = await makeClientWithResidentUser()
        const wifeClient = await makeClientWithResidentUser()

        // Create billing integration and billing entities
        const [integration] = await createTestBillingIntegration(adminClient)
        const [context] = await createTestBillingIntegrationOrganizationContext(adminClient, organization, integration)
        const [billingProperty] = await createTestBillingProperty(adminClient, context)
        const [billingAccount, billingAccountAttrs] = await createTestBillingAccount(adminClient, context, billingProperty)
        const [billingAccount2] = await createTestBillingAccount(adminClient, context, billingProperty)
        const [receipt] = await createTestBillingReceipt(adminClient, context, billingProperty, billingAccount)
        await createTestBillingReceipt(adminClient, context, billingProperty, billingAccount2)

        const [residentHusband] = await registerResidentByTestClient(husbandClient, {
            address: property.address,
            addressMeta: property.addressMeta,
            unitName: billingAccountAttrs.unitName,
        })
        const [serviceConsumerHusband] = await registerServiceConsumerByTestClient(husbandClient, {
            residentId: residentHusband.id,
            accountNumber: billingAccountAttrs.number,
            organizationId: organization.id,
        })
        // you can't read billingAccount field as resident, so we should get true serviceConsumer here to further check
        const [serviceConsumerHusbandWithAccount] = await ServiceConsumer.getAll(adminClient, { id: serviceConsumerHusband.id })

        const [residentWife] = await registerResidentByTestClient(wifeClient, {
            address: property.address,
            addressMeta: property.addressMeta,
            unitName: billingAccountAttrs.unitName,
        })
        const [serviceConsumerWife] = await registerServiceConsumerByTestClient(wifeClient, {
            residentId: residentWife.id,
            accountNumber: billingAccountAttrs.number,
            organizationId: organization.id,
        })
        // you can't read billingAccount field as resident, so we should get true serviceConsumer here to further check
        const [serviceConsumerWifeWithAccount] = await ServiceConsumer.getAll(adminClient, { id: serviceConsumerWife.id })

        expect(serviceConsumerHusbandWithAccount.billingAccount.id).toEqual(serviceConsumerWifeWithAccount.billingAccount.id)
        expect(serviceConsumerHusbandWithAccount.billingAccount.id).toEqual(billingAccount.id)

        const objsHusband = await ResidentBillingReceipt.getAll(husbandClient, { serviceConsumer: { resident: { id: residentHusband.id } } })
        expect(objsHusband).toHaveLength(1)
        expect(objsHusband[0].raw).toEqual(undefined)
        expect(objsHusband[0].id).toEqual(receipt.id)

        const objsWife = await ResidentBillingReceipt.getAll(wifeClient, { serviceConsumer: { resident: { id: residentWife.id } } })
        expect(objsWife).toHaveLength(1)
        expect(objsWife[0].raw).toEqual(undefined)
        expect(objsWife[0].id).toEqual(receipt.id)
    })

    test('user with valid serviceAccount and with deleted service account can read BillingReceipt without raw data', async () => {
        /**
         * Story: Nikolay deleted the service consumer by accident and registered new
         *        Nikolay should be able to get all receipts!
         */

        const adminClient = await makeLoggedInAdminClient()
        const [organization] = await createTestOrganization(adminClient)
        const [property] = await createTestProperty(adminClient, organization)

        const client = await makeClientWithResidentUser()

        // Create billing integration and billing entities
        const [integration] = await createTestBillingIntegration(adminClient)
        const [context] = await createTestBillingIntegrationOrganizationContext(adminClient, organization, integration)
        const [billingProperty] = await createTestBillingProperty(adminClient, context)
        const [billingAccount, billingAccountAttrs] = await createTestBillingAccount(adminClient, context, billingProperty)
        const [billingAccount2] = await createTestBillingAccount(adminClient, context, billingProperty)
        const [receipt] = await createTestBillingReceipt(adminClient, context, billingProperty, billingAccount)
        await createTestBillingReceipt(adminClient, context, billingProperty, billingAccount2)

        const [resident] = await createTestResident(adminClient, client.user, organization, property, {
            unitName: billingAccountAttrs.unitName,
        })
        const [firstServiceConsumer] = await registerServiceConsumerByTestClient(client, {
            residentId: resident.id,
            accountNumber: billingAccountAttrs.number,
            organizationId: organization.id,
        })
        const [updatedServiceConsumer] = await updateTestServiceConsumer(client, firstServiceConsumer.id, { deletedAt: 'true' })
        expect(updatedServiceConsumer.deletedAt).not.toBeNull()

        const objsFirst = await ResidentBillingReceipt.getAll(client, { serviceConsumer: { resident: { id: resident.id } } })
        expect(objsFirst).toHaveLength(0)

        await registerServiceConsumerByTestClient(client, {
            residentId: resident.id,
            accountNumber: billingAccountAttrs.number,
            organizationId: organization.id,
        })

        const objsSecond = await ResidentBillingReceipt.getAll(client, { serviceConsumer: { resident: { id: resident.id } } })
        expect(objsSecond).toHaveLength(1)
        expect(objsSecond[0].raw).toEqual(undefined)
        expect(objsSecond[0].id).toEqual(receipt.id)
    })

    test('user with valid serviceAccount can filter residentBillingReceipts by serviceConsumer', async () => {
        // User has flats in building A and building B
        // Each building has own BillingOrganizationIntegrationContext
        // User is able to get receipts for both of his buildings

        const userClient = await makeClientWithProperty()
        const adminClient = await makeLoggedInAdminClient()

        // User has two flats in building A:
        const [integrationA] = await createTestBillingIntegration(adminClient)
        const [contextA] = await createTestBillingIntegrationOrganizationContext(adminClient, userClient.organization, integrationA)
        const [billingPropertyA] = await createTestBillingProperty(adminClient, contextA)
        const [billingAccountA, billingAccountAttrsA] = await createTestBillingAccount(adminClient, contextA, billingPropertyA)
        const [billingAccountA2, billingAccountAttrsA2] = await createTestBillingAccount(adminClient, contextA, billingPropertyA)

        await addResidentAccess(userClient.user)
        const [residentA] = await createTestResident(adminClient, userClient.user, userClient.organization, userClient.property, {
            unitName: billingAccountAttrsA.unitName,
        })

        const serviceConsumerPayloadA = {
            residentId: residentA.id,
            accountNumber: billingAccountAttrsA.number,
            organizationId: userClient.organization.id,
        }
        await registerServiceConsumerByTestClient(userClient, serviceConsumerPayloadA)

        const [residentA2] = await createTestResident(adminClient, userClient.user, userClient.organization, userClient.property, {
            unitName: billingAccountAttrsA2.unitName,
        })

        const serviceConsumerPayloadA2 = {
            residentId: residentA2.id,
            accountNumber: billingAccountAttrsA2.number,
            organizationId: userClient.organization.id,
        }
        await registerServiceConsumerByTestClient(userClient, serviceConsumerPayloadA2)

        await createTestBillingReceipt(adminClient, contextA, billingPropertyA, billingAccountA)
        await createTestBillingReceipt(adminClient, contextA, billingPropertyA, billingAccountA2)

        // User has one flat in building B:
        const [organizationB] = await createTestOrganization(adminClient)
        const [propertyB] = await createTestProperty(adminClient, organizationB)
        const [integrationB] = await createTestBillingIntegration(adminClient)
        const [contextB] = await createTestBillingIntegrationOrganizationContext(adminClient, organizationB, integrationB)
        const [billingPropertyB] = await createTestBillingProperty(adminClient, contextB)
        const [billingAccountB, billingAccountAttrsB] = await createTestBillingAccount(adminClient, contextB, billingPropertyB)

        const [residentB] = await createTestResident(adminClient, userClient.user, organizationB, propertyB, {
            unitName: billingAccountAttrsB.unitName,
        })

        const payloadForServiceConsumerB = {
            residentId: residentB.id,
            accountNumber: billingAccountAttrsB.number,
            organizationId: organizationB.id,
        }
        await registerServiceConsumerByTestClient(userClient, payloadForServiceConsumerB)

        await createTestBillingReceipt(adminClient, contextB, billingPropertyB, billingAccountB)

        // User get two receipts for his building A
        const objsA = await ResidentBillingReceipt.getAll(userClient, { serviceConsumer: { resident: { id: residentA.id } } })
        expect(objsA).toHaveLength(1)

        const objsA2 = await ResidentBillingReceipt.getAll(userClient, { serviceConsumer: { resident: { id: residentA2.id } } })
        expect(objsA2).toHaveLength(1)

        // User get one receipt for his building B
        const objsForResident2 = await ResidentBillingReceipt.getAll(userClient, { serviceConsumer: { resident: { id: residentB.id } } })
        expect(objsForResident2).toHaveLength(1)
    })

    test('user with valid multiple serviceAccounts can read all his BillingReceipts without raw data', async () => {
        const userClient = await makeClientWithProperty()
        const adminClient = await makeLoggedInAdminClient()

        const [integration] = await createTestBillingIntegration(adminClient)
        const [context] = await createTestBillingIntegrationOrganizationContext(adminClient, userClient.organization, integration)
        const [billingProperty] = await createTestBillingProperty(adminClient, context)
        const [billingAccount, billingAccountAttrs] = await createTestBillingAccount(adminClient, context, billingProperty)
        const [billingAccount2, billingAccountAttrs2] = await createTestBillingAccount(adminClient, context, billingProperty)

        await addResidentAccess(userClient.user)

        const [resident] = await createTestResident(adminClient, userClient.user, userClient.organization, userClient.property, {
            unitName: billingAccountAttrs.unitName,
        })

        const payload = {
            residentId: resident.id,
            accountNumber: billingAccountAttrs.number,
            organizationId: userClient.organization.id,
        }
        await registerServiceConsumerByTestClient(userClient, payload)

        const [resident2] = await createTestResident(adminClient, userClient.user, userClient.organization, userClient.property, {
            unitName: billingAccountAttrs2.unitName,
        })

        const payload2 = {
            residentId: resident2.id,
            accountNumber: billingAccountAttrs2.number,
            organizationId: userClient.organization.id,
        }
        await registerServiceConsumerByTestClient(userClient, payload2)

        await createTestBillingReceipt(adminClient, context, billingProperty, billingAccount)
        await createTestBillingReceipt(adminClient, context, billingProperty, billingAccount2)

        const objs = await ResidentBillingReceipt.getAll(userClient)
        expect(objs).toHaveLength(2)
    })

    test('user with valid serviceAccount can read BillingReceipt without raw data with where query', async () => {
        const userClient = await makeClientWithProperty()
        const adminClient = await makeLoggedInAdminClient()

        const [integration] = await createTestBillingIntegration(adminClient)
        const [context] = await createTestBillingIntegrationOrganizationContext(adminClient, userClient.organization, integration)
        const [billingProperty] = await createTestBillingProperty(adminClient, context)
        const [billingAccount, billingAccountAttrs] = await createTestBillingAccount(adminClient, context, billingProperty)

        await addResidentAccess(userClient.user)

        const [resident] = await createTestResident(adminClient, userClient.user, userClient.organization, userClient.property, {
            unitName: billingAccountAttrs.unitName,
        })
        const payload = {
            residentId: resident.id,
            accountNumber: billingAccountAttrs.number,
            organizationId: userClient.organization.id,
        }

        await registerServiceConsumerByTestClient(userClient, payload)
        await createTestBillingReceipt(adminClient, context, billingProperty, billingAccount)
        const [receipt] = await createTestBillingReceipt(adminClient, context, billingProperty, billingAccount)

        await updateTestBillingReceipt(adminClient, receipt.id, { toPay: '100.50' })

        const objs = await ResidentBillingReceipt.getAll(userClient, { toPay: '100.50' })
        expect(objs).toHaveLength(1)
        expect(objs[0].raw).toEqual(undefined)
        expect(objs[0].id).toEqual(receipt.id)
    })

    test('user with stolen billing account id and hacky intentions cant read BillingReceipt', async () => {
        const userClient = await makeClientWithProperty()
        const adminClient = await makeLoggedInAdminClient()

        const [integration] = await createTestBillingIntegration(adminClient)
        const [context] = await createTestBillingIntegrationOrganizationContext(adminClient, userClient.organization, integration)
        const [billingProperty] = await createTestBillingProperty(adminClient, context)
        const [billingAccount, billingAccountAttrs] = await createTestBillingAccount(adminClient, context, billingProperty)
        await createTestBillingReceipt(adminClient, context, billingProperty, billingAccount)

        await addResidentAccess(userClient.user)
        const [resident] = await createTestResident(adminClient, userClient.user, userClient.organization, userClient.property, {
            unitName: billingAccountAttrs.unitName,
        })
        const payload = {
            residentId: resident.id,
            accountNumber: billingAccountAttrs.number,
            organizationId: userClient.organization.id,
        }
        await registerServiceConsumerByTestClient(userClient, payload)

        const hackerClient = await makeClientWithProperty()
        const [context2] = await createTestBillingIntegrationOrganizationContext(adminClient, hackerClient.organization, integration)
        const [billingProperty2] = await createTestBillingProperty(adminClient, context2)
        const [billingAccount2] = await createTestBillingAccount(adminClient, context2, billingProperty2)

        await addResidentAccess(hackerClient.user)
        const [hackerResident] = await createTestResident(adminClient, hackerClient.user, hackerClient.organization, hackerClient.property, {
            unitName: billingAccount2.unitName,
        })
        const hackerPayload = {
            residentId: hackerResident.id,
            accountNumber: billingAccount2.number,
            organizationId: userClient.organization.id,
        }
        // Hacker is connected to billingAccount2 and tries to get receipts for billingAccount
        await catchErrorFrom(async () => {
            await registerServiceConsumerByTestClient(hackerClient, hackerPayload)
            await ResidentBillingReceipt.getAll(hackerClient, { account: { id: billingAccountAttrs.id } })
        }, (err) => {
            expect(err).toBeDefined()
        })
    })

    test('user without valid serviceAccount cant read BillingReceipt', async () => {
        const userClient = await makeClientWithProperty()
        const adminClient = await makeLoggedInAdminClient()

        const [integration] = await createTestBillingIntegration(adminClient)
        const [context] = await createTestBillingIntegrationOrganizationContext(adminClient, userClient.organization, integration)
        const [billingProperty] = await createTestBillingProperty(adminClient, context)
        const [billingAccount, billingAccountAttrs] = await createTestBillingAccount(adminClient, context, billingProperty)
        await createTestResident(adminClient, userClient.user, userClient.organization, userClient.property, {
            unitName: billingAccountAttrs.unitName,
        })
        await createTestBillingReceipt(adminClient, context, billingProperty, billingAccount)
        await addResidentAccess(userClient.user)

        const objs = await ResidentBillingReceipt.getAll(userClient)
        expect(objs).toHaveLength(0)
    })

    test('user without valid resident cant read BillingReceipt', async () => {
        const userClient = await makeClientWithProperty()
        const adminClient = await makeLoggedInAdminClient()

        const [integration] = await createTestBillingIntegration(adminClient)
        const [context] = await createTestBillingIntegrationOrganizationContext(adminClient, userClient.organization, integration)
        const [billingProperty] = await createTestBillingProperty(adminClient, context)
        const [billingAccount] = await createTestBillingAccount(adminClient, context, billingProperty)

        await createTestBillingReceipt(adminClient, context, billingProperty, billingAccount)
        await addResidentAccess(userClient.user)

        const objs = await ResidentBillingReceipt.getAll(userClient)
        expect(objs).toHaveLength(0)
    })
})