/**
 * Generated by `createservice billing.BillingReceiptsService --type queries`
 */

const { BillingReceipt, createTestBillingIntegration, createTestBillingReceipt } = require('@condo/domains/billing/utils/testSchema')
const { registerServiceConsumerByTestClient } = require('@condo/domains/resident/utils/testSchema')
const { createTestBillingIntegrationOrganizationContext } = require('@condo/domains/billing/utils/testSchema')
const { createTestResident } = require('../utils/testSchema')
const { makeClientWithProperty } = require('@condo/domains/property/utils/testSchema')
const { createTestBillingAccount, createTestBillingProperty } = require('@condo/domains/billing/utils/testSchema')
const { makeLoggedInAdminClient } = require('@core/keystone/test.utils')

describe('GetBillingReceiptsForServiceConsumerService', () => {

    test('user with valid serviceAccount can read BillingReceipt in normal form', async () => {

        const userClient = await makeClientWithProperty()
        const adminClient = await makeLoggedInAdminClient()

        const [integration] = await createTestBillingIntegration(adminClient)
        const [context] = await createTestBillingIntegrationOrganizationContext(adminClient, userClient.organization, integration)
        const [billingProperty] = await createTestBillingProperty(adminClient, context)
        const [billingAccount, billingAccountAttrs] = await createTestBillingAccount(adminClient, context, billingProperty)
        await createTestBillingReceipt(adminClient, context, billingProperty, billingAccount)

        const [resident] = await createTestResident(adminClient, userClient.user, userClient.organization, userClient.property, {
            unitName: billingAccountAttrs.unitName,
        })

        const payload = {
            residentId: resident.id,
            unitName: billingAccountAttrs.unitName,
            accountNumber: billingAccountAttrs.number,
        }

        const [serviceClient] = await registerServiceConsumerByTestClient(adminClient, payload)

        const objs = await BillingReceipt.getAll(userClient)
        expect(objs).toHaveLength(1)
    })

    test('user without valid serviceAccount cant read BillingReceipt', async () => {

    })

    test('user with a valid, but stolen, serviceAccountId cant read BillingReceipt', async () => {

    })

})