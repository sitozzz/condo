/**
 * Generated by `createschema user.ForgotPasswordAction 'user:Relationship:User:CASCADE; token:Text; requestedAt:DateTimeUtc; expiresAt:DateTimeUtc; usedAt:DateTimeUtc;'`
 */

const { makeLoggedInAdminClient, makeClient, UUID_RE, DATETIME_RE } = require('@core/keystone/test.utils')

const { ForgotPasswordAction, createTestForgotPasswordAction, updateTestForgotPasswordAction } = require('@condo/domains/user/utils/testSchema')

describe('ForgotPasswordAction', () => {
    test('user: create ForgotPasswordAction', async () => {
        const client = await makeClient()  // TODO(codegen): use truly useful client!

        const [obj, attrs] = await createTestForgotPasswordAction(client)  // TODO(codegen): write 'user: create ForgotPasswordAction' test
        expect(obj.id).toMatch(UUID_RE)
        expect(obj.dv).toEqual(1)
        expect(obj.sender).toEqual(attrs.sender)
        expect(obj.v).toEqual(1)
        expect(obj.newId).toEqual(null)
        expect(obj.deletedAt).toEqual(null)
        expect(obj.createdBy).toEqual(expect.objectContaining({ id: client.user.id }))
        expect(obj.updatedBy).toEqual(expect.objectContaining({ id: client.user.id }))
        expect(obj.createdAt).toMatch(DATETIME_RE)
        expect(obj.updatedAt).toMatch(DATETIME_RE)
    })

    test('anonymous: create ForgotPasswordAction', async () => {
        const client = await makeClient()
        try {
            await createTestForgotPasswordAction(client)  // TODO(codegen): check the 'anonymous: create ForgotPasswordAction' test!
        } catch (e) {
            expect(e.errors[0]).toMatchObject({
                'message': 'You do not have access to this resource',
                'name': 'AccessDeniedError',
                'path': ['obj'],
            })
            expect(e.data).toEqual({ 'obj': null })
        }
    })

    test('user: read ForgotPasswordAction', async () => {
        const admin = await makeLoggedInAdminClient()
        const [obj, attrs] = await createTestForgotPasswordAction(admin)  // TODO(codegen): check create function!

        const client = await makeClient()  // TODO(codegen): use truly useful client!
        const objs = await ForgotPasswordAction.getAll(client, {}, { sortBy: ['updatedAt_DESC'] })

        // TODO(codegen): check 'user: read ForgotPasswordAction' test!
        expect(objs).toHaveLength(1)
        // expect(objs.length >= 1).toBeTruthy()
        expect(objs[0].id).toMatch(obj.id)
        expect(objs[0].dv).toEqual(1)
        expect(objs[0].sender).toEqual(attrs.sender)
        expect(objs[0].v).toEqual(1)
        expect(objs[0].newId).toEqual(null)
        expect(objs[0].deletedAt).toEqual(null)
        expect(objs[0].createdBy).toEqual(expect.objectContaining({ id: admin.user.id }))
        expect(objs[0].updatedBy).toEqual(expect.objectContaining({ id: admin.user.id }))
        expect(objs[0].createdAt).toMatch(obj.createdAt)
        expect(objs[0].updatedAt).toMatch(obj.updatedAt)
    })

    test('anonymous: read ForgotPasswordAction', async () => {
        const client = await makeClient()

        try {
            await ForgotPasswordAction.getAll(client)
        } catch (e) {
            expect(e.errors[0]).toMatchObject({
                'message': 'You do not have access to this resource',
                'name': 'AccessDeniedError',
                'path': ['objs'],
            })
            expect(e.data).toEqual({ 'objs': null })
        }
    })

    test('user: update ForgotPasswordAction', async () => {
        const admin = await makeLoggedInAdminClient()
        const [objCreated] = await createTestForgotPasswordAction(admin)  // TODO(codegen): check create function!

        const client = await makeClient()  // TODO(codegen): use truly useful client!
        const payload = {}  // TODO(codegen): change the 'user: update ForgotPasswordAction' payload
        const [objUpdated, attrs] = await updateTestForgotPasswordAction(client, objCreated.id, payload)

        // TODO(codegen): white checks for 'user: update ForgotPasswordAction' test
        expect(objUpdated.id).toEqual(objCreated.id)
        expect(objUpdated.dv).toEqual(1)
        expect(objUpdated.sender).toEqual(attrs.sender)
        expect(objUpdated.v).toEqual(2)
        expect(objUpdated.newId).toEqual(null)
        expect(objUpdated.deletedAt).toEqual(null)
        expect(objUpdated.createdBy).toEqual(expect.objectContaining({ id: client.user.id }))
        expect(objUpdated.updatedBy).toEqual(expect.objectContaining({ id: client.user.id }))
        expect(objUpdated.createdAt).toMatch(DATETIME_RE)
        expect(objUpdated.updatedAt).toMatch(DATETIME_RE)
        expect(objUpdated.updatedAt).not.toEqual(objUpdated.createdAt)
    })

    test('anonymous: update ForgotPasswordAction', async () => {
        const admin = await makeLoggedInAdminClient()
        const [objCreated] = await createTestForgotPasswordAction(admin)  // TODO(codegen): check create function!

        const client = await makeClient()
        const payload = {}  // TODO(codegen): change the 'anonymous: update ForgotPasswordAction' payload
        try {
            await updateTestForgotPasswordAction(client, objCreated.id, payload)
        } catch (e) {
            expect(e.errors[0]).toMatchObject({
                'message': 'You do not have access to this resource',
                'name': 'AccessDeniedError',
                'path': ['obj'],
            })
            expect(e.data).toEqual({ 'obj': null })
        }
    })

    test('user: delete ForgotPasswordAction', async () => {
        const admin = await makeLoggedInAdminClient()
        const [objCreated] = await createTestForgotPasswordAction(admin)  // TODO(codegen): check create function!

        const client = await makeClient()  // TODO(codegen): use truly useful client!
        try {
            // TODO(codegen): check 'user: delete ForgotPasswordAction' test!
            await ForgotPasswordAction.delete(client, objCreated.id)
        } catch (e) {
            expect(e.errors[0]).toMatchObject({
                'message': 'You do not have access to this resource',
                'name': 'AccessDeniedError',
                'path': ['obj'],
            })
            expect(e.data).toEqual({ 'obj': null })
        }
    })

    test('anonymous: delete ForgotPasswordAction', async () => {
        const admin = await makeLoggedInAdminClient()
        const [objCreated] = await createTestForgotPasswordAction(admin)  // TODO(codegen): check create function!

        const client = await makeClient()
        try {
            // TODO(codegen): check 'anonymous: delete ForgotPasswordAction' test!
            await ForgotPasswordAction.delete(client, objCreated.id)
        } catch (e) {
            expect(e.errors[0]).toMatchObject({
                'message': 'You do not have access to this resource',
                'name': 'AccessDeniedError',
                'path': ['obj'],
            })
            expect(e.data).toEqual({ 'obj': null })
        }
    })
})
