/**
 * Generated by `createschema user.User name:Text; password?:Password; isAdmin?:Checkbox; email?:Text; isEmailVerified?:Checkbox; phone?:Text; isPhoneVerified?:Checkbox; avatar?:File; meta:Json; importId:Text;`
 */

const { getRandomString, makeLoggedInAdminClient, makeClient } = require('@core/keystone/test.utils')

const { User, UserAdmin, createTestUser, updateTestUser, makeClientWithNewRegisteredAndLoggedInUser, makeLoggedInClient } = require('@condo/domains/user/utils/testSchema')

describe('User', () => {
    test('user: create User', async () => {
        const client = await makeClientWithNewRegisteredAndLoggedInUser()

        try {
            await createTestUser(client)
        } catch (e) {
            expect(e.errors[0]).toMatchObject({
                'message': 'You do not have access to this resource',
                'name': 'AccessDeniedError',
                'path': ['obj'],
            })
            expect(e.data).toEqual({ 'obj': null })
        }
    })

    test('anonymous: create User', async () => {
        const client = await makeClient()
        try {
            await createTestUser(client)
        } catch (e) {
            expect(e.errors[0]).toMatchObject({
                'message': 'You do not have access to this resource',
                'name': 'AccessDeniedError',
                'path': ['obj'],
            })
            expect(e.data).toEqual({ 'obj': null })
        }
    })

    test('user: read User', async () => {
        const admin = await makeLoggedInAdminClient()
        await createTestUser(admin)

        const client = await makeClientWithNewRegisteredAndLoggedInUser()
        const { data } = await UserAdmin.getAll(client, {}, { raw: true, sortBy: ['updatedAt_DESC'] })
        expect(data.objs).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ id: client.user.id, email: client.userAttrs.email }),
                expect.objectContaining({ email: null }),
            ]),
        )
        expect(data.objs.length >= 1).toBeTruthy()
    })

    test('anonymous: read User', async () => {
        const client = await makeClient()

        try {
            await User.getAll(client)
        } catch (e) {
            expect(e.errors[0]).toMatchObject({
                'message': 'You do not have access to this resource',
                'name': 'AccessDeniedError',
                'path': ['objs'],
            })
            expect(e.data).toEqual({ 'objs': null })
        }
    })

    test('user: update User', async () => {
        const admin = await makeLoggedInAdminClient()
        const [objCreated] = await createTestUser(admin)

        const client = await makeClientWithNewRegisteredAndLoggedInUser()
        const payload = {}
        try {
            await updateTestUser(client, objCreated.id, payload)
        } catch (e) {
            expect(e.errors[0]).toMatchObject({
                'message': 'You do not have access to this resource',
                'name': 'AccessDeniedError',
                'path': ['obj'],
            })
            expect(e.data).toEqual({ 'obj': null })
        }
    })

    test('anonymous: update User', async () => {
        const admin = await makeLoggedInAdminClient()
        const [objCreated] = await createTestUser(admin)

        const client = await makeClient()
        const payload = {}
        try {
            await updateTestUser(client, objCreated.id, payload)
        } catch (e) {
            expect(e.errors[0]).toMatchObject({
                'message': 'You do not have access to this resource',
                'name': 'AccessDeniedError',
                'path': ['obj'],
            })
            expect(e.data).toEqual({ 'obj': null })
        }
    })

    test('user: delete User', async () => {
        const admin = await makeLoggedInAdminClient()
        const [objCreated] = await createTestUser(admin)

        const client = await makeClientWithNewRegisteredAndLoggedInUser()
        try {
            await User.delete(client, objCreated.id)
        } catch (e) {
            expect(e.errors[0]).toMatchObject({
                'message': 'You do not have access to this resource',
                'name': 'AccessDeniedError',
                'path': ['obj'],
            })
            expect(e.data).toEqual({ 'obj': null })
        }
    })

    test('anonymous: delete User', async () => {
        const admin = await makeLoggedInAdminClient()
        const [objCreated] = await createTestUser(admin)

        const client = await makeClient()
        try {
            await User.delete(client, objCreated.id)
        } catch (e) {
            expect(e.errors[0]).toMatchObject({
                'message': 'You do not have access to this resource',
                'name': 'AccessDeniedError',
                'path': ['obj'],
            })
            expect(e.data).toEqual({ 'obj': null })
        }
    })

    test('anonymous: count', async () => {
        const client = await makeClient()
        const { data, errors } = await User.count(client, {}, { raw: true })
        expect(data).toEqual({ meta: { count: null } })
        expect(errors[0]).toMatchObject({
            'data': { 'target': '_allUsersMeta', 'type': 'query' },
            'message': 'You do not have access to this resource',
            'name': 'AccessDeniedError',
            'path': ['meta', 'count'],
        })
    })

    test('user: count', async () => {
        const admin = await makeLoggedInAdminClient()
        const [, userAttrs] = await createTestUser(admin)
        const client = await makeLoggedInClient(userAttrs)
        const count = await User.count(client)
        expect(count).toBeGreaterThanOrEqual(2)
    })
})

describe('User utils', () => {
    test('createUser()', async () => {
        const admin = await makeLoggedInAdminClient()
        const [user, userAttrs] = await createTestUser(admin)
        expect(user.id).toMatch(/^[A-Za-z0-9-]+$/g)
        expect(userAttrs.email).toBeTruthy()
        expect(userAttrs.password).toBeTruthy()
    })

})

describe('User fields', () => {
    test('Convert email to lower case', async () => {
        const admin = await makeLoggedInAdminClient()
        const email = 'XXX' + getRandomString() + '@example.com'
        const [user, userAttrs] = await createTestUser(admin, { email })

        const objs = await UserAdmin.getAll(admin, { id: user.id })
        expect(objs[0]).toEqual(expect.objectContaining({ email: email.toLowerCase(), id: user.id }))

        const client2 = await makeLoggedInClient({ password: userAttrs.password, email: email.toLowerCase() })
        expect(client2.user.id).toEqual(user.id)

        // TODO(pahaz): fix in a future (it's no OK if you can't logged in by upper case email)
        const checkAuthByUpperCaseEmail = async () => {
            await makeLoggedInClient(userAttrs)
        }
        await expect(checkAuthByUpperCaseEmail).rejects.toThrow(/passwordAuth:identity:notFound/)
    })
})
