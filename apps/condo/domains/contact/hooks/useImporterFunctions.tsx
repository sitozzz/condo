import { Columns, ObjectCreator, RowNormalizer, RowValidator } from '@condo/domains/common/utils/importer'
import { useOrganization } from '@core/next/organization'
import { useApolloClient } from '@core/next/apollo'
import { useAddressApi } from '@condo/domains/common/components/AddressApi'
import get from 'lodash/get'
import { Contact } from '../utils/clientSchema'
import { searchProperty, searchContacts } from '@condo/domains/ticket/utils/clientSchema/search'

const { normalizePhone } = require('@condo/domains/common/utils/phone')

const parsePhones = (phones: string) => {
    const splitPhones = phones.split(/[, ;.]+/)
    return splitPhones.map(phone => {
        if (phone.startsWith('8')) {
            phone = '+7' + phone.substring(1)
        }
        phone = phone.replace(/[^0-9+]/g, '')
        return normalizePhone(phone)
    }).filter(phone => phone)
}

export const useImporterFunctions = (): [Columns, RowNormalizer, RowValidator, ObjectCreator] => {
    const userOrganization = useOrganization()
    const client = useApolloClient()
    const { addressApi } = useAddressApi()

    const userOrganizationId = get(userOrganization, ['organization', 'id'])

    // @ts-ignore
    const contactCreateAction = Contact.useCreate({},
        () => Promise.resolve())

    const columns: Columns = [
        { name: 'Address', type: 'string' },
        { name: 'Unit Name', type: 'string' },
        { name: 'Phones', type: 'string' },
        { name: 'Full name', type: 'string' },
    ]

    const contactNormalizer: RowNormalizer = (row) => {
        const addons = { address: null, property: null, phones: null, fullName: null }
        if (row.length !== columns.length) return Promise.resolve({ row })
        const [address, , phones, fullName] = row
        return addressApi.getSuggestions(String(address.value)).then(result => {
            const suggestion = get(result, ['suggestions', 0])
            if (suggestion) {
                addons.address = suggestion.value
                const where = {
                    address_contains_i: suggestion.value,
                    organization: { id: userOrganizationId },
                }
                // TODO (savelevMatthew): better way to detect building
                return searchProperty(client, where, undefined).then((res) => {
                    addons.property = res.length > 0 ? res[0].value : null
                    addons.phones = parsePhones(String(phones.value))
                    addons.fullName = String(fullName.value).trim()
                    return { row, addons }
                })
            }
            addons.phones = parsePhones(String(phones.value))
            addons.fullName = String(fullName.value).trim()
            return { row, addons }
        })
    }

    const contactValidator: RowValidator = (row) => {
        if (!row || !row.addons) return Promise.resolve(false)
        if (!row.addons.property) return Promise.resolve(false)
        if (!row.addons.fullName) return Promise.resolve(false)

        const unitName = get(row.row, ['1', 'value'])
        if (!unitName || String(unitName).trim().length === 0) return Promise.resolve(false)

        const phones = get(row.addons, ['phones'])
        if (!phones || phones.length === 0) return Promise.resolve(false)

        return Promise.resolve(true)
    }

    const contactCreator: ObjectCreator = (row) => {
        if (!row) return Promise.resolve()
        const unitName = String(get(row.row, ['1', 'value'])).trim().toLowerCase()
        const contactPool = []
        for (let i = 0; i < row.addons.phones.length; i++) {
            const phone: string = row.addons.phones[i]
            contactPool.push(searchContacts(client, {
                organizationId: userOrganizationId,
                propertyId: row.addons.property,
                unitName,
                // @ts-ignore
            }).then((result) => {
                const { data, loading, error } = result
                if (loading || error) return Promise.resolve()
                const alreadyRegistered = data.objs.some(contact => {
                    return contact.phone === phone && contact.name === row.addons.fullName
                })
                if (alreadyRegistered) return Promise.resolve()
                return contactCreateAction({
                    organization: String(userOrganizationId),
                    property: String(row.addons.property),
                    unitName,
                    phone: phone,
                    name: row.addons.fullName,
                })
            }))
        }
        return Promise.all(contactPool)
    }

    return [columns, contactNormalizer, contactValidator, contactCreator]
}