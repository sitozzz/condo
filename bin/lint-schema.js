const { prepareKeystoneExpressApp } = require('@core/keystone/test.utils')
const path = require('path')

const APPS = ['condo']

function verifySchema (keystone) {
    let errorCounter = 0
    const report = (msg) => { throw new Error(`WRONG-SCHEMA-DEFINITION[${errorCounter}]: ${msg}`) }
    Object.entries(keystone.lists).forEach(([key, list]) => {
        list.fields.forEach((field) => {
            if (field.isRelationship && !field.many) {
                const { kmigratorOptions, knexOptions } = field.config
                if (!kmigratorOptions || typeof kmigratorOptions !== 'object') {
                    report(`${list.key}->${field.path} relation without kmigratorOptions`)
                } else {
                    if (!kmigratorOptions.on_delete) {
                        report(`${list.key}->${field.path} relation without on_delete! Example: "kmigratorOptions: { null: false, on_delete: 'models.CASCADE' }". Chose one: CASCADE, PROTECT, SET_NULL, DO_NOTHING`)
                    }
                    if (kmigratorOptions.null === false) {
                        if (!knexOptions || typeof knexOptions !== 'object' || knexOptions.isNotNullable !== true) {
                            report(`${list.key}->${field.path} non nullable relation should have knexOptions like: "knexOptions: { isNotNullable: true }"`)
                        }
                        if (knexOptions.on_delete) {
                            report(`${list.key}->${field.path} knexOptions should not contain on_delete key!`)
                        }
                    }
                }
            }
        })
    })
    if (errorCounter > 0) throw new Error(`Your have ${errorCounter} WRONG-SCHEMA-DEFINITION! Fix it first!`)
}

async function processKeystoneSchema (keystone) {
    verifySchema(keystone)
}

async function main () {
    const name = path.basename(process.cwd())
    const root = path.join(__dirname, '..', 'apps', name)

    for (const app of APPS) {
        console.log('LINT', app)
        const module = require(path.join(root, 'index'))
        const { keystone } = await prepareKeystoneExpressApp(module)
        await processKeystoneSchema(keystone)
    }

    process.exit(0)
}

main().catch((e) => {
    console.error(e)
    process.exit(1)
})