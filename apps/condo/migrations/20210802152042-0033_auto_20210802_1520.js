// auto generated by kmigrator
// KMIGRATOR:0033_auto_20210802_1520:IyBHZW5lcmF0ZWQgYnkgRGphbmdvIDMuMi41IG9uIDIwMjEtMDgtMDIgMTA6MjANCg0KaW1wb3J0IGRqYW5nby5jb250cmliLnBvc3RncmVzLmZpZWxkcy5qc29uYg0KZnJvbSBkamFuZ28uZGIgaW1wb3J0IG1pZ3JhdGlvbnMsIG1vZGVscw0KDQoNCmNsYXNzIE1pZ3JhdGlvbihtaWdyYXRpb25zLk1pZ3JhdGlvbik6DQoNCiAgICBkZXBlbmRlbmNpZXMgPSBbDQogICAgICAgICgnX2RqYW5nb19zY2hlbWEnLCAnMDAzMl9hbHRlcl9mb3Jnb3RwYXNzd29yZGFjdGlvbl90b2tlbicpLA0KICAgIF0NCg0KICAgIG9wZXJhdGlvbnMgPSBbDQogICAgICAgIG1pZ3JhdGlvbnMuQWRkRmllbGQoDQogICAgICAgICAgICBtb2RlbF9uYW1lPSdvcmdhbml6YXRpb25lbXBsb3llZXJvbGUnLA0KICAgICAgICAgICAgbmFtZT0nZGVzY3JpcHRpb24nLA0KICAgICAgICAgICAgZmllbGQ9bW9kZWxzLlRleHRGaWVsZChkZWZhdWx0PU5vbmUpLA0KICAgICAgICAgICAgcHJlc2VydmVfZGVmYXVsdD1GYWxzZSwNCiAgICAgICAgKSwNCiAgICAgICAgbWlncmF0aW9ucy5BZGRGaWVsZCgNCiAgICAgICAgICAgIG1vZGVsX25hbWU9J29yZ2FuaXphdGlvbmVtcGxveWVlcm9sZWhpc3RvcnlyZWNvcmQnLA0KICAgICAgICAgICAgbmFtZT0nZGVzY3JpcHRpb24nLA0KICAgICAgICAgICAgZmllbGQ9ZGphbmdvLmNvbnRyaWIucG9zdGdyZXMuZmllbGRzLmpzb25iLkpTT05GaWVsZChibGFuaz1UcnVlLCBudWxsPVRydWUpLA0KICAgICAgICApLA0KICAgICAgICBtaWdyYXRpb25zLkFsdGVyRmllbGQoDQogICAgICAgICAgICBtb2RlbF9uYW1lPSdvcmdhbml6YXRpb25lbXBsb3llZXJvbGVoaXN0b3J5cmVjb3JkJywNCiAgICAgICAgICAgIG5hbWU9J25hbWUnLA0KICAgICAgICAgICAgZmllbGQ9ZGphbmdvLmNvbnRyaWIucG9zdGdyZXMuZmllbGRzLmpzb25iLkpTT05GaWVsZChibGFuaz1UcnVlLCBudWxsPVRydWUpLA0KICAgICAgICApLA0KICAgIF0NCg==

exports.up = async (knex) => {
    await knex.raw(`
    BEGIN;
--
-- Add field description to organizationemployeerole
--
ALTER TABLE "OrganizationEmployeeRole" ADD COLUMN "description" text NOT NULL;
--
-- Add field description to organizationemployeerolehistoryrecord
--
ALTER TABLE "OrganizationEmployeeRoleHistoryRecord" ADD COLUMN "description" jsonb NULL;
--
-- Alter field name on organizationemployeerolehistoryrecord
--
ALTER TABLE "OrganizationEmployeeRoleHistoryRecord" ALTER COLUMN "name" TYPE jsonb USING "name"::jsonb;
COMMIT;

    `)
}

exports.down = async (knex) => {
    await knex.raw(`
    BEGIN;
--
-- Alter field name on organizationemployeerolehistoryrecord
--
ALTER TABLE "OrganizationEmployeeRoleHistoryRecord" ALTER COLUMN "name" TYPE text USING "name"::text;
--
-- Add field description to organizationemployeerolehistoryrecord
--
ALTER TABLE "OrganizationEmployeeRoleHistoryRecord" DROP COLUMN "description" CASCADE;
--
-- Add field description to organizationemployeerole
--
ALTER TABLE "OrganizationEmployeeRole" DROP COLUMN "description" CASCADE;
COMMIT;

    `)
}