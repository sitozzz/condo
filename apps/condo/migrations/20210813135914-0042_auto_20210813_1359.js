// auto generated by kmigrator
// KMIGRATOR:0042_auto_20210813_1359:IyBHZW5lcmF0ZWQgYnkgRGphbmdvIDMuMi41IG9uIDIwMjEtMDgtMTMgMDg6NTkNCg0KZnJvbSBkamFuZ28uZGIgaW1wb3J0IG1pZ3JhdGlvbnMsIG1vZGVscw0KDQoNCmNsYXNzIE1pZ3JhdGlvbihtaWdyYXRpb25zLk1pZ3JhdGlvbik6DQoNCiAgICBkZXBlbmRlbmNpZXMgPSBbDQogICAgICAgICgnX2RqYW5nb19zY2hlbWEnLCAnMDA0MV9hdXRvXzIwMjEwODEyXzEzNDAnKSwNCiAgICBdDQoNCiAgICBvcGVyYXRpb25zID0gWw0KICAgICAgICBtaWdyYXRpb25zLkFsdGVyRmllbGQoDQogICAgICAgICAgICBtb2RlbF9uYW1lPSdvcmdhbml6YXRpb25lbXBsb3llZScsDQogICAgICAgICAgICBuYW1lPSdpZCcsDQogICAgICAgICAgICBmaWVsZD1tb2RlbHMuVVVJREZpZWxkKHByaW1hcnlfa2V5PVRydWUsIHNlcmlhbGl6ZT1GYWxzZSksDQogICAgICAgICksDQogICAgICAgIG1pZ3JhdGlvbnMuQWx0ZXJGaWVsZCgNCiAgICAgICAgICAgIG1vZGVsX25hbWU9J29yZ2FuaXphdGlvbmVtcGxveWVlJywNCiAgICAgICAgICAgIG5hbWU9J25ld0lkJywNCiAgICAgICAgICAgIGZpZWxkPW1vZGVscy5VVUlERmllbGQoYmxhbms9VHJ1ZSwgbnVsbD1UcnVlKSwNCiAgICAgICAgKSwNCiAgICAgICAgbWlncmF0aW9ucy5BbHRlckZpZWxkKA0KICAgICAgICAgICAgbW9kZWxfbmFtZT0nb3JnYW5pemF0aW9uZW1wbG95ZWVoaXN0b3J5cmVjb3JkJywNCiAgICAgICAgICAgIG5hbWU9J2hpc3RvcnlfaWQnLA0KICAgICAgICAgICAgZmllbGQ9bW9kZWxzLlVVSURGaWVsZChkYl9pbmRleD1UcnVlKSwNCiAgICAgICAgKSwNCiAgICBdDQo=

exports.up = async (knex) => {
    await knex.raw(`
    BEGIN;
    CREATE EXTENSION if not exists "uuid-ossp";

    --
    -- Rename id -> old_id
    --
    ALTER TABLE "OrganizationEmployee" RENAME COLUMN "id" TO "old_id";
    ALTER TABLE "OrganizationEmployee" ADD COLUMN "id" UUID NULL;

    -- id -> id = uuid
    UPDATE "OrganizationEmployee" SET "id" = uuid_generate_v4();

    -- Drop old PK and change it.
    ALTER TABLE "OrganizationEmployee" DROP CONSTRAINT "OrganizationEmployee_pkey";
    ALTER TABLE "OrganizationEmployee" ADD PRIMARY KEY ("id");

    -- Rename history_id to old_history_id
    ALTER TABLE "OrganizationEmployeeHistoryRecord" RENAME COLUMN "history_id" TO "old_history_id";
    -- Create history id
    ALTER TABLE "OrganizationEmployeeHistoryRecord" ADD COLUMN "history_id" UUID NULL;

    -- Set OrganizationEmployeeHistoryRecord.history_id = OrganizationEmployee.id where OrganizationEmployee.old_id = OrganizationEmployeeHistoryRecord.old_history_id
    UPDATE "OrganizationEmployeeHistoryRecord" hr
    SET "history_id" = e."id"
    FROM "OrganizationEmployee" as e
    WHERE(
      e."old_id" = hr."old_history_id"
    );

    ALTER TABLE "OrganizationEmployeeHistoryRecord" ALTER COLUMN "history_id" SET NOT NULL;
    ALTER TABLE "OrganizationEmployeeHistoryRecord" ALTER COLUMN "old_history_id" SET NULL;

    --
    -- Rename newId to old_newId
    --
    ALTER TABLE "OrganizationEmployee" RENAME COLUMN "newId" TO "old_newId";
    ALTER TABLE "OrganizationEmployee" ADD COLUMN "newId" UUID NULL;

    COMMIT;
    END;
    `)
}

exports.down = async (knex) => {
    await knex.raw(`
    BEGIN;

    ALTER TABLE "OrganizationEmployee" RENAME COLUMN "id" TO "_old_id";
    ALTER TABLE "OrganizationEmployee" RENAME COLUMN "old_id" TO "id";
    ALTER TABLE "OrganizationEmployee" DROP COLUMN "_old_id";

--     ALTER TABLE "OrganizationEmployee" DROP CONSTRAINT "OrganizationEmployee_pkey";
    ALTER TABLE "OrganizationEmployee" ADD PRIMARY KEY ("id");

    ALTER TABLE "OrganizationEmployeeHistoryRecord" RENAME COLUMN "history_id" TO "_old_history_id";
    ALTER TABLE "OrganizationEmployeeHistoryRecord" RENAME COLUMN "old_history_id" TO "history_id";
    ALTER TABLE "OrganizationEmployeeHistoryRecord" DROP COLUMN "_old_history_id";

    ALTER TABLE "OrganizationEmployee" RENAME COLUMN "newId" TO "_old_newId";
    ALTER TABLE "OrganizationEmployee" RENAME COLUMN "old_newId" TO "newId";
    ALTER TABLE "OrganizationEmployee" DROP COLUMN "_old_newId";

    COMMIT;
    END;
    `)
}