-- Plugin for PAM attributes
--
-- Creates the following:
--   User Attributes: uidnumber, gidnumber
--   Group Attributes: gidnumber
--   Groups: pam_users
--
-- Strives to maintain:
--   Users: all have a unique uidnumber
--   Users: all users by default have a gidnumber corresponding to the
--          pam_users group created.
--   Groups: all groups have a unique uidnumber
--
-- Group will only be created when a user needs the gidnumber for
-- it, this is done to avoid it being created as group 1, before
-- lldap_admin, in new setups.
--
-- TODO:
--   1. 'pam_users' group should be configurable
--   2. defined offsets and shared group should come from lldap config
--   3. max uid should be stored in a key-value store instead
--

local gid_offset = 100000
local uid_offset = 100000

local resolve_gid_default_group = function(context)
    local groups = context.api:list_groups({ filter = "(cn=pam_users)" })
    local group_id = nil
    if lldap.tables:empty(groups) then
        lldap.log:debug("Creating 'pam_users' group")
        local id, err = context.api:create_group({
            display_name = "pam_users",
            attributes = {}
        })
        if err ~= nil then
            -- Error
            error("Failed to create 'pam_users' group", 1)
        end
        lldap.log:debug("Created 'pam_users' group with id " .. tostring(id))
        local group_gidnumber = gid_offset + id
        local res, err = context.api:update_group({
            group_id = id,
            insert_attributes = {
                gidnumber = { int = group_gidnumber }
            }
        })
        if err ~= nil then
            error("Failed to set gidnumber attribute to 'pam_users' group")
        end
        lldap.log:debug("Assigned gidnumber to 'pam_users': " .. tostring(group_gidnumber))
        group_id = group_gidnumber
    else
        group_id = groups[1].attributes.gidnumber.int
    end
    return group_id
end

local assign_user_attributes = function(context)
    -- Ensure that the uidNumber for the created user is unique.
    lldap.log:debug("Resolving current maximum uid and gid")
    local max_uid = uid_offset
    -- obtain list of all users in the system
    local users, err = context.api:list_users({})
    if err ~= nil then
        -- Error
        return err
    end
    if not lldap.tables:empty(users) then
        -- obtain id of shared pam_users group
        local group_id = resolve_gid_default_group(context)
        lldap.log:debug("Resolved 'pam_users' group to ID: " .. tostring(group_id))
        -- determine current max uid
        for idx, user_and_group in pairs(users) do
            if user_and_group.user.attributes.uidnumber ~= nil then
                local uid = user_and_group.user.attributes.uidnumber.int
                if uid > max_uid then
                    max_uid = uid
                end
            end
        end
        lldap.log:debug("Resolved maximum uidnumber to: " .. tostring(max_uid))
        -- determined max uid, continue with assigning to any users missing
        for idx, user_and_group in pairs(users) do
            if user_and_group.user.attributes.uidnumber == nil then
                -- increment max_uid
                max_uid = max_uid + 1
                -- assign the uid to user
                local res, err = context.api:update_user({
                    user_id = user_and_group.user.user_id,
                    insert_attributes = {
                        uidnumber = { int = max_uid },
                    }
                })
                if err ~= nil then
                    lldap.log:warn("Failed to set uidnumber for user_id: " .. user_and_group.user.user_id)
                end
            end
            if user_and_group.user.attributes.gidnumber == nil then
                -- assign the gid to user
                local res, err = context.api:update_user({
                    user_id = user_and_group.user.user_id,
                    insert_attributes = {
                        gidnumber = { int = group_id }
                    }
                })
                if err ~= nil then
                    lldap.log:warn("Failed to set gidnumber for user_id: " .. user_and_group.user.user_id)
                end
            end
        end
    end
end

local assign_group_attributes = function(context)
    local groups, err = context.api:list_groups({})
    if err ~= nil then
        lldap.log:warn("Unable to search groups")
    else
        for idx, group in pairs(groups) do
            lldap.log:debug("Group: " .. group.display_name)
            if group.attributes.gidnumber == nil then
                local res, err = context.api:update_group({
                    group_id = group.group_id,
                    insert_attributes = {
                        gidnumber = { int = gid_offset + group.group_id }
                    }
                })
                if err ~= nil then
                    lldap.log:warn("Failed to set gidnumber for group: " .. group.display_name)
                end
            end
        end
    end
end

local ensure_user_attribute_exists = function(context, schema, attribute_name, attribute_type)
    if schema.user_attributes.attributes[attribute_name] == nil then
        local res = context.api:add_user_attribute({
            name = attribute_name,
            attribute_type = attribute_type,
            is_list = false,
            is_visible = true,
            is_editable = false,
        })
        if res ~= nil then
            -- Error.
            error("Got error from creating '" .. attribute_name .. "' attribute", 1)
        end
    end
end

local ensure_group_attribute_exists = function(context, schema, attribute_name, attribute_type)
    if schema.group_attributes.attributes[attribute_name] == nil then
        local res = context.api:add_group_attribute({
            name = attribute_name,
            attribute_type = attribute_type,
            is_list = false,
            is_visible = true,
            is_editable = false,
        })
        if res ~= nil then
            -- Error.
            error("Got error from creating '" .. attribute_name .. "' group attribute", 1)
        end
    end
end

local initialize_attributes = function(context)
    local schema = context.api:get_schema()
    -- ensure we have the basic samba related attributes for users
    lldap.log:debug("Creating user attributes")
    ensure_user_attribute_exists(context, schema, "uidnumber", "Integer")
    ensure_user_attribute_exists(context, schema, "gidnumber", "Integer")
    -- ensure we have the basic samba related attributes for groups
    lldap.log:debug("Creating group attributes")
    ensure_group_attribute_exists(context, schema, "gidnumber", "Integer")
    -- assign uidnumber and gidnumber to all users missing it
    assign_user_attributes(context)
    -- assign gidnumber to all groups missing it
    assign_group_attributes(context)
end

local on_created_user = function(context, args)
    -- User has been created, assign a uid to it.
    -- we do it after the user has been created, a bit as preparation for
    -- when we get a key-value store to maintain the uid. With that, we'll
    -- need to register the assigned gidnumber before the user is actually
    -- created, which might leave us with gaps if user creation ultimately
    -- fails.
    -- Should be fine to do it after the user has been created, if it fails,
    -- it'll get one assigned on next user creation, or restart.

    -- assign uidnumber and gidnumber to all users missing it
    assign_user_attributes(context)

    -- The returned args will replace the original args.
    return args
end

local on_created_group = function(context, args)
    -- assign gidnumber to all groups missing it
    assign_group_attributes(context)
    return args
end

return {
    name = "pam",
    version = "1.0",
    author = "broeng",
    repo = "https://github.com/broeng/lldap-plugins/blob/main/pam/pam.lua",
    init = initialize_attributes,
    listeners = {
        { event = "on_created_user",  priority = 50, impl = on_created_user },
        { event = "on_created_group", priority = 50, impl = on_created_group },
    },
}
