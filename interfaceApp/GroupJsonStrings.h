// The JSON tags for group commands, data etc.
//
// Created by werner on 22.05.16.
//

#ifndef LIBAXOLOTL_GROUPJSONSTRINGS_H
#define LIBAXOLOTL_GROUPJSONSTRINGS_H

namespace axolotl {
    static const char* GROUP_ID = "groupId";
    static const char* GROUP_NAME = "name";
    static const char* GROUP_OWNER = "ownerId";
    static const char* GROUP_DESC = "description";
    static const char* GROUP_MAX_MEMBERS = "maxMembers";
    static const char* GROUP_MEMBER_COUNT = "memberCount";

    static const char* MEMBER_ID = "memberId";
    static const char* DEVICE_ID = "deviceId";

    static const char* INVITE_TOKEN = "inviteToken";

    static const char* GROUP_COMMAND = "grp";

    // The following string follow the GROUP_COMMAND and identify the command action
    static const char* INVITE = "inv";
}
#endif //LIBAXOLOTL_GROUPJSONSTRINGS_H
