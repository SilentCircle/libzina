// The JSON tags for group commands, data etc.
//
// Created by werner on 22.05.16.
//

#ifndef LIBAXOLOTL_JSONSTRINGS_H
#define LIBAXOLOTL_JSONSTRINGS_H

namespace axolotl {
    static const char* GROUP_ID = "grpId";
    static const char* GROUP_NAME = "name";
    static const char* GROUP_OWNER = "ownerId";
    static const char* GROUP_DESC = "desc";
    static const char* GROUP_MAX_MEMBERS = "maxMbr";
    static const char* GROUP_MEMBER_COUNT = "mbrCnt";
    static const char* GROUP_ATTRIBUTE = "grpA";
    static const char* GROUP_MOD_TIME = "grpMT";

    static const char* MEMBER_ID = "mbrId";
//    static const char* MEMBER_DEVICE_ID = "devId";
    static const char* MEMBER_ATTRIBUTE = "mbrA";
    static const char* MEMBER_MOD_TIME = "mbrMT";

    static const char* MSG_RECIPIENT = "recipient";
    static const char* MSG_ID = "msgId";
    static const char* MSG_MESSAGE = "message";
    static const char* MSG_SENDER = "sender";

    static const char* GROUP_COMMAND = "grp";

    // The following string follow the GROUP_COMMAND and identify the command
    static const char* INVITE = "inv";          //!< Group Invitation
    static const char* INVITE_ANSWER = "ian";   //!< Invitation answer
    static const char* MEMBER_LIST = "mls";     //!< Command contain a group's member list
    static const char* HELLO = "hel";           //!< Introduce myself as a new member of the list
    static const char* REQUEST_MEMBER_LIST = "rls"; //!< Command to request a group's member list

    static const char* INVITE_SYNC = "s_inv";   //!< Sync accepted Group Invitation

    // Parameters inside commands other than generic Group or Member tags
    static const char* TOKEN = "tok";
    static const char* ACCEPTED = "acc";
    static const char* REASON = "rsn";
    static const char* MEMBERS = "mbrs";
    static const char* INITIAL_LIST = "ini";
    static const char* LIST_HASH = "hash";


}
#endif //LIBAXOLOTL_JSONSTRINGS_H
