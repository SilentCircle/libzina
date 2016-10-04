// The JSON tags for group commands, data etc.
//
// Created by werner on 22.05.16.
//

#ifndef LIBZINA_JSONSTRINGS_H
#define LIBZINA_JSONSTRINGS_H

namespace zina {
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

    static const char* MSG_VERSION = "version";
    static const char* MSG_RECIPIENT = "recipient";
    static const char* MSG_ID = "msgId";
    static const char* MSG_MESSAGE = "message";
    static const char* MSG_SENDER = "sender";
    static const char* MSG_DEVICE_ID = "scClientDevId";
    static const char* MSG_DISPLAY_NAME = "display_name";
    static const char* MSG_COMMAND = "cmd";
    static const char* MSG_SYNC_COMMAND = "syc";
    static const char* MSG_TYPE = "type";

    // The following strings follow the MSG_COMMAND and identify the command
    static const char* DELIVERY_RECEIPT = "dr";

    // Error commands, sent by message receiver to the sender
    static const char* DR_DATA_REQUIRED = "errdrq";     //!< Not Delivered Due to Policy: DR required [ERRDRQ]
    static const char* DR_META_REQUIRED = "errmrq";     //!< Not Delivered Due to Policy: MR required [ERRMRQ]
    static const char* DR_DATA_REJECTED = "errdrj";     //!< Not Delivered Due to Policy: DR rejected [ERRDRJ]
    static const char* DR_META_REJECTED = "errmrj";     //!< Not Delivered Due to Policy: MR rejected [ERRMRJ]
    static const char* DECRYPTION_FAILED = "errdecf";   //!< Not Delivered Due to decryption failure [ERRDECF]

    static const char* GROUP_COMMAND = "grp";

    // The following strings follow the GROUP_COMMAND and identify the command
    static const char* INVITE = "inv";          //!< Group Invitation
    static const char* INVITE_ANSWER = "ian";   //!< Invitation answer
    static const char* MEMBER_LIST = "mls";     //!< Command contain a group's member list
    static const char* HELLO = "hel";           //!< Introduce myself as a new member of the list
    static const char* REQ_MEMBER_LIST = "rls"; //!< Command to request a group's member list
    static const char* LEAVE = "lve";           //!< Leave a group
    static const char* NOT_MEMBER = "nmbr";     //!< Not a member of the group
    static const char* NEW_GROUP_SYNC = "ngrp"; //!< sent to siblings to sync a group creation

    static const char* INVITE_SYNC = "s_inv";   //!< Sync accepted Group Invitation

    // Parameters inside commands other than generic Group or Member tags
    static const char* TOKEN = "tok";
    static const char* ACCEPTED = "acc";
    static const char* REASON = "rsn";
    static const char* MEMBERS = "mbrs";
    static const char* INITIAL_LIST = "ini";
    static const char* LIST_HASH = "hash";
    static const char* DELIVERY_TIME = "dr_time";
    static const char* COMMAND_TIME = "cmd_time"; //!< Time at client (ZULU) when it created the command

    // JSON keys for local messaging retention flags
    static const char* LRMM = "lrmm";           //!< local client retains message metadata
    static const char* LRMP = "lrmp";           //!< local client retains message plaintext
    static const char* LRAP = "lrap";           //!< local client retains attachment plaintext
    static const char* BLDR = "bldr";           //!< Block local data retention
    static const char* BLMR = "blmr";           //!< Block local metadata retention
    static const char* BRDR = "brdr";           //!< Block remote data retention
    static const char* BRMR = "brmr";           //!< Block remote metadata retention

    // JSON keys for remote user messaging retention flags
    static const char* RETENTION_ORG = "ret_org";
    static const char* RRMM = "rrmm";
    static const char* RRMP = "rrmp";
    static const char* RRCM = "rrcm";
    static const char* RRCP = "rrcp";
    static const char* RRAP = "rrap";

    // JSON keys in message attributes to show DR states
    static const char* RAP = "RAP";             //!< set bey sender: "retention accepted plaintext"
    static const char* RAM = "RAM";             //!< set bey sender: "retention accepted metadata"
    static const char* ROP = "ROP";             //!< set bey sender: "retention occurred plaintext"
    static const char* ROM = "ROM";             //!< set bey sender: "retention occurred metadata"

}
#endif //LIBZINA_JSONSTRINGS_H
