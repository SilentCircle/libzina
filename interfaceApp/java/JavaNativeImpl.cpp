
#ifdef ANDROID
#include <android/log.h>
#else
#include <stdio.h>
#endif

#include "axolotl_AxolotlNative.h"
#include "../AppInterfaceImpl.h"
#include "../../appRepository/AppRepository.h"
#include "../../interfaceTransport/sip/SipTransport.h"
#include "../../axolotl/state/AxoConversation.h"
#include "../../axolotl/crypto/EcCurve.h"
#include "../../axolotl/crypto/DhKeyPair.h"
#include <stdarg.h>
#include <vector>
#include <string>

using namespace axolotl;

/**
 * Define -DPACKAGE_NAME="Java_some_package_name_" to define another package 
 * name during compilation
 */
#ifndef PACKAGE_NAME
#define PACKAGE_NAME Java_axolotl_AxolotlNative_
#endif

#define CONCATx(a,b) a##b
#define CONCAT(a,b) CONCATx(a,b)

#define JNI_FUNCTION(FUNC_NAME)  CONCAT(PACKAGE_NAME, FUNC_NAME)


#define LOGGING
#ifdef LOGGING
#define LOG(deb)   deb
#else
#define LOG(deb)
#endif

#ifdef EMBEDDED
JavaVM *t_getJavaVM();
#endif

static AppInterfaceImpl* axoAppInterface = NULL;
static JavaVM* javaVM = NULL;

// Set in doInit(...)
static jobject axolotlCallbackObject = NULL;
static jmethodID receiveMessageCallback = NULL;
static jmethodID stateReportCallback = NULL;
static jmethodID httpHelperCallback = NULL;

static int32_t debugLevel = 1;

static void Log(char const *format, va_list arg) {
#ifdef ANDROID
    LOG(if (debugLevel > 0) __android_log_vprint(ANDROID_LOG_DEBUG, "axolotl", format, arg);)
#else
    LOG(if (debugLevel > 0){ vfprintf(stderr, format, arg); fprintf(stderr, "\n");})
#endif
}


void Log(const char* format, ...)
{
    va_list arg;
    va_start(arg, format);
    Log(format, arg);
    va_end( arg );
}


// typedef void (*SEND_DATA_FUNC)(uint8_t* [], uint8_t* [], uint8_t* [], size_t [], uint64_t []);
#ifdef UNITTESTS
// names, devIds, envelopes, sizes, msgIds
static void sendDataFuncTesting(uint8_t* names[], uint8_t* devIds[], uint8_t* envelopes[], size_t sizes[], uint64_t msgIds[])
{
//    Log("sendData: %s - %s - %s\n", names[0], devIds[0], envelopes[0]);

    std::string fName((const char*)names[0]);
    fName.append((const char*)devIds[0]).append(".msg");

    FILE* msgFile = fopen(fName.c_str(), "w");

    size_t num = fwrite(envelopes[0], 1, sizes[0], msgFile);
    Log("Message file written: %d bytes\n", num);
    fclose(msgFile);
    msgIds[0] = 4711;
}

static void reciveData(const std::string msgFileName)
{
    uint8_t msgData[2000];
    FILE* msgFile = fopen(msgFileName.c_str(), "r");
    if (msgFile == NULL) {
        Log("Message file %s not found\n", msgFileName.c_str());
        return;
    }

    size_t num = fread(msgData, 1, 2000, msgFile);
    Log("Message file read: %d bytes\n", num);
    axoAppInterface->getTransport()->receiveAxoMessage(msgData, num);
    fclose(msgFile);

}
#endif

static bool arrayToString(JNIEnv* env, jbyteArray array, std::string* output)
{
    if (array == NULL)
        return false;

    int dataLen = env->GetArrayLength(array);
    if (dataLen <= 0)
        return false;

    const uint8_t* tmp = (uint8_t*)env->GetByteArrayElements(array, 0);
    if (tmp == NULL)
        return false;

    output->assign((const char*)tmp, dataLen);
    env->ReleaseByteArrayElements(array, (jbyte*)tmp, 0);
    return true;
}

static jbyteArray stringToArray(JNIEnv* env, const std::string& input)
{
    jbyteArray data = env->NewByteArray(input.size());
    if (data == NULL)
        return NULL;
    if (input.size() == 0)
        return NULL;
    env->SetByteArrayRegion(data, 0, input.size(), (jbyte*)input.data());
    return data;
}

static void setReturnCode(JNIEnv* env, jintArray codeArray, int32_t result, int32_t data = 0)
{
    jint* code = env->GetIntArrayElements(codeArray, 0);
    code[0] = result;
    if (data != 0)
        code[1] = data;
    env->ReleaseIntArrayElements(codeArray, code, 0);
}


/**
 * Local helper class to keep track of thread attach / thread detach
 */
class CTJNIEnv {
    JNIEnv *env;
    bool attached;
public:
    CTJNIEnv() : attached(false), env(NULL) {

#ifdef EMBEDDED
        if (!javaVM)
            javaVM = t_getJavaVM();
#endif

        if (!javaVM)
            return;

        int s = javaVM->GetEnv((void**)&env, JNI_VERSION_1_6);
        if (s != JNI_OK){
#ifdef ANDROID
            s = javaVM->AttachCurrentThread(&env, NULL);
#else
            s = javaVM->AttachCurrentThread((void**)&env, NULL);
#endif
            if (!env || s < 0) {
                env = NULL;
                return;
            }
            attached = true;
        }
    }

    ~CTJNIEnv() {
        if (attached && javaVM)
            javaVM->DetachCurrentThread();
    }

    JNIEnv *getEnv() {
        return env;
    }
};

// A global symbol to force loading of the object in case of embedded usage
void loadAxolotl() 
{
}

/*
 * Receive message callback for AppInterfaceImpl.
 * 
 * "([B[B[B)I"
 */
int32_t receiveMessage(const std::string& messageDescriptor, const std::string& attachementDescriptor = std::string(), const std::string& messageAttributes = std::string())
{
    if (axolotlCallbackObject == NULL)
        return -1;

    CTJNIEnv jni;
    JNIEnv *env = jni.getEnv();
    if (!env)
        return -2;

    jbyteArray message = stringToArray(env, messageDescriptor);
    Log("receiveMessage - message: '%s' - length: %d", messageDescriptor.c_str(), messageDescriptor.size());

    jbyteArray attachment = NULL;
    if (!attachementDescriptor.empty()) {
        attachment = stringToArray(env, attachementDescriptor);
        if (attachment == NULL) {
            return -4;
        }
    }
    jbyteArray attributes = NULL;
    if (!messageAttributes.empty()) {
        attributes = stringToArray(env, messageAttributes);
        if (attributes == NULL) {
            return -4;
        }
    }
    int32_t result = env->CallIntMethod(axolotlCallbackObject, receiveMessageCallback, message, attachment, attributes);

    env->DeleteLocalRef(message);
    if (attachment != NULL)
        env->DeleteLocalRef(attachment);
    if (attributes != NULL)
        env->DeleteLocalRef(attributes);

    return result;
}

/*
 * State change callback for AppInterfaceImpl.
 * 
 * "(J[B)V"
 */
void messageStateReport(int64_t messageIdentfier, int32_t statusCode, const std::string& stateInformation)
{
    if (axolotlCallbackObject == NULL)
        return;

    CTJNIEnv jni;
    JNIEnv *env = jni.getEnv();
    if (!env)
        return;

    jbyteArray information = NULL;
    if (!stateInformation.empty()) {
        information = stringToArray(env, stateInformation);
    }
    env->CallVoidMethod(axolotlCallbackObject, stateReportCallback, messageIdentfier, statusCode, information);
    if (information != NULL)
        env->DeleteLocalRef(information);
}

/*
 * Class:     AxolotlNative
 * Method:    httpHelper
 * Signature: ([BLjava/lang/String;[B[I)[B
 */
/*
 * HTTP request helper callback for provisioning etc.
 */
#define JAVA_HELPER
#if defined JAVA_HELPER || defined UNITTESTS
int32_t httpHelper(const std::string& requestUri, const std::string& method, const std::string& requestData, std::string* response)
{
    if (axolotlCallbackObject == NULL)
        return -1;

    CTJNIEnv jni;
    JNIEnv *env = jni.getEnv();

    if (!env) {
        return -2;
    }

    jbyteArray uri = NULL;
    uri = env->NewByteArray(requestUri.size());
    if (uri == NULL)
        return -3;
    env->SetByteArrayRegion(uri, 0, requestUri.size(), (jbyte*)requestUri.data());

    jbyteArray reqData = NULL;
    if (!requestData.empty()) {
        reqData = stringToArray(env, requestData);
    }
    jstring mthod = env->NewStringUTF(method.c_str());

    jintArray code = env->NewIntArray(1);

    jbyteArray data = (jbyteArray)env->CallObjectMethod(axolotlCallbackObject, httpHelperCallback, uri, mthod, reqData, code);
     if (data != NULL) {
        arrayToString(env, data, response);
    }
    int32_t result = -1;
    env->GetIntArrayRegion(code, 0, 1, &result);

    env->DeleteLocalRef(uri);
    if (reqData != NULL)
        env->DeleteLocalRef(reqData);
    env->DeleteLocalRef(mthod);
    env->DeleteLocalRef(code);

    return result;
}
#else
static int32_t httpHelper(const std::string& requestUri, const std::string& method, const std::string& requestData, std::string* response)
{

    char* t_send_http_json(const char *url, const char *meth,  char *bufResp, int iMaxLen, int &iRespContentLen, const char *pContent);

    Log("httpHelper request, method: '%s', url '%s'", method.c_str(), requestUri.c_str());
    if (requestData.size() > 0) {
        Log("httpHelper request, data: '%s'", requestData.c_str());
    }

    int iSizeOfRet = 4 * 1024;
    char *retBuf = new char [iSizeOfRet];
    int iContentLen = 0;

    int code = 0;
    char *content = t_send_http_json (requestUri.c_str(), method.c_str(), retBuf, iSizeOfRet - 1, iContentLen, requestData.c_str());

    Log("httpHelper response data: '%s'", content ? content : "No response data");

    if(content && iContentLen > 0 && response)
        response->assign((const char*)content, iContentLen);

    delete retBuf;

    if(iContentLen < 1)
        return -1;
   return 200;
}
#endif

#ifndef EMBEDDED
jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
    javaVM = vm;
    return JNI_VERSION_1_6;
}
#endif

/*
 * Class:     AxolotlNative
 * Method:    doInit
 * Signature: (ILjava/lang/String;[B[B[B)I
 */
/*
 * Class:     axolotl_AxolotlNative
 * Method:    doInit
 * Signature: (ILjava/lang/String;[B[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_axolotl_AxolotlNative_doInit
  (JNIEnv *, jobject, jint, jstring, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

JNIEXPORT jint JNICALL 
JNI_FUNCTION(doInit)(JNIEnv* env, jobject thiz, jint debug, jstring dbName, jbyteArray dbPassphrase, jbyteArray userName,
                    jbyteArray authorization, jbyteArray scClientDeviceId)
{
    debugLevel = debug;
    if (axolotlCallbackObject == NULL) {
        axolotlCallbackObject = env->NewGlobalRef(thiz);
        if (axolotlCallbackObject == NULL) {
            return -1;
        }
        jclass callbackClass = NULL;
        callbackClass = env->GetObjectClass(axolotlCallbackObject);
        if (callbackClass == NULL) {
            return -2;
        }
        receiveMessageCallback = env->GetMethodID(callbackClass, "receiveMessage", "([B[B[B)I");
        if (receiveMessageCallback == NULL) {
            return -3;
        }
        stateReportCallback = env->GetMethodID(callbackClass, "messageStateReport", "(JI[B)V");
        if (stateReportCallback == NULL) {
            return -4;
        }
        httpHelperCallback = env->GetMethodID(callbackClass, "httpHelper", "([BLjava/lang/String;[B[I)[B");
        if (httpHelperCallback == NULL) {
            return -5;
        }

    }
    std::string name;
    if (!arrayToString(env, userName, &name) || name.empty()) {
        return -10;
    }

    std::string auth;
    if (!arrayToString(env, authorization, &auth) || auth.empty()) {
        return -11;
    }

    std::string devId;
    if (!arrayToString(env, scClientDeviceId, &devId) || devId.empty())
        return -12;

    axoAppInterface = new AppInterfaceImpl(name, auth, devId, receiveMessage, messageStateReport);
    Transport* sipTransport = new SipTransport(axoAppInterface);

    /* ***********************************************************************************
     * Initialize pointers/callback to the send/receive SIP data functions (network layer) 
     */
#ifdef UNITTESTS
    sipTransport->setSendDataFunction(sendDataFuncTesting);
#elif defined (EMBEDDED)
    // Functions defined in t_a_main module of silentphone library, this sends the data
    // via SIP message
    void g_sendDataFuncAxo(uint8_t* names[], uint8_t* devIds[], uint8_t* envelopes[], size_t sizes[], uint64_t msgIds[]);
    void t_setAxoTransport(Transport *transport);

    sipTransport->setSendDataFunction(g_sendDataFuncAxo);
    t_setAxoTransport(sipTransport);
#else
#error "***** Missing initialization."
#endif
    /* set sipTransport class to SIP network handler, sipTransport contains callback
     * functions 'receiveAxoData' and 'stateReportAxo'
     *********************************************************************************** */
    axoAppInterface->setTransport(sipTransport);
    axoAppInterface->setHttpHelper(httpHelper);

    const uint8_t* pw = (uint8_t*)env->GetByteArrayElements(dbPassphrase, 0);
    int pwLen = env->GetArrayLength(dbPassphrase);
    if (pw == NULL)
        return -14;
    if (pwLen != 32)
        return -15;

    std::string dbPw((const char*)pw, pwLen);
    env->ReleaseByteArrayElements(dbPassphrase, (jbyte*)pw, 0);

    // initialize and open the persitent store singleton instance
    SQLiteStoreConv* store = SQLiteStoreConv::getStore();
    store->setKey(dbPw);
    const char* db = (const char *)env->GetStringUTFChars(dbName, 0);
    store->openStore(std::string (db));
    env->ReleaseStringUTFChars(dbName, db);

    int32_t retVal = 1;
    AxoConversation* ownAxoConv = AxoConversation::loadLocalConversation(name);
    if (ownAxoConv == NULL) {  // no yet available, create one. An own conversation has the same local and remote name, empty device id
        Log("Axolotl - create identity for: '%s'", name.c_str());
        ownAxoConv = new AxoConversation(name, name, string());
        const DhKeyPair* idKeyPair = EcCurve::generateKeyPair(EcCurveTypes::Curve25519);
        ownAxoConv->setDHIs(idKeyPair);
        ownAxoConv->storeConversation();
        retVal = 2;
    }
    delete ownAxoConv;    // Not needed anymore here

    return retVal;
}

/*
 * Class:     AxolotlNative
 * Method:    sendMessage
 * Signature: ([B[B[B)[J
 */
JNIEXPORT jlongArray JNICALL 
JNI_FUNCTION(sendMessage)(JNIEnv* env, jclass clazz, jbyteArray messageDescriptor, jbyteArray attachementDescriptor, jbyteArray messageAttributes)
{
    if (messageDescriptor == NULL)
        return 0L;

    std::string message;
    if (!arrayToString(env, messageDescriptor, &message)) {
        return 0L;
    }
    Log("sendMessage - message: '%s' - length: %d", message.c_str(), message.size());

    std::string attachment;
    if (attachementDescriptor != NULL) {
        arrayToString(env, attachementDescriptor, &attachment);
        Log("sendMessage - attachement: '%s' - length: %d", attachment.c_str(), attachment.size());
    }
    std::string attributes;
    if (messageAttributes != NULL) {
        arrayToString(env, messageAttributes, &attributes);
        Log("sendMessage - attributes: '%s' - length: %d", attributes.c_str(), attributes.size());
    }
    std::vector<int64_t>* msgIds = axoAppInterface->sendMessage(message, attachment, attributes);
    if (msgIds == NULL || msgIds->empty()) {
        delete msgIds;
        return NULL;
    }
    int size = msgIds->size();

    jlongArray result = NULL;
    result = env->NewLongArray(size);
    jlong* resultArray = env->GetLongArrayElements(result, 0);

    for(int32_t i = 0; i < size; i++) {
        resultArray[i] = msgIds->at(i);
    }
    env->ReleaseLongArrayElements(result, resultArray, 0);
    delete msgIds;
    return result;
}

/*
 * Class:     AxolotlNative
 * Method:    getKnownUsers
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL 
JNI_FUNCTION(getKnownUsers)(JNIEnv* env, jclass clazz)
{
    std::string* jsonNames = axoAppInterface->getKnownUsers();
    if (jsonNames == NULL)
        return NULL;

    int32_t size = jsonNames->size();
    jbyteArray names = NULL;
    names = env->NewByteArray(size);
    if (names != NULL) {
        env->SetByteArrayRegion(names, 0, size, (jbyte*)jsonNames->data());
    }
    delete jsonNames;
    return names;
}

/*
 * Class:     AxolotlNative
 * Method:    registerAxolotlDevice
 * Signature: ([B[I)[B
 */
JNIEXPORT jbyteArray JNICALL 
JNI_FUNCTION(registerAxolotlDevice)(JNIEnv* env, jclass clazz, jintArray code)
{
    std::string info;
    if (code == NULL || env->GetArrayLength(code) < 1)
        return NULL;

    int32_t result = axoAppInterface->registerAxolotlDevice(&info);

    setReturnCode(env, code, result);

    jbyteArray infoBytes = NULL;
    if (!info.empty()) {
        int32_t size = info.size();
        infoBytes = env->NewByteArray(size);
        if (infoBytes != NULL) {
            env->SetByteArrayRegion(infoBytes, 0, size, (jbyte*)info.data());
        }
    }
    return infoBytes;
}
/*
 * Class:     axolotl_AxolotlNative
 * Method:    newPreKeys
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL 
JNI_FUNCTION(newPreKeys)(JNIEnv* env, jclass clazz, jint numbers)
{
    return axoAppInterface->newPreKeys(numbers);
}

/*
 * Class:     axolotl_AxolotlNative
 * Method:    getNumPreKeys
 * Signature: ()I
 */
JNIEXPORT jint JNICALL
JNI_FUNCTION(getNumPreKeys) (JNIEnv* env, jclass clazz)
{
    return axoAppInterface->getNumPreKeys();
}

/*
 * Class:     AxolotlNative
 * Method:    getErrorCode
 * Signature: ()I
 */
JNIEXPORT jint JNICALL
JNI_FUNCTION(getErrorCode)(JNIEnv* env, jclass clazz)
{
    return axoAppInterface->getErrorCode();
}

/*
 * Class:     AxolotlNative
 * Method:    getErrorInfo
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
JNI_FUNCTION(getErrorInfo)(JNIEnv* env, jclass clazz)
{
    const std::string info = axoAppInterface->getErrorInfo();
    jstring errInfo = env->NewStringUTF(info.c_str());
    return errInfo;
}

/*
 * Class:     AxolotlNative
 * Method:    testCommand
 * Signature: (Ljava/lang/String;[B)I
 */
JNIEXPORT jint JNICALL
JNI_FUNCTION(testCommand)(JNIEnv* env, jclass clazz, jstring command, jbyteArray data)
{
    int32_t result = 0;
    const char* cmd = (const char *)env->GetStringUTFChars(command, 0);

    std::string dataContainer;
    if (data != NULL) {
        int dataLen = env->GetArrayLength(data);
        if (dataLen > 0) {
            const uint8_t* tmp = (uint8_t*)env->GetByteArrayElements(data, 0);
            if (tmp != NULL) {
                dataContainer.assign((const char*)tmp, dataLen);
                env->ReleaseByteArrayElements(data, (jbyte*)tmp, 0);
            }
        }
    }
    Log("testCommand - command: '%s' - data: '%s'", cmd, dataContainer.c_str());

#ifdef UNITTESTS
    if (strcmp("http", cmd) == 0) {
        std::string resultData;
        result = httpHelper(std::string("/some/request"), dataContainer, std::string("MTH"), &resultData);
        Log("httpHelper - code: %d, resultData: %s", result, resultData.c_str());
    }

    if (strcmp("read", cmd) == 0) {
        reciveData(dataContainer);
    }
#endif
    if (strcmp("resetaxodb", cmd) == 0) {
        SQLiteStoreConv* store = SQLiteStoreConv::getStore();
        store->resetStore();
        Log("Resetted Axolotl store");
    }

    env->ReleaseStringUTFChars(command, cmd);
    return result;
}

/*
 * Class:     axolotl_AxolotlNative
 * Method:    axoCommand
 * Signature: (Ljava/lang/String;[B)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL JNI_FUNCTION(axoCommand)(JNIEnv* env, jclass clazz, jstring command, jbyteArray data)
{
    if (command == NULL)
        return NULL;
    const char* cmd = (const char *)env->GetStringUTFChars(command, 0);

    std::string dataContainer;
    arrayToString(env, data, &dataContainer);


    env->ReleaseStringUTFChars(command, cmd);
    return NULL;
}

/*
 * **************************************************************
 * Below the native functions for the repository database
 * *************************************************************
 */

static AppRepository* appRepository = NULL;

 /*
 * Class:     axolotl_AxolotlNative
 * Method:    repoOpenDatabase
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL
JNI_FUNCTION(repoOpenDatabase) (JNIEnv* env, jclass clazz, jstring dbName)
{
    std::string nameString;
    if (dbName != NULL) {
        const char* name = (const char *)env->GetStringUTFChars(dbName, 0);
        nameString = name;
        env->ReleaseStringUTFChars(dbName, name);
    }
    appRepository = AppRepository::getStore(nameString);
    if (appRepository == NULL)
        return -1;

    return appRepository->getSqlCode();
}

/*
 * Class:     axolotl_AxolotlNative
 * Method:    repoCloseDatabase
 * Signature: ()V
 */
JNIEXPORT void JNICALL
JNI_FUNCTION(repoCloseDatabase) (JNIEnv* env, jclass clazz) {
    if (appRepository != NULL)
        AppRepository::closeStore();
    appRepository = NULL;
}

/*
 * Class:     axolotl_AxolotlNative
 * Method:    repoIsOpen
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL
JNI_FUNCTION(repoIsOpen) (JNIEnv* env, jclass clazz)
{
    return appRepository != NULL;
}


/*
 * Class:     axolotl_AxolotlNative
 * Method:    existConversation
 * Signature: ([B)Z
 */
JNIEXPORT jboolean JNICALL
JNI_FUNCTION(existConversation) (JNIEnv* env, jclass clazz, jbyteArray namePattern)
{
    std::string name;
    if (!arrayToString(env, namePattern, &name) || name.empty())
        return false;

    bool result = appRepository->existConversation(name);
    return result;
}

/*
 * Class:     axolotl_AxolotlNative
 * Method:    storeConversation
 * Signature: ([B[B)I
 */
JNIEXPORT jint JNICALL
JNI_FUNCTION(storeConversation) (JNIEnv* env, jclass clazz, jbyteArray inName, jbyteArray convData)
{
    std::string name;
    if (!arrayToString(env, inName, &name) || name.empty())
        return -1;

    std::string data;
    arrayToString(env, convData, &data);
    return appRepository->storeConversation(name, data);
}

/*
 * Class:     axolotl_AxolotlNative
 * Method:    loadConversation
 * Signature: ([B[I)[B
 */
JNIEXPORT jbyteArray JNICALL
JNI_FUNCTION(loadConversation) (JNIEnv* env, jclass clazz, jbyteArray inName, jintArray code)
{
    if (code == NULL || env->GetArrayLength(code) < 1)
        return NULL;

    std::string name;
    if (!arrayToString(env, inName, &name) || name.empty()) {
        setReturnCode(env, code, -1);
        return NULL;
    }

    std::string data;
    int32_t result = appRepository->loadConversation(name, &data);
    if (SQL_FAIL(result)) {
        setReturnCode(env, code, result);
        return NULL;
    }

    setReturnCode(env, code, result);
    jbyteArray retData = stringToArray(env, data);
    return retData;
}

/*
 * Class:     axolotl_AxolotlNative
 * Method:    deleteConversation
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL 
JNI_FUNCTION(deleteConversation) (JNIEnv* env, jclass clazz, jbyteArray inName)
{
    std::string name;
    if (!arrayToString(env, inName, &name) || name.empty()) {
        return -1;
    }
    return appRepository->deleteConversation(name);
}

/*
 * Class:     axolotl_AxolotlNative
 * Method:    insertEvent
 * Signature: ([B[B[B)I
 */
JNIEXPORT jint JNICALL
JNI_FUNCTION(insertEvent) (JNIEnv* env, jclass clazz, jbyteArray inName, jbyteArray eventId, jbyteArray eventData)
{
    std::string name;
    if (!arrayToString(env, inName, &name) || name.empty()) {
        return -1;
    }
    std::string id;
    if (!arrayToString(env, eventId, &id) || id.empty()) {
        return -1;
    }
    std::string data;
    arrayToString(env, eventData, &data);
    return appRepository->insertEvent(name, id, data);
}

/*
 * Class:     axolotl_AxolotlNative
 * Method:    loadEvent
 * Signature: ([B[B[I)[B
 */
JNIEXPORT jbyteArray JNICALL
JNI_FUNCTION(loadEvent) (JNIEnv* env, jclass clazz, jbyteArray inName, jbyteArray eventId, jintArray code)
{
    if (code == NULL || env->GetArrayLength(code) < 2)
        return NULL;

    std::string name;
    if (!arrayToString(env, inName, &name) || name.empty()) {
        setReturnCode(env, code, -1);
        return NULL;
    }
    std::string id;
    if (!arrayToString(env, eventId, &id) || id.empty()) {
        setReturnCode(env, code, -1);
        return NULL;
    }
    int32_t msgNumber = 0;
    std::string data;
    int32_t result = appRepository->loadEvent(name, id, &data, &msgNumber);
    if (SQL_FAIL(result)) {
        setReturnCode(env, code, result);
        return NULL;
    }
    setReturnCode(env, code, result, msgNumber);
    jbyteArray retData = stringToArray(env, data);
    return retData;
}

/*
 * Class:     axolotl_AxolotlNative
 * Method:    existEvent
 * Signature: ([B[B)Z
 */
JNIEXPORT jboolean JNICALL
JNI_FUNCTION(existEvent) (JNIEnv* env, jclass clazz, jbyteArray inName, jbyteArray eventId)
{
    std::string name;
    if (!arrayToString(env, inName, &name) || name.empty()) {
        return false;
    }
    std::string id;
    if (!arrayToString(env, eventId, &id) || id.empty()) {
        return false;
    }
    bool result = appRepository->existEvent(name, id);
    return result;
}

/*
 * Class:     axolotl_AxolotlNative
 * Method:    loadEvents
 * Signature: ([BII[I)[[B
 */
JNIEXPORT jobjectArray JNICALL 
JNI_FUNCTION(loadEvents) (JNIEnv* env, jclass clazz, jbyteArray inName, jint offset, jint number, jintArray code)
{
    if (code == NULL || env->GetArrayLength(code) < 2)
        return NULL;

    std::string name;
    if (!arrayToString(env, inName, &name) || name.empty()) {
        setReturnCode(env, code, -1);
        return NULL;
    }

    int32_t msgNumber = 0;
    std::list<std::string*> events;
    int32_t result = appRepository->loadEvents(name, offset, number, &events, &msgNumber);

    if (SQL_FAIL(result)) {
        setReturnCode(env, code, result);
        while (!events.empty()) {
            std::string* s = events.front();
            events.pop_front();
            delete s;
        }
        return NULL;
    }
    jclass byteArrayClass = env->FindClass("[B");
    jobjectArray retArray = env->NewObjectArray(events.size(), byteArrayClass, NULL);  

    int32_t index = 0;
    while (!events.empty()) {
        std::string* s = events.front();
        events.pop_front();
        jbyteArray retData = stringToArray(env, *s);
        env->SetObjectArrayElement(retArray, index++, retData);
        delete s;
    }
    setReturnCode(env, code, result, msgNumber);
    return retArray;
}

/*
 * Class:     axolotl_AxolotlNative
 * Method:    deleteEvent
 * Signature: ([B[B)I
 */
JNIEXPORT jint JNICALL
JNI_FUNCTION(deleteEvent) (JNIEnv* env, jclass clazz, jbyteArray inName, jbyteArray eventId)
{
    std::string name;
    if (!arrayToString(env, inName, &name) || name.empty()) {
        return -1;
    }
    std::string id;
    if (!arrayToString(env, eventId, &id) || id.empty()) {
        return -1;
    }
    return appRepository->deleteEvent(name, id);
}


/*
 * Class:     axolotl_AxolotlNative
 * Method:    insertObject
 * Signature: ([B[B[B[B)I
 */
JNIEXPORT jint JNICALL
JNI_FUNCTION(insertObject) (JNIEnv* env, jclass clazz, jbyteArray inName, jbyteArray eventId, jbyteArray objId, jbyteArray objData)
{
    std::string name;
    if (!arrayToString(env, inName, &name) || name.empty()) {
        return -1;
    }
    std::string event;
    if (!arrayToString(env, eventId, &event) || event.empty()) {
        return -1;
    }
    std::string id;
    if (!arrayToString(env, objId, &id) || id.empty()) {
        return -1;
    }
    std::string data;
    arrayToString(env, objData, &data);
    return appRepository->insertObject(name, event, id, data);
}

/*
 * Class:     axolotl_AxolotlNative
 * Method:    loadObject
 * Signature: ([B[B[B[I)[B
 */
JNIEXPORT jbyteArray JNICALL
JNI_FUNCTION(loadObject) (JNIEnv* env, jclass clazz, jbyteArray inName, jbyteArray eventId, jbyteArray objId, jintArray code)
{
    if (code == NULL || env->GetArrayLength(code) < 1)
        return NULL;

    std::string name;
    if (!arrayToString(env, inName, &name) || name.empty()) {
        setReturnCode(env, code, -1);
        return NULL;
    }
    std::string event;
    if (!arrayToString(env, eventId, &event) || event.empty()) {
        setReturnCode(env, code, -1);
        return NULL;
    }
    std::string id;
    if (!arrayToString(env, objId, &id) || id.empty()) {
        return NULL;
    }
    std::string data;
    int32_t result = appRepository->loadObject(name, event, id, &data);
    if (SQL_FAIL(result)) {
        setReturnCode(env, code, result);
        return NULL;
    }
    setReturnCode(env, code, result);
    jbyteArray retData = stringToArray(env, data);
    return retData;
}

/*
 * Class:     axolotl_AxolotlNative
 * Method:    existObject
 * Signature: ([B[B[B)Z
 */
JNIEXPORT jboolean JNICALL
JNI_FUNCTION(existObject) (JNIEnv* env, jclass clazz, jbyteArray inName, jbyteArray eventId, jbyteArray objId)
{
    std::string name;
    if (!arrayToString(env, inName, &name) || name.empty()) {
        return false;
    }
    std::string event;
    if (!arrayToString(env, eventId, &event) || event.empty()) {
        return false;
    }
    std::string id;
    if (!arrayToString(env, objId, &id) || id.empty()) {
        return false;
    }
    return appRepository->existObject(name, event, id);
}

/*
 * Class:     axolotl_AxolotlNative
 * Method:    loadObjects
 * Signature: ([B[B[I)[[B
 */
JNIEXPORT jobjectArray JNICALL
JNI_FUNCTION(loadObjects) (JNIEnv* env, jclass clazz, jbyteArray inName, jbyteArray eventId, jintArray code)
{
    if (code == NULL || env->GetArrayLength(code) < 1)
        return NULL;

    std::string name;
    if (!arrayToString(env, inName, &name) || name.empty()) {
        setReturnCode(env, code, -1);
        return NULL;
    }
    std::string event;
    if (!arrayToString(env, eventId, &event) || event.empty()) {
        setReturnCode(env, code, -1);
        return NULL;
    }
    std::list<std::string*> objects;
    int32_t result = appRepository->loadObjects(name, event, &objects);

    if (SQL_FAIL(result)) {
        setReturnCode(env, code, result);
        while (!objects.empty()) {
            std::string* s = objects.front();
            objects.pop_front();
            delete s;
        }
        return NULL;
    }
    jclass byteArrayClass = env->FindClass("[B");
    jobjectArray retArray = env->NewObjectArray(objects.size(), byteArrayClass, NULL);  

    int32_t index = 0;
    while (!objects.empty()) {
        std::string* s = objects.front();
        objects.pop_front();
        jbyteArray retData = stringToArray(env, *s);
        env->SetObjectArrayElement(retArray, index++, retData);
        delete s;
    }
    setReturnCode(env, code, result);
    return retArray;
}

/*
 * Class:     axolotl_AxolotlNative
 * Method:    deleteObject
 * Signature: ([B[B[B)I
 */
JNIEXPORT jint JNICALL 
JNI_FUNCTION(deleteObject) (JNIEnv* env, jclass clazz, jbyteArray inName, jbyteArray eventId, jbyteArray objId)
{
    std::string name;
    if (!arrayToString(env, inName, &name) || name.empty()) {
        return -1;
    }
    std::string event;
    if (!arrayToString(env, eventId, &event) || event.empty()) {
        return -1;
    }
    std::string id;
    if (!arrayToString(env, objId, &id) || id.empty()) {
        return -1;
    }
    return appRepository->deleteObject(name, event, id);
}

