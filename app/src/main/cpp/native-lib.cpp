#include <jni.h>
#include <string>
#include <algorithm>
#include <iostream>
#include <android/log.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include <base/log.h>
#include "encode/base64.h"

#define TAG "yue_"
#define LOG_D(...) __android_log_print(ANDROID_LOG_DEBUG,TAG ,__VA_ARGS__)
#define LOG_E(...) __android_log_print(ANDROID_LOG_ERROR,TAG ,__VA_ARGS__)


static const char *PACKAGE_NAME = "com.jni.encrypt.test";
static const char *RELEASE_SIGN = "308202e4308201cc020101300d06092a864886f70d010105050030373116301406035504030c0d416e64726f69642044656275673110300e060355040a0c07416e64726f6964310b30090603550406130255533020170d3230303333313132353835325a180f32303530303332343132353835325a30373116301406035504030c0d416e64726f69642044656275673110300e060355040a0c07416e64726f6964310b300906035504061302555330820122300d06092a864886f70d01010105000382010f003082010a0282010100829a027cf7e1e42097fe3904423fc2ca7063b15764da55032192d237f1a9f636030dc94b91692f9387e164d86ebadf302142ccfa404d28dabf5822d0346080ebb88f965ba5f6d5021d397e9420365a8880f79e8fa0fb60c40b967d731429180dc4a0046dc611d16d956ebd6b7e7c8ad2603c7ff96c0856c24eb908af81c7759067dad905672be01a54da805b9652ce2e5fc909852efec5eefd2eaec6ad680f088cfd6ff14e412015aa24b3a19a6ddfc03f4ef52811f949bd187dd5787b3c1337fd28736e24fa9ba51853a072bbd8a4c901907ac0da14338e71a678137dfc7dabd7fc850505ff2497278797f4649a061184b40a944b7a1da92367e62cb3e08ddb0203010001300d06092a864886f70d01010505000382010100133a66505b18e02561795578244b223edff324bb6d0e9f40815290ff7d37bb8854a747a89d1c1d7944340f95fb530be86734d47c38db1b338783774875bc50b4426846dce0dceb47b5d33401ec21c2bd46cce3f627eecd6a093c164bf74456f183c459f5408a964a74472912f9f06d4637d3a10e97caf3a7a0872aaceb45f33b3e29e0d4f1c884eeb6828db80ff22b9311c5f9722fdf5a7c6b07eb0c911139992f35f93c99ed96a513665edf9c389ddd3342d8efa6d19f0b82dd7e96662f8861bd8360eb6c4d53ab82e9d92cd42bd77fd7eda14f5866a18fad103329a51cbdc2cf8224ddf852ba51f94e0efa924452c068af1fd231b183249c8212f1e82a4ff8";

static const unsigned char password[] = "ynadcc@p$abw0rdcdbttye$38949!@$@";
static const int pwdBitsLength = 256;
static const unsigned char iv[] = "=o&g%m,*o?dL~def";
static bool initSuccess = false;

/**
 * 加密之前进行填充
 * @param buf 输入数据
 * @param size 输入数据长度
 * @param final_size 填充后的数据长度
 * @return 填充后的数据
 */
unsigned char *padding_buf(const char *buf, size_t size, size_t *final_size) {
    unsigned char *ret = NULL;
    size_t padding_size = AES_BLOCK_SIZE - (size % AES_BLOCK_SIZE);
    size_t i;
    *final_size = size + padding_size;
    ret = (unsigned char *) malloc(*final_size + 1);
    memcpy(ret, buf, size);
    const unsigned char paddingChar = (unsigned char) padding_size;
    for (i = size; i < *final_size; i++) {
        // zero padding算法：
        // ret[i] = 0;
        // or PKCS7Padding算法
        ret[i] = paddingChar;
    }
    ret[*final_size] = '\0';
    return ret;
}

unsigned char *getIv() {
    size_t len = strlen((char *) iv);
    unsigned char *ivCopy = (unsigned char *) malloc(len);
    memcpy(ivCopy, iv, len);
    return ivCopy;
}

AES_KEY *getAesKey() {
    AES_KEY *aes_key = (AES_KEY *) malloc(sizeof(AES_KEY));
    AES_set_encrypt_key(password, pwdBitsLength, aes_key);
    return aes_key;
}

jstring encrypt(JNIEnv *env, jobject instance, jstring plainText) {
    bool newLine = false;
    const char *inChars = (env->GetStringUTFChars(plainText, JNI_FALSE));
    const size_t originalLength = strlen(inChars);
    size_t paddedLength = 0;
    unsigned char *in = padding_buf(inChars, originalLength, &paddedLength);
    env->ReleaseStringUTFChars(plainText, inChars);
    auto *encryptOut = (unsigned char *) malloc((paddedLength) * sizeof(unsigned char));
    int num = 0;
    unsigned char *ivec = getIv();
    AES_KEY *aes_key = getAesKey();
    AES_cfb128_encrypt(in, encryptOut, paddedLength, aes_key, ivec, &num, AES_ENCRYPT);
    free(in);
    free(ivec);
    free(aes_key);
    /*
     * //十六进制字符串转换
     * char *result = (char *) malloc((paddedLength * 2 + 1) * sizeof(char));
    convert_hex(out, paddedLength, result);
     */
    auto *base64OutBuf = static_cast<unsigned char *>(malloc(
            sizeof(unsigned char) * calcBase64EncodeBufLen(paddedLength, newLine)));
    encodeB64(encryptOut, base64OutBuf, paddedLength, newLine);
    free(encryptOut);
    jstring tmp = env->NewStringUTF(reinterpret_cast<const char *>(base64OutBuf));
    free(base64OutBuf);
    return tmp;
}


static JNINativeMethod gMethods[] = {{"encrypt", "(Ljava/lang/String;)Ljava/lang/String;", (void *) encrypt}};

int JNI_OnLoad(JavaVM *vm, void *re) {
    JNIEnv *env;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass javaClass = env->FindClass("com/example/aes/TestJNI");
    if (javaClass == NULL) {
        return JNI_ERR;
    }
    if (env->RegisterNatives(javaClass, gMethods, sizeof(gMethods) / sizeof(gMethods[0])) < 0) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_aes_TestJNI_log(JNIEnv *env, jclass clazz) {
    LOG_E("my name is %s", "yue");
}


extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_aes_TestJNI_decrypt(JNIEnv *env, jobject instance, jstring cipher_text) {


}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_aes_TestJNI_getKeyValue(JNIEnv *env, jobject instance) {

}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_aes_TestJNI_getIv(JNIEnv *env, jobject instance) {

}

