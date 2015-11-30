/*
**
** Copyright 2008, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define LOG_TAG "mediaserver"
//#define LOG_NDEBUG 0

#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>
#include <cutils/properties.h>
#include <utils/Log.h>
#include "RegisterExtensions.h"

// from LOCAL_C_INCLUDES
#include "AudioFlinger.h"
#include "CameraService.h"
#include "MediaLogService.h"
#include "MediaPlayerService.h"
#include "AudioPolicyService.h"
#include "SoundTriggerHwService.h"

#include <android/log.h>
#include <Drm.h>
#include <Crypto.h>
#include <drm/DrmAPI.h> // only for DrmPlugin::KeyType
#include <algorithm>
#include <iterator>
#include <iostream>
#include <sstream>
typedef uint8_t byte;
#define LOG(format, args...) __android_log_print(ANDROID_LOG_INFO, "TestDrmServer", format, ## args); \
                     printf("[TestDrmServer]" format "\n", ##args)
using namespace android;
const uint8_t mock_uuid[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
const uint8_t invalid_uuid[16] = {0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
//const uint8_t wideVine_uuid[16] = {};

namespace util
{
  template<class Vec1, class Vec2>
  bool equal(const Vec1& vec1, const Vec2& vec2)
  {
    if (vec1.size() != vec2.size())
    {
      return false;
    }
    for (size_t i = 0; i < vec1.size(); i++)
    {
      if (vec1[i] != vec2[i])
      {
        return false;
      }
    }
    return true;
  }

  template<class T, size_t N>
  void fill(Vector<T>& vec, const T (&vecValue)[N])
  {
    vec.clear();
    for (size_t i = 0; i < N; i++)
    {
      vec.push_back(vecValue[i]);
    }

  }

  template<class T>
  void printVec(const Vector<T>& vec)
  {
    using namespace std;
    ostringstream ss;
    for (size_t i = 0; i < vec.size(); i++)
    {
      ss<<vec[i];
    }
    ss<<endl;
    LOG("printVec = %s", ss.str().c_str());
  }

  template<>
  void printVec(const Vector<byte>& vec)
  {
    using namespace std;
    ostringstream ss;
    for (size_t i = 0; i < vec.size(); i++)
    {
      ss<<hex<<static_cast<uint>(vec[i]);
    }
    ss<<endl;
    LOG("printVec = %s", ss.str().c_str());
  }

  template<class T, size_t N>
  Vector<T> make_vec(const T (&vecValue)[N])
  {
    Vector<T> vec;
    fill(vec, vecValue);
    return vec;
  }
} //util
class TestDrm
{
public:
  TestDrm()
  : mDrmInstance(new Drm), mCryptoInstance(new Crypto)
  {
    status_t result = OK;
    if (mDrmInstance != NULL)
    {
      LOG("==============drm ok==============");
      // Create Plugin
      result = mDrmInstance->createPlugin(mock_uuid);
      LOG("createPlugin = %d\n", result);
    }
    if (mCryptoInstance != NULL)
    {
      LOG("==============crypto ok==============");
    }
  }
  void testIsCryptoSchemeSupported()
  {
    LOG("=============%s=============\n", __func__);
    bool result = false;
    // with valid mimetype
    String8 mimeType("video/mp4");
    result = mDrmInstance->isCryptoSchemeSupported(mock_uuid, mimeType);
    LOG("testIsCryptoSchemeSupported valid mimetype bool = %d\n",result);
    // with invalid uuid
    result = mDrmInstance->isCryptoSchemeSupported(invalid_uuid, mimeType);
    LOG("testIsCryptoSchemeSupported invalid_uuid bool = %d\n", result);
    // with invalid mimetype
    String8 mimeType2("video/foo");
    result = mDrmInstance->isCryptoSchemeSupported(mock_uuid, mimeType2);
    LOG("testIsCryptoSchemeSupported invalid mimetype bool = %d\n", result);
  }

  void testStringProperties()
  {
    LOG("=============%s=============\n", __func__);
    status_t result = OK;
    result = mDrmInstance->setPropertyString(String8("test-string"), String8("test-value"));
    LOG("setPropertyString = %d\n", result);
    String8 value;
    result = mDrmInstance->getPropertyString(String8("test-string"), value);
    LOG("getPropertyString = %d\n", result);

    LOG("testStringProperties check = %s\n", value.string());
    // test if not exit string.
    result = mDrmInstance->getPropertyString(String8("foo"), value);
    LOG("getPropertyString not exist = %d\n", result);
  }

  void testByteArrayProperties()
  {
    LOG("=============%s=============\n", __func__);
    status_t result = OK;
    byte testArray[] = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x10, 0x11, 0x12};
    Vector<byte> arrayPropertiesValue = util::make_vec(testArray);

    result = mDrmInstance->setPropertyByteArray(String8("test-array"), arrayPropertiesValue);
    LOG("setPropertyByteArray = %d\n", result);

    Vector<uint8_t> arrayGetPropertiesValue;
    result = mDrmInstance->getPropertyByteArray(String8("test-array"), arrayGetPropertiesValue);
    LOG("getPropertyByteArray = %d\n", result);

    LOG("testByteArrayProperties equal = %d\n", util::equal(arrayGetPropertiesValue, arrayPropertiesValue));
    // test if not exit property.
    result = mDrmInstance->getPropertyByteArray(String8("foo"), arrayGetPropertiesValue);
    LOG("getPropertyByteArray not exist = %d\n", result);
  }

  void testOpenCloseSession()
  {
    LOG("=============%s=============\n", __func__);
    status_t result = OK;
    Vector<uint8_t> sessionId;
    result = mDrmInstance->openSession(sessionId);
    util::printVec(sessionId);
    LOG("openSession = %d\n", result);
    result = mDrmInstance->closeSession(sessionId);
    LOG("closeSession = %d\n", result);

    // test close bad session id.
    uint8_t badId[] = {0x05, 0x6, 0x7, 0x8};
    Vector<uint8_t> badSessionId = util::make_vec(badId);
    result = mDrmInstance->closeSession(badSessionId);
    LOG("closeSession bad id = %d\n", result);
  }

  void testGetKeyRequest()
  {
    LOG("=============%s=============\n", __func__);
    Vector<byte> sessionId;
    status_t result = mDrmInstance->openSession(sessionId);

    // Set up mock expected responses using properties
    byte testRequest[] = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x10, 0x11, 0x12};
    Vector<byte> testRequestVec = util::make_vec(testRequest);
    mDrmInstance->setPropertyByteArray(String8("mock-request"), testRequestVec);
    String8 testDefaultUrl("http://1.2.3.4:8080/blah");
    mDrmInstance->setPropertyString(String8("mock-defaultUrl"), testDefaultUrl);


    byte initData[] = {0x0a, 0x0b, 0x0c, 0x0d};
    Vector<byte> initDataVec = util::make_vec(initData);
    KeyedVector<String8, String8> optionalParameters;
    optionalParameters.add(String8("param1"), String8("value1"));
    optionalParameters.add(String8("param2"), String8("value2"));

    String8 mimeType("video/iso.segment");

    Vector<byte> requestResult;
    String8 defaultUrlResult;
    result = mDrmInstance->getKeyRequest(sessionId,
                                         initDataVec,
                                         mimeType,
                                         DrmPlugin::kKeyType_Streaming,
                                         optionalParameters,
                                         requestResult,
                                         defaultUrlResult);
    //[TODO] why design this pattern logic? maybe need to change for widevine.
    LOG("requestResult == testRequest(%d)\n", util::equal(requestResult, testRequestVec));
    LOG("defaultUrlResult == testDefaultUrl(%d)\n", (defaultUrlResult == testDefaultUrl));

    Vector<byte> initdataGetPropertiesValue;
    result = mDrmInstance->getPropertyByteArray(String8("mock-initdata"), initdataGetPropertiesValue);
    LOG("initDataVec == initdataGetPropertiesValue(%d)\n", util::equal(initDataVec, initdataGetPropertiesValue));

    String8 mimeTypeResult;
    result = mDrmInstance->getPropertyString(String8("mock-mimetype"), mimeTypeResult);
    LOG("mimeTypeResult == mimeType(%d)\n", (mimeTypeResult == mimeType));

    String8 keyTypeResult;
    result = mDrmInstance->getPropertyString(String8("mock-keytype"), keyTypeResult);
    LOG("keyTypeResult == 1(%d)\n", (keyTypeResult == "1"));

    String8 optparamsResult;
    result = mDrmInstance->getPropertyString(String8("mock-optparams"), optparamsResult);
    LOG("optparamsResult == {param1,value1},{param2,value2}(%d)\n", (optparamsResult == "{param1,value1},{param2,value2}"));

    mDrmInstance->closeSession(sessionId);

    //[TODO] port testGetKeyRequestOffline, testGetKeyRequestNoOptionalParameters, testGetKeyRequestRelease
    // Not sure if we can invoke getKeyRequest multiple times.
  }

  void testProvideKeyResponse()
  {
    LOG("=============%s=============\n", __func__);
    Vector<byte> sessionId;
    status_t result = mDrmInstance->openSession(sessionId);
    // Set up mock expected responses using properties
    byte testResponse[] = {0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    Vector<byte> testResponseVec = util::make_vec(testResponse);
    Vector<byte> keySetId;
    // [TODO] what is keySetId???
    result = mDrmInstance->provideKeyResponse(sessionId, testResponseVec, keySetId);

    Vector<byte> testResponseResult;

    result = mDrmInstance->getPropertyByteArray(String8("mock-response"), testResponseResult);
    // testResponseResult.editItemAt(0) = 25;
    LOG("testResponseVec == testResponseResult(%d)", util::equal(testResponseVec, testResponseResult));
    mDrmInstance->closeSession(sessionId);
  }

  void testRemoveKeys()
  {
    LOG("=============%s=============\n", __func__);
    Vector<byte> sessionId;
    status_t result = mDrmInstance->openSession(sessionId);

    byte testResponse[] = {0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    Vector<byte> testResponseVec = util::make_vec(testResponse);
    Vector<byte> keySetId;
    // [TODO] what is keySetId???
    result = mDrmInstance->provideKeyResponse(sessionId, testResponseVec, keySetId);

    result = mDrmInstance->closeSession(sessionId);
    result = mDrmInstance->removeKeys(keySetId);
    LOG("testRemoveKeys = %d\n", result);
  }

  void testRestoreKeys()
  {
    LOG("=============%s=============\n", __func__);
    Vector<byte> sessionId;
    status_t result = mDrmInstance->openSession(sessionId);

    byte testResponse[] = {0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    Vector<byte> testResponseVec = util::make_vec(testResponse);
    Vector<byte> keySetId;
    // [TODO] what is keySetId???
    result = mDrmInstance->provideKeyResponse(sessionId, testResponseVec, keySetId);

    result = mDrmInstance->closeSession(sessionId);

    result = mDrmInstance->openSession(sessionId);
    result = mDrmInstance->restoreKeys(sessionId, keySetId);
    LOG("testRestoreKeys = %d\n", result);
    result = mDrmInstance->closeSession(sessionId);
  }

  void testQueryKeyStatus()
  {
    LOG("=============%s=============\n", __func__);
    Vector<byte> sessionId;
    status_t result = mDrmInstance->openSession(sessionId);

    KeyedVector<String8, String8> infoMap;
    mDrmInstance->queryKeyStatus(sessionId, infoMap);

    // these are canned strings returned by the mock
    LOG("QueryKeyStatus has key purchaseDuration(%d)\n", infoMap.indexOfKey(String8("purchaseDuration")) >= 0);
    LOG("QueryKeyStatus has value purchaseDuration(%d)\n", infoMap.valueFor(String8("purchaseDuration")) == "1000");
    LOG("QueryKeyStatus has key licenseDuration(%d)\n", infoMap.indexOfKey(String8("licenseDuration")) >= 0);
    LOG("QueryKeyStatus has value licenseDuration(%d)\n", infoMap.valueFor(String8("licenseDuration")) == "100");

    mDrmInstance->closeSession(sessionId);
  }

  void testGetProvisionRequest()
  {
    LOG("=============%s=============\n", __func__);
    status_t result = OK;
    // Set up mock expected responses using properties
    byte testRequest[] = {0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x60, 0x61, 0x62};
    Vector<byte> testRequestValue = util::make_vec(testRequest);
    mDrmInstance->setPropertyByteArray(String8("mock-request"), testRequestValue);
    String8 testDefaultUrl("http://1.2.3.4:8080/bar");
    mDrmInstance->setPropertyString(String8("mock-defaultUrl"), testDefaultUrl);

    // [TODO] String8 const &certType, String8 const &certAuthority did not know how to use it.
    // Pass empty string for mock.
    // http://developer.android.com/intl/zh-tw/reference/android/media/MediaDrm.html#getProvisionRequest()
    Vector<byte> requestData;
    String8 defaultUrl;
    result = mDrmInstance->getProvisionRequest(String8(""), String8(""), requestData, defaultUrl);
    util::printVec(requestData);
    LOG("testGetProvisionRequest getProvisionRequest = %d\n", result);
    LOG("testGetProvisionRequest defaultUrl = %s\n", defaultUrl.string());

  }

  void testProvideProvisionResponse()
  {
    LOG("=============%s=============\n", __func__);
    // Set up mock expected responses using properties
    byte testResponse[] = {0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    Vector<byte> testResponseVec = util::make_vec(testResponse);
    Vector<byte> certificate;
    Vector<byte> wrappedKey;
    // [TODO]: do not know how to passs 2nd, 3rd arguments.
    // http://developer.android.com/intl/zh-tw/reference/android/media/MediaDrm.html#provideProvisionResponse(byte[])
    mDrmInstance->provideProvisionResponse(testResponseVec, certificate, wrappedKey);
    // [TODO] Thos string like "mock-response", how to deal with WideVine?
    Vector<byte> provisionResponseArray;
    mDrmInstance->getPropertyByteArray(String8("mock-response"), provisionResponseArray);
    LOG("testProvideProvisionResponse provisionResponseArray equal = %d\n",
      util::equal(provisionResponseArray, testResponseVec));
  }

  void testGetSecureStops()
  {
    LOG("=============%s=============\n", __func__);
    // Set up mock expected responses using properties
    byte ss1[] = {0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    byte ss2[] = {0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30};
    Vector<byte> ss1Vec = util::make_vec(ss1);
    Vector<byte> ss2Vec = util::make_vec(ss2);

    // [TODO] what is these two magic string in WV?
    mDrmInstance->setPropertyByteArray(String8("mock-secure-stop1"), ss1Vec);
    mDrmInstance->setPropertyByteArray(String8("mock-secure-stop2"), ss2Vec);

    List< Vector<byte> > secureStopList;
    mDrmInstance->getSecureStops(secureStopList);
    List< Vector<byte> >::iterator itr = secureStopList.begin();
    LOG("testGetSecureStops 1 equal = %d\n",
      util::equal(ss1Vec, *itr));
    itr++;
    LOG("testGetSecureStops 2 equal = %d\n",
      util::equal(ss2Vec, *itr));
  }

  void testReleaseSecureStops()
  {
    LOG("=============%s=============\n", __func__);
    // Set up mock expected responses using properties
    // [TODO] what is these magic vector in WV?
    byte ssrelease[] = {0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40};
    Vector<byte> ssreleaseVec = util::make_vec(ssrelease);
    status_t result = mDrmInstance->releaseSecureStops(ssreleaseVec);
    LOG("testReleaseSecureStopsreleaseSecureStops = %d\n",result);
  }

  void testMultipleSessions()
  {
    LOG("=============%s=============\n", __func__);
    Vector<byte> sessionId1;
    mDrmInstance->openSession(sessionId1);
    Vector<byte> sessionId2;
    mDrmInstance->openSession(sessionId2);
    Vector<byte> sessionId3;
    mDrmInstance->openSession(sessionId3);

    LOG("testMultipleSessions should not be equal = %d\n", util::equal(sessionId1, sessionId2));
    LOG("testMultipleSessions should not be equal = %d\n", util::equal(sessionId2, sessionId3));

    mDrmInstance->closeSession(sessionId1);
    mDrmInstance->closeSession(sessionId2);
    mDrmInstance->closeSession(sessionId3);
  }

  // [TODO] getCryptoSession seems c++ API should use it directly via mDrmInstance.
  void testCryptoSessionEncrypt()
  {
    LOG("=============%s=============\n", __func__);
    // status_t encrypt(Vector<uint8_t> const &sessionId,
    //               Vector<uint8_t> const &keyId,
    //               Vector<uint8_t> const &input,
    //               Vector<uint8_t> const &iv,
    //               Vector<uint8_t> &output) {
    Vector<byte> sessionId1;
    mDrmInstance->openSession(sessionId1);

    // [TODO] what is the corresponding value for WV?
    byte keyId[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    Vector<byte> keyIdVec = util::make_vec(keyId);
    byte input[] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};
    Vector<byte> inputVec = util::make_vec(input);
    byte iv[]= {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29};
    Vector<byte> ivVec = util::make_vec(iv);
    byte expectedOutput[] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    Vector<byte> expectedOutputVec = util::make_vec(expectedOutput);

    Vector<byte> output;
    mDrmInstance->setPropertyByteArray(String8("mock-output"), expectedOutputVec);

    mDrmInstance->encrypt(sessionId1, keyIdVec, inputVec, ivVec, output);

    // [TODO] mock only test, skip.
    // assertTrue(Arrays.equals(keyId, md.getPropertyByteArray("mock-keyid")));
    // assertTrue(Arrays.equals(input, md.getPropertyByteArray("mock-input")));
    // assertTrue(Arrays.equals(iv, md.getPropertyByteArray("mock-iv")));


    LOG("testCryptoSessionEncrypt expected output equal = %d\n",
      util::equal(expectedOutputVec, output));

    mDrmInstance->closeSession(sessionId1);
  }

  void testCryptoSessionDecrypt()
  {
    LOG("=============%s=============\n", __func__);
    // status_t decrypt(Vector<uint8_t> const &sessionId,
    //                             Vector<uint8_t> const &keyId,
    //                             Vector<uint8_t> const &input,
    //                             Vector<uint8_t> const &iv,
    //                             Vector<uint8_t> &output)
    Vector<byte> sessionId1;
    mDrmInstance->openSession(sessionId1);

    byte keyId[] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49};
    Vector<byte> keyIdVec = util::make_vec(keyId);
    byte input[] = {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59};
    Vector<byte> inputVec = util::make_vec(input);
    byte iv[] = {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69};
    Vector<byte> ivVec = util::make_vec(iv);
    byte expectedOutput[] = {0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79};
    Vector<byte> expectedOutputVec = util::make_vec(expectedOutput);
    Vector<byte> output;
    mDrmInstance->setPropertyByteArray(String8("mock-output"), expectedOutputVec);

    mDrmInstance->decrypt(sessionId1, keyIdVec, inputVec, ivVec, output);

    // [TODO] mock only test, skip.
    // assertTrue(Arrays.equals(keyId, md.getPropertyByteArray("mock-keyid")));
    // assertTrue(Arrays.equals(input, md.getPropertyByteArray("mock-input")));
    // assertTrue(Arrays.equals(iv, md.getPropertyByteArray("mock-iv")));
    LOG("testCryptoSessionDecrypt expected output equal = %d\n",
      util::equal(expectedOutputVec, output));

    mDrmInstance->closeSession(sessionId1);
  }

  void testCryptoSessionSign()
  {
    LOG("=============%s=============\n", __func__);
    // status_t sign(Vector<uint8_t> const &sessionId,
    //                          Vector<uint8_t> const &keyId,
    //                          Vector<uint8_t> const &message,
    //                          Vector<uint8_t> &signature)
    Vector<byte> sessionId1;
    mDrmInstance->openSession(sessionId1);

    byte keyId[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    Vector<byte> keyIdVec = util::make_vec(keyId);
    byte message[] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29};
    Vector<byte> messageVec = util::make_vec(message);
    byte expected_signature[] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    Vector<byte> expectedSignatureVec = util::make_vec(expected_signature);
    Vector<byte> outputSignature;
    mDrmInstance->setPropertyByteArray(String8("mock-signature"), expectedSignatureVec);

    mDrmInstance->sign(sessionId1, keyIdVec, messageVec, outputSignature);

    // assertTrue(Arrays.equals(keyId, md.getPropertyByteArray("mock-keyid")));
    // assertTrue(Arrays.equals(message, md.getPropertyByteArray("mock-message")));
    LOG("testCryptoSessionSign expected output signature equal = %d\n",
      util::equal(expectedSignatureVec, outputSignature));

    mDrmInstance->closeSession(sessionId1);
  }

  void testCryptoSessionVerify()
  {
    LOG("=============%s=============\n", __func__);
    // status_t verify(Vector<uint8_t> const &sessionId,
    //                            Vector<uint8_t> const &keyId,
    //                            Vector<uint8_t> const &message,
    //                            Vector<uint8_t> const &signature,
    //                            bool &match)
    Vector<byte> sessionId1;
    mDrmInstance->openSession(sessionId1);

    byte keyId[] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49};
    Vector<byte> keyIdVec = util::make_vec(keyId);
    byte message[] = {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59};
    Vector<byte> messageVec = util::make_vec(message);
    byte signature[] = {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69};
    Vector<byte> signatureVec = util::make_vec(signature);

    // [TODO] what is the test case for WV?
    mDrmInstance->setPropertyString(String8("mock-match"), String8("1"));
    bool isMatch = false;
    mDrmInstance->verify(sessionId1, keyIdVec, messageVec, signatureVec, isMatch);
    LOG("testCryptoSessionVerify should match = %d\n", isMatch);

    // assertTrue(Arrays.equals(keyId, md.getPropertyByteArray("mock-keyid")));
    // assertTrue(Arrays.equals(message, md.getPropertyByteArray("mock-message")));
    // assertTrue(Arrays.equals(signature, md.getPropertyByteArray("mock-signature")));

    mDrmInstance->setPropertyString(String8("mock-match"), String8("0"));
    mDrmInstance->verify(sessionId1, keyIdVec, messageVec, signatureVec, isMatch);
    LOG("testCryptoSessionVerify should not match = %d\n", isMatch);

    mDrmInstance->closeSession(sessionId1);
  }

  // testEventNoSessionNoData and testEventWithSessionAndData seems no need to test.
private:
  sp<IDrm> mDrmInstance;
  sp<ICrypto> mCryptoInstance;
};
int main()
{
    LOG("==============TestServer==============\n");
    TestDrm testDrm;
    testDrm.testIsCryptoSchemeSupported();
    testDrm.testStringProperties();
    testDrm.testByteArrayProperties();
    testDrm.testOpenCloseSession();
    testDrm.testGetKeyRequest();
    testDrm.testProvideKeyResponse();
    testDrm.testRemoveKeys();
    testDrm.testRestoreKeys();
    testDrm.testQueryKeyStatus();
    testDrm.testGetProvisionRequest();
    testDrm.testProvideProvisionResponse();
    testDrm.testGetSecureStops();
    testDrm.testReleaseSecureStops();
    testDrm.testMultipleSessions();
    testDrm.testCryptoSessionEncrypt();
    testDrm.testCryptoSessionDecrypt();
    testDrm.testCryptoSessionSign();
    testDrm.testCryptoSessionVerify();
    return 0;
}
