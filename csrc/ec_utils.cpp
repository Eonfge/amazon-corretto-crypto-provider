// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <vector>
#include "generated-headers.h"
#include "util.h"
#include "env.h"
#include "bn.h"
#include "auto_free.h"

using namespace AmazonCorrettoCryptoProvider;

/*
 * Class:     com_amazon_corretto_crypto_provider_EcUtils
 * Method:    buildCurve
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_buildGroup
  (JNIEnv *pEnv, jclass, jint nid)
{
    EC_GROUP* group;
    try {
        raii_env env(pEnv);

        if (unlikely(!(group = EC_GROUP_new_by_curve_name(nid)))) {
            throw_openssl("Unable to get group");
        }

        return (jlong) group;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EcUtils
 * Method:    freeCurve
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_freeGroup
  (JNIEnv *, jclass, jlong group)
{
    EC_GROUP_free((EC_GROUP*) group);
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EcUtils
 * Method:    curveNameToInfo
 * Signature: (Ljava/lang/String;[B[B[B[B[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_curveNameToInfo(
  JNIEnv *pEnv,
  jclass,
  jstring curveName,
  jintArray mArr,
  jbyteArray pArr,
  jbyteArray aArr,
  jbyteArray bArr,
  jbyteArray cofactorArr,
  jbyteArray gxArr,
  jbyteArray gyArr,
  jbyteArray orderArr,
  jbyteArray encoded)
{
    try {
        raii_env env(pEnv);

        if (!curveName) {
            throw_java_ex(EX_NPE, "Curve name must not be null");
        }
        jni_string jniCurve(env, curveName);

        int nid = OBJ_txt2nid(jniCurve.native_str);
        if (nid == NID_undef) {
            ERR_clear_error();
            return 0;
        }

        EC_GROUP_auto group = EC_GROUP_auto::from(EC_GROUP_new_by_curve_name(nid));
        if (unlikely(!group.isInitialized())) {
            unsigned long errCode = drainOpensslErrors();
            if (ERR_GET_LIB(errCode) == ERR_LIB_EC && ERR_GET_REASON(errCode) == EC_R_UNKNOWN_GROUP) {
                throw_java_ex(EX_ILLEGAL_ARGUMENT, "Unknown curve");
            } else {
                throw_java_ex(EX_RUNTIME_CRYPTO,
                    formatOpensslError(errCode, "Unable to create group"));
            }
        }

        BigNumObj pBN;
        BigNumObj aBN;
        BigNumObj bBN;
        BigNumObj cfBN;
        BigNumObj gxBN;
        BigNumObj gyBN;
        BigNumObj orderBN;

        const EC_POINT* generator = NULL;
        const EC_METHOD * method = NULL;
        int fieldNid = 0;
        int m = 0;

        // Figure out which type of group this is
        method = EC_GROUP_method_of(group);
        if (!method) {
            throw_openssl("Unable to acquire method");
        }
        fieldNid = EC_METHOD_get_field_type(method);

        if (EC_GROUP_get_cofactor(group, cfBN, NULL) != 1) {
            throw_openssl("Unable to get cofactor");
        }
        cfBN.toJavaArray(env, cofactorArr);

        generator = EC_GROUP_get0_generator(group);
        if (!generator) {
            throw_openssl("Unable to get generator");
        }

        switch (fieldNid) {
            case NID_X9_62_prime_field:
                if (EC_GROUP_get_curve_GFp(group, pBN, aBN, bBN, NULL) != 1) {
                    throw_openssl("Unable to get group information");
                }
                if (EC_POINT_get_affine_coordinates_GFp(group, generator, gxBN, gyBN, NULL) != 1) {
                    throw_openssl("Unable to get generator coordinates");
                }
                break;
            case NID_X9_62_characteristic_two_field:
                if (EC_GROUP_get_curve_GFp(group, pBN, aBN, bBN, NULL) != 1) {
                    throw_openssl("Unable to get group information");
                }
                if (EC_POINT_get_affine_coordinates_GFp(group, generator, gxBN, gyBN, NULL) != 1) {
                    throw_openssl("Unable to get generator coordinates");
                }
                m = EC_GROUP_get_degree(group);
                env->SetIntArrayRegion(mArr, 0, 1, &m);
                env.rethrow_java_exception();
                break;
        }

        gxBN.toJavaArray(env, gxArr);
        gyBN.toJavaArray(env, gyArr);

        pBN.toJavaArray(env, pArr);
        aBN.toJavaArray(env, aArr);
        bBN.toJavaArray(env, bArr);


        if (EC_GROUP_get_order(group, orderBN, NULL) != 1) {
            throw_openssl("Unable to get group order");
        }
        orderBN.toJavaArray(env, orderArr);

        // TODO [childw]
        jni_borrow borrow = jni_borrow(env, java_buffer::from_array(env, encoded), /*trace*/nullptr);
        CBB cbb;
        CBB_init_fixed(&cbb, borrow.data(), borrow.len());
        if (!EC_KEY_marshal_curve_name(&cbb, group)) {
            throw_openssl("Unable to encode curve OID");
        }

        return nid;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EcUtils
 * Method:    getCurveNames
 * Signature: TODO [childw]
 */
JNIEXPORT jobjectArray JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_getCurveNames(
  JNIEnv *pEnv,
  jclass)
{
    try {
        raii_env env(pEnv);

        std::vector<EC_builtin_curve> curves;
        size_t numCurves = EC_get_builtin_curves(curves.data(), 0); // get curve count
        curves.resize(numCurves);
        numCurves = EC_get_builtin_curves(curves.data(), curves.size());
        if (numCurves > curves.size()) {
            throw_openssl("Too many curves");
        }

        jobjectArray names = env->NewObjectArray(numCurves, env->FindClass("java/lang/String"), nullptr);
        for (int i = 0; i < numCurves; i++) {
            int nid = curves[i].nid;
            env->SetObjectArrayElement(names, i, env->NewStringUTF(EC_curve_nid2nist(nid)));
        }

        return names;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return nullptr;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EcUtils
 * Method:    decodeCurve
 * Signature: TODO [childw]
 */
JNIEXPORT jstring JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_getCurveNameFromEncoded(
  JNIEnv *pEnv,
  jclass,
  jbyteArray encoded
  )
{
    try {
        raii_env env(pEnv);

        jni_borrow borrow = jni_borrow(env, java_buffer::from_array(env, encoded), /*trace*/nullptr);
        CBS cbs;
        CBS_init(&cbs, borrow.data(), borrow.len());
        EC_GROUP *group = EC_KEY_parse_curve_name(&cbs);
        if (group == nullptr) {
            throw_openssl("Unable to decode curve OID");
        }

        int nid = EC_GROUP_get_curve_name(group);
        return env->NewStringUTF(EC_curve_nid2nist(nid));
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return nullptr;
    }
}

/*

// EC_curve_nid2nist returns the NIST name of the elliptic curve specified by
// |nid|, or NULL if |nid| is not a NIST curve. For example, it returns "P-256"
// for |NID_X9_62_prime256v1|.
OPENSSL_EXPORT const char *EC_curve_nid2nist(int nid);

// EC_KEY_parse_curve_name parses a DER-encoded OBJECT IDENTIFIER as a curve
// name from |cbs| and advances |cbs|. It returns a newly-allocated |EC_GROUP|
// or NULL on error.
OPENSSL_EXPORT EC_GROUP *EC_KEY_parse_curve_name(CBS *cbs);

*/
