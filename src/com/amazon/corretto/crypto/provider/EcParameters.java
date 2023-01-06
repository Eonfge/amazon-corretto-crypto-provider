// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.io.IOException;

import java.security.*;
import java.security.spec.*;


public final class EcParameters extends AlgorithmParametersSpi {
    private EcUtils.ECInfo ecInfo;

    // A public constructor is required by AlgorithmParameters class.
    public EcParameters() {}

    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (paramSpec == null) {
            throw new InvalidParameterSpecException("paramSpec must not be null");
        }

        if (paramSpec instanceof ECParameterSpec) {
            String name = EcUtils.getNameBySpec((ECParameterSpec)paramSpec);
            ecInfo = EcUtils.getSpecByName(name);
        } else if (paramSpec instanceof ECGenParameterSpec) {
            String name = ((ECGenParameterSpec)paramSpec).getName();
            ecInfo = EcUtils.getSpecByName(name);
        } else {
            throw new InvalidParameterSpecException("Only ECParameterSpec and ECGenParameterSpec supported");
        }

        if (ecInfo == null) {
            throw new InvalidParameterSpecException("Not a supported curve: " + paramSpec);
        }
    }

    protected void engineInit(byte[] params) throws IOException {
        // TODO [childw]: what to do here?
        //DerValue encodedParams = new DerValue(params);
        //if (encodedParams.tag == DerValue.tag_ObjectId) {
            //ObjectIdentifier oid = encodedParams.getOID();
            //NamedCurve spec = CurveDB.lookup(oid.toString());
            //if (spec == null) {
                //throw new IOException("Unknown named curve: " + oid);
            //}

            //namedCurve = spec;
            //return;
        //}

        throw new IOException("Only named EcParameters supported");
    }

    protected void engineInit(byte[] params, String unused) throws IOException {
        engineInit(params);
    }

    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> spec)
            throws InvalidParameterSpecException {

        if (spec.isAssignableFrom(ECParameterSpec.class)) {
            return spec.cast(ecInfo.spec);
        }

        if (spec.isAssignableFrom(ECGenParameterSpec.class)) {
            return spec.cast(new ECGenParameterSpec(ecInfo.name));
        }

        throw new InvalidParameterSpecException("Only ECParameterSpec and ECGenParameterSpec supported");
    }

    protected byte[] engineGetEncoded() throws IOException {
        // TODO [childw] clone before returning to avoid exposing static reference?
        return ecInfo.encoded;
    }

    protected byte[] engineGetEncoded(String encodingMethod) throws IOException {
        return engineGetEncoded();
    }

    protected String engineToString() {
        if (ecInfo == null) {
            return "Not initialized";
        }

        return ecInfo.name;
    }
}
