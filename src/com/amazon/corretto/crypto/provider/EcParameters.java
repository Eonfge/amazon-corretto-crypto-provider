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

        String name = null;
        if (paramSpec instanceof ECParameterSpec) {
            name = EcUtils.getNameBySpec((ECParameterSpec)paramSpec);
        } else if (paramSpec instanceof ECGenParameterSpec) {
            name = ((ECGenParameterSpec)paramSpec).getName();
        } else {
            throw new InvalidParameterSpecException("Only ECParameterSpec, ECGenParameterSpec, and ECKeySizeParameterSpec supported");
        }

        ecInfo = EcUtils.getSpecByName(name);
        if (ecInfo == null) {
            throw new InvalidParameterSpecException("Unknown curve: " + paramSpec);
        }
    }

    protected void engineInit(byte[] params) throws IOException {
        String name = null;
        try {
            name = EcUtils.getCurveNameFromEncoded(params);
        } catch (RuntimeCryptoException e) {
            // pass, handle via null check below
        }
        if (name == null) {
            throw new IOException("Only named EcParameters supported");
        }
        ecInfo = EcUtils.getSpecByName(name);
        if (ecInfo == null) {
            throw new IOException("Unknown named curve: " + name);
        }
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
        return ecInfo.encoded.clone();
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
