// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class EcUtils {
    private static final BigInteger MAX_COFACTOR = BigInteger.valueOf(Integer.MAX_VALUE);
    private static final Pattern NIST_CURVE_PATTERN = Pattern.compile("(?:NIST )?(.)-(\\d+)");
    private static final ConcurrentHashMap<EllipticCurve, String> EC_NAME_BY_CURVE = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<Integer, String> EC_NAME_BY_KEY_SIZE = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, ECInfo> EC_INFO_CACHE = new ConcurrentHashMap<>();
    private static final Function<String, ECInfo> EC_INFO_LOADER = new Function<String, ECInfo>() {
        @Override
        public ECInfo apply(final String curveName) {
            final int[] m = new int[1];
            // 1024 bits is more than large enough for all of these values.
            // There is length checking on the native size.
            final byte[] fieldBasis = new byte[128];
            final byte[] a = new byte[128];
            final byte[] b = new byte[128];
            final byte[] cofactor = new byte[128];
            final byte[] gx = new byte[128];
            final byte[] gy = new byte[128];
            final byte[] order = new byte[128];
            final byte[] encoded = new byte[128];   // just OID of named curve, not explicit params

            final int nid = curveNameToInfo(normalizeName(curveName), m, fieldBasis, a, b,
                    cofactor, gx, gy, order, encoded);
            if (nid == 0) {
                    throw new IllegalArgumentException("Invalid curve name: " + curveName);
            }

            final BigInteger bnCofactor = new BigInteger(cofactor);
            if (bnCofactor.compareTo(MAX_COFACTOR) > 0) {
                throw new IllegalArgumentException(
                        "Requested curve has a cofactor which is too large. Curve: " + curveName
                                + " cofactor " + bnCofactor);
            }
            final ECField field;
            if (m[0] != 0) {
                field = new ECFieldF2m(m[0], new BigInteger(fieldBasis));
            } else {
                field = new ECFieldFp(new BigInteger(fieldBasis));
            }

            final EllipticCurve curve = new EllipticCurve(field, new BigInteger(a), new BigInteger(b));
            final ECPoint g = new ECPoint(new BigInteger(gx), new BigInteger(gy));

            final ECParameterSpec spec = new ECParameterSpec(curve, g, new BigInteger(order), bnCofactor.intValue());

            return new ECInfo(curveName, spec, nid, encoded);
        }

        private String normalizeName(final String name) {
            final Matcher matcher = NIST_CURVE_PATTERN.matcher(name);
            if (matcher.matches()) {
                switch (matcher.group(1)) {
                    case "P":
                        // TODO [childw]
                        if ("256".equals(matcher.group(2))) {
                            return "prime256v1";
                        } else {
                            return "secp" + matcher.group(2) + "r1";
                        }
                    case "K":
                        return "sect" + matcher.group(2) + "k1";
                    case "B":
                        // 163 is special. Maybe we need a table of these?
                        if ("163".equals(matcher.group(2))) {
                            return "sect163r2";
                        } else {
                            return "sect" + matcher.group(2) + "r1";
                        }
                    default:
                        return name;
                }
            } else if (name.startsWith("X9.62 ")) {
                return name.substring(6);
            } else if (name.equals("secp256r1")) {  // TODO [childw]
                return "prime256v1";
            } else {
                return name;
            }
        }
    };

    private static native int curveNameToInfo(String curveName,
            // Array of length 1 to contain the binary field M return value
            // 0 if a prime field
            int[] m,
            // Basis for the field
            byte[] basis,
            // Curve equation
            byte[] a, byte[] b,
            // Cofactor
            byte[] cofactor,
            // Generator
            byte[] gx, byte[] gy,
            // Order of the generator
            byte[] order,
            // DER-encoded info: OID for named, ECParameters for explicit (cf. RFC-3279 2.3.5)
            byte[] encoded);
    private static native long buildGroup(int nid);
    private static native void freeGroup(long ptr);
    private static native String[] getCurveNames();
    static native String getCurveNameFromEncoded(byte[] encoded);

    private EcUtils() {
        // Prevent instantiation
    }

    static ECInfo getSpecByName(final String curveName) {
        return EC_INFO_CACHE.computeIfAbsent(curveName, EC_INFO_LOADER);
    }

    static String getNameBySpec(final ECParameterSpec spec) throws InvalidParameterSpecException {
        if (EC_NAME_BY_CURVE.isEmpty()) {
            for (String name : getCurveNames()) {
                EC_NAME_BY_CURVE.put(getSpecByName(name).spec.getCurve(), name);
            }
        }
        return EC_NAME_BY_CURVE.get(spec.getCurve());
    }

    static String getNameByKeySize(final Integer keySize) throws InvalidParameterSpecException {
        if (EC_NAME_BY_KEY_SIZE.isEmpty()) {
            for (String name : getCurveNames()) {
                EC_NAME_BY_KEY_SIZE.put(getSpecByName(name).spec.getCurve().getField().getFieldSize(), name);
            }
        }
        return EC_NAME_BY_KEY_SIZE.get(keySize);
    }

    static final class ECInfo {
        private final ThreadLocal<NativeGroup> group = new ThreadLocal<NativeGroup>() {
          @Override
          protected NativeGroup initialValue() {
              if (nid != 0) {
                  return new NativeGroup(buildGroup(nid));
              } else {
                  return null;
              }
          }
        };

        final String name;
        final ECParameterSpec spec;
        final int nid;
        final byte[] encoded;

        private ECInfo(final String name, final ECParameterSpec spec, final int nid, final byte[] encoded) {
            super();
            this.name = name;
            this.spec = spec;
            this.nid = nid;
            this.encoded = encoded;
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, nid);
        }

        @Override
        public boolean equals(final Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final ECInfo other = (ECInfo) obj;
            if (!Objects.equals(name, other.name)) {
                return false;
            }
            if (!Objects.equals(nid, other.nid)) {
                return false;
            }
            return true;
        }

        NativeGroup getGroup() {
            return group.get();
        }

        @Override
        public String toString() {
            return "ECInfo [name=" + name + ", spec=" + spec + ", nid=" + nid + "]";
        }
    }

    static final class NativeGroup extends NativeResource {
        protected NativeGroup(long ptr) {
            super(ptr, EcUtils::freeGroup);
        }
    }
}
