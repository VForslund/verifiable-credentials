package com.truecaller.backend.service.crypto;

import java.util.Arrays;

/**
 * Multibase base58btc (RFC draft-multibase) — the encoding required by the
 * W3C Data Integrity {@code proofValue} and {@code did:key} (W3C-DID-KEY).
 * Pure Java, no external deps.
 */
public final class Base58Btc {

    private static final String ALPHABET =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    private Base58Btc() {}

    public static String encode(byte[] input) {
        if (input.length == 0) return "";
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) zeros++;
        byte[] copy = Arrays.copyOf(input, input.length);
        int startAt = zeros;
        StringBuilder sb = new StringBuilder();
        while (startAt < copy.length) {
            int mod = divmod58(copy, startAt);
            if (copy[startAt] == 0) startAt++;
            sb.append(ALPHABET.charAt(mod));
        }
        sb.repeat("1", zeros);
        return sb.reverse().toString();
    }

    public static byte[] decode(String input) {
        if (input.isEmpty()) return new byte[0];
        byte[] input58 = new byte[input.length()];
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit = ALPHABET.indexOf(c);
            if (digit < 0) throw new IllegalArgumentException("Invalid base58 character: " + c);
            input58[i] = (byte) digit;
        }
        int zeros = 0;
        while (zeros < input58.length && input58[zeros] == 0) zeros++;
        byte[] decoded = new byte[input.length()];
        int outputStart = decoded.length;
        for (int inputStart = zeros; inputStart < input58.length; ) {
            decoded[--outputStart] = divmod256(input58, inputStart);
            if (input58[inputStart] == 0) inputStart++;
        }
        while (outputStart < decoded.length && decoded[outputStart] == 0) outputStart++;
        return Arrays.copyOfRange(decoded, outputStart - zeros, decoded.length);
    }

    private static int divmod58(byte[] number, int startAt) {
        int remainder = 0;
        for (int i = startAt; i < number.length; i++) {
            int digit256 = number[i] & 0xFF;
            int temp = remainder * 256 + digit256;
            number[i] = (byte) (temp / 58);
            remainder = temp % 58;
        }
        return remainder;
    }

    private static byte divmod256(byte[] number58, int startAt) {
        int remainder = 0;
        for (int i = startAt; i < number58.length; i++) {
            int digit58 = number58[i] & 0xFF;
            int temp = remainder * 58 + digit58;
            number58[i] = (byte) (temp / 256);
            remainder = temp % 256;
        }
        return (byte) remainder;
    }
}

