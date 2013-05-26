package com.exef.utils;

import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author Filip
 */
public class HexOperations {

    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }

    public static String toHexString(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }
}
