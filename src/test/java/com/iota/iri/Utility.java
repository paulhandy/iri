package com.iota.iri;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Created by paul on 5/21/17.
 */
public class Utility {
    private static SecureRandom rnd = new SecureRandom();
    public static int[] getRandomTrits(int length) {
        return Arrays.stream(new int[length]).map(i -> rnd.nextInt(3) - 1).toArray();
    }
}
