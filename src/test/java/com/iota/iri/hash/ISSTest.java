package com.iota.iri.hash;

import com.iota.iri.Utility;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

import static com.iota.iri.hash.Curl.HASH_LENGTH;
import static org.junit.Assert.*;

/**
 * Created by paul on 5/21/17.
 */
public class ISSTest {
    @Test
    public void checksum() throws Exception {
        int length = 2345;
        int[] trits = Utility.getRandomTrits(length);
        int[] hash = new int[HASH_LENGTH];
    }

}