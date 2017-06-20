package com.iota.iri.hash;

import com.iota.iri.Utility;
import com.iota.iri.controllers.TransactionViewModelTest;
import com.iota.iri.model.Hash;
import com.iota.iri.utils.Converter;

import java.math.BigInteger;
import java.util.Random;
import static org.junit.Assert.*;

import com.iota.iri.utils.Pair;
import org.junit.Assert;
import org.junit.Test;

public class PearlDiverTest {

	private final static int TRYTE_LENGTH = 2673;

	@Test
	public void testTranspose() {
	    int offset = 0;
		int length = 60;
		long l = 0b0010101010101010101010101010101010101010101010101010101010101010L,
                h = 0b0101010101010101010101010101010101010101010101010101010101010101L;
		for(int j = 1; j < length; j++) {
            Pair<long[], long[]> longPair = new Pair<>(new long[j], new long[j]);
            for (int i = 0; i < j; i++) {
                if (i % 2 == 0) {
                    longPair.low[i] = l;
                    longPair.hi[i] = h;
                } else {
                    longPair.low[i] = h;
                    longPair.hi[i] = l;
                }
            }
            Pair<BigInteger[], BigInteger[]> p = PearlDiver.transpose(longPair, offset, j);
            int count = p.low[0].bitCount();
            Assert.assertEquals(p.hi[0].bitCount(), j/ 2 + (j% 2 == 0 ? 0 : 1));
            Assert.assertEquals(p.low[0].bitCount(), j/ 2);
        }
	}

	@Test
	public void testchecksumFinder() {
        int checksumLength = 27;
        PearlDiver pearlDiver = new PearlDiver();
        int numberOfThreads = 1;
        int[] trits = Utility.getRandomTrits(729);
        int[] checksum = pearlDiver.findChecksum(trits, checksumLength, numberOfThreads, 243);
        assertEquals(0, ISS.checkChecksum(trits, checksum));
	}

	@Test
	public void testRandomTryteHash() {
		PearlDiver pearlDiver = new PearlDiver();
		Curl curl = new Curl();
		String hash;
		int[] hashTrits = new int[Curl.HASH_LENGTH],
				myTrits;
		int i = 0,
		testCount = 20,
		minWeightMagnitude = 9,
		numCores = -1; // use n-1 cores
		
        String trytes = getRandomTrytes();
        myTrits = Converter.trits(trytes);
        pearlDiver.search(myTrits, minWeightMagnitude, numCores);
        curl.absorb(myTrits, 0, myTrits.length);
        curl.squeeze(hashTrits, 0, Curl.HASH_LENGTH);
        curl.reset();
        hash = Converter.trytes(hashTrits);
        boolean success = isAllNines(hash.substring(Curl.HASH_LENGTH/3-minWeightMagnitude/3));
        i = Curl.HASH_LENGTH;
        int end = Curl.HASH_LENGTH - minWeightMagnitude;
        while(i-- > end) {
            assertEquals(hashTrits[i], 0);
		}
	}

	// Remove below comment to test pearlDiver iteratively
    //@Test
    public void testNoRandomFail() {
        PearlDiver pearlDiver = new PearlDiver();

        int[] trits;
        Hash hash;
        int minWeightMagnitude = 9, numCores = -1; // use n-1 cores
        for(int i = 0; i++ < 10000;) {
            trits = TransactionViewModelTest.getRandomTransactionTrits();
            pearlDiver.search(trits, minWeightMagnitude, numCores);
            hash = Hash.calculate(trits);
            for(int j = Hash.SIZE_IN_TRITS; j --> Hash.SIZE_IN_TRITS - minWeightMagnitude;) {
                assertEquals(hash.trits()[j], 0);
            }
            if(i % 100 == 0) {
                System.out.println(i + " successful hashes.");
            }
        }
    }

	private String getRandomTrytes() {
		String trytes = "";
		Random rand = new Random();
		int i, r;
		for(i = 0; i < TRYTE_LENGTH; i++) {
			r = rand.nextInt(27);
			trytes += Converter.TRYTE_ALPHABET.charAt(r);
		}
		return trytes;
	}
	
	private boolean isAllNines(String hash) {
		int i;
		for(i = 0; i < hash.length(); i++) {
			if(hash.charAt(i) != '9') {
				return false;
			}
		}
		return true;
	}

}
