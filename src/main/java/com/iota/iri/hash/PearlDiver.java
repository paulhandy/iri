package com.iota.iri.hash;

import com.iota.iri.utils.Converter;
import com.iota.iri.utils.Pair;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * (c) 2016 Come-from-Beyond
 */
public class PearlDiver {

    public static final int TRANSACTION_LENGTH = 8019;

    private static final int CURL_HASH_LENGTH = 243;
    private static final int CURL_STATE_LENGTH = CURL_HASH_LENGTH * 3;

    private static final long HIGH_BITS = 0b1111111111111111111111111111111111111111111111111111111111111111L;
    //private static final long LOW_BITS = 0b0000000000000000000000000000000000000000000000000000000000000000L;

    private static final int RUNNING = 0;
    private static final int CANCELLED = 1;
    private static final int COMPLETED = 2;

    private volatile int state;
    private final Object syncObj = new Object();

    public void cancel() {
        synchronized (syncObj){
            state = CANCELLED;
            syncObj.notifyAll();            
        }
    }

    public synchronized boolean search(final int[] transactionTrits, final int minWeightMagnitude, int numberOfThreads) {

        if (transactionTrits.length != TRANSACTION_LENGTH) {
            throw new RuntimeException("Invalid transaction trits length: " + transactionTrits.length);
        }
        if (minWeightMagnitude < 0 || minWeightMagnitude > CURL_HASH_LENGTH) {
            throw new RuntimeException("Invalid min weight magnitude: " + minWeightMagnitude);
        }

        synchronized (syncObj) {
            state = RUNNING;
        }

        Pair<long[], long[]> midCurl = absorb(transactionTrits, TRANSACTION_LENGTH/CURL_HASH_LENGTH-1, null);
        offset(midCurl);

        numberOfThreads = getThreadCount(numberOfThreads);

        Thread[] workers = new Thread[numberOfThreads];
        
        while (numberOfThreads-- > 0) {

            final int threadIndex = numberOfThreads;
            Thread worker = (new Thread(() -> {

                final long[] midCurlStateCopyLow = new long[CURL_STATE_LENGTH], midCurlStateCopyHigh = new long[CURL_STATE_LENGTH];
                System.arraycopy(midCurl.low, 0, midCurlStateCopyLow, 0, CURL_STATE_LENGTH);
                System.arraycopy(midCurl.hi, 0, midCurlStateCopyHigh, 0, CURL_STATE_LENGTH);
                for (int i = threadIndex; i-- > 0; ) {
                    increment(midCurlStateCopyLow, midCurlStateCopyHigh, CURL_HASH_LENGTH / 3, (CURL_HASH_LENGTH / 3) * 2);
                }

                final long[] curlStateLow = new long[CURL_STATE_LENGTH], curlStateHigh = new long[CURL_STATE_LENGTH];
                final long[] curlScratchpadLow = new long[CURL_STATE_LENGTH], curlScratchpadHigh = new long[CURL_STATE_LENGTH];
                long mask, outMask = 1;
                while (state == RUNNING) {

                    increment(midCurlStateCopyLow, midCurlStateCopyHigh, (CURL_HASH_LENGTH / 3) * 2, CURL_HASH_LENGTH);
                    System.arraycopy(midCurlStateCopyLow, 0, curlStateLow, 0, CURL_STATE_LENGTH);
                    System.arraycopy(midCurlStateCopyHigh, 0, curlStateHigh, 0, CURL_STATE_LENGTH);
                    transform(curlStateLow, curlStateHigh, curlScratchpadLow, curlScratchpadHigh);

                    mask = HIGH_BITS;
                    for (int i = minWeightMagnitude; i-- > 0;) {
                        mask &= ~(curlStateLow[CURL_HASH_LENGTH - 1 - i] ^ curlStateHigh[CURL_HASH_LENGTH - 1 - i]);
                        if ( mask == 0) {
                            break;
                        }
                    }
                    if(mask == 0) continue;

                    synchronized (syncObj) {
                        if (state == RUNNING) {
                            state = COMPLETED;
                            while((outMask & mask) == 0) {
                                outMask <<= 1;
                            }
                            for (int i = 0; i < CURL_HASH_LENGTH; i++) {
                                transactionTrits[TRANSACTION_LENGTH - CURL_HASH_LENGTH + i] = (midCurlStateCopyLow[i] & outMask) == 0 ? 1: (midCurlStateCopyHigh[i] & outMask) == 0 ? -1 : 0;
                            }
							syncObj.notifyAll();
						}
                    }
                    break;
                }
            }));
            workers[threadIndex] = worker;
            worker.start();
        }

        try {
            synchronized (syncObj) {
                if(state == RUNNING) {
                    syncObj.wait();
                }
            }
        } catch (final InterruptedException e) {
            synchronized (syncObj) {
                state = CANCELLED;
            }
        }

        for (Thread worker : workers) {
            try {
                worker.join();
            } catch (final InterruptedException e) {
                synchronized (syncObj) {
                    state = CANCELLED;
                }
            }
        }
        
        return state == COMPLETED;
    }

    private static int getThreadCount(int numberOfThreads) {
        if (numberOfThreads <= 0) {
            numberOfThreads = Runtime.getRuntime().availableProcessors() - 1;
            if (numberOfThreads < 1) {
                return 1;
            }
        }
        return numberOfThreads;
    }


    private static Pair<long[], long[]> absorb(final int[] trits, final int end, Pair<long[], long[]> state) {
        if(state == null) {
            final long[] midCurlStateLow = new long[CURL_STATE_LENGTH], midCurlStateHigh = new long[CURL_STATE_LENGTH];
            for (int i = CURL_HASH_LENGTH; i < CURL_STATE_LENGTH; i++) {

                midCurlStateLow[i] = 0b1111111111111111111111111111111111111111111111111111111111111111L;
                midCurlStateHigh[i] = 0b1111111111111111111111111111111111111111111111111111111111111111L;
            }
            state = new Pair<>(midCurlStateLow, midCurlStateHigh);
        }
        int offset = 0;
        final long[] curlScratchpadLow = new long[CURL_STATE_LENGTH], curlScratchpadHigh = new long[CURL_STATE_LENGTH];
        for (int i = end; i-- > 0; ) {

            for (int j = 0; j < CURL_HASH_LENGTH; j++) {

                if(offset < trits.length) {
                    switch (trits[offset++]) {

                        case 0: {

                            state.low[j] = 0b1111111111111111111111111111111111111111111111111111111111111111L;
                            state.hi[j] = 0b1111111111111111111111111111111111111111111111111111111111111111L;

                        }
                        break;

                        case 1: {

                            state.low[j] = 0b0000000000000000000000000000000000000000000000000000000000000000L;
                            state.hi[j] = 0b1111111111111111111111111111111111111111111111111111111111111111L;

                        }
                        break;

                        default: {

                            state.low[j] = 0b1111111111111111111111111111111111111111111111111111111111111111L;
                            state.hi[j] = 0b0000000000000000000000000000000000000000000000000000000000000000L;
                        }
                    }
                }
            }

            transform(state.low, state.hi, curlScratchpadLow, curlScratchpadHigh);
        }
        return state;
    }

    private static void offset(final Pair<long[], long[]> trits) {
        trits.low[0] = 0b1101101101101101101101101101101101101101101101101101101101101101L;
        trits.hi[0] = 0b1011011011011011011011011011011011011011011011011011011011011011L;
        trits.low[1] = 0b1111000111111000111111000111111000111111000111111000111111000111L;
        trits.hi[1] = 0b1000111111000111111000111111000111111000111111000111111000111111L;
        trits.low[2] = 0b0111111111111111111000000000111111111111111111000000000111111111L;
        trits.hi[2] = 0b1111111111000000000111111111111111111000000000111111111111111111L;
        trits.low[3] = 0b1111111111000000000000000000000000000111111111111111111111111111L;
        trits.hi[3] = 0b0000000000111111111111111111111111111111111111111111111111111111L;
    }

    public int[] findChecksum(final int[] trits, final int length, int numberOfThreads, final int sumLength) {
        int rem = trits.length % Curl.HASH_LENGTH;
        int end = trits.length / Curl.HASH_LENGTH;
        if(rem != 0) {
            end++;
        }

        int[] lengthTrits = Converter.trits(trits.length);
        Pair<long[], long[]> midCurlState = absorb(lengthTrits, 1, null);
        absorb(trits, end, midCurlState);
        for(int i = 0; i < length; i++) {
            midCurlState.hi[i] = HIGH_BITS;
            midCurlState.low[i] = HIGH_BITS;
        }
        offset(midCurlState);

        numberOfThreads = getThreadCount(numberOfThreads);

        Thread[] workers = new Thread[numberOfThreads];
        int[] checksum;
        AtomicInteger state = new AtomicInteger(RUNNING);
        AtomicInteger checksumLength = new AtomicInteger(length);
        checksum = new int[Curl.HASH_LENGTH];
        while (numberOfThreads-- > 0) {
            workers[numberOfThreads] = new Thread(spawnChecksumFinder(checksum, trits, midCurlState, checksumLength, sumLength, numberOfThreads, syncObj, state), "Checksum Finder " + numberOfThreads);
            workers[numberOfThreads].start();
        }

        try {
            synchronized (syncObj) {
                if (state.get() == RUNNING) {
                    syncObj.wait();
                }
            }
        } catch (final InterruptedException e) {
            state.set(CANCELLED);
            synchronized (syncObj) {
                state.set(CANCELLED);
            }
        }

        for (Thread worker : workers) {
            try {
                worker.join();
            } catch (final InterruptedException e) {
                synchronized (syncObj) {
                    state.set(CANCELLED);
                }
            }
        }
        checksum = Arrays.copyOf(checksum, checksumLength.get());
        int sum = ISS.checkChecksum(trits, checksum);
        return checksum;
    }

    private static Runnable spawnChecksumFinder(final int[] out, final int[] trits, final Pair<long[], long[]> midCurlState, final AtomicInteger checksumLength,
                                                final int sumLength, final int threadIndex, final Object syncObj, final AtomicInteger state) {
        return () -> {
            int length = checksumLength.get();
            int midLength = length/2;
            Pair<long[], long[]> midCurlStateCopy = new Pair<>(new long[CURL_STATE_LENGTH], new long[CURL_STATE_LENGTH]);
            Pair<long[], long[]> curlState = new Pair<>(new long[CURL_STATE_LENGTH], new long[CURL_STATE_LENGTH]);
            Pair<long[], long[]> curlScratchpad = new Pair<>(new long[CURL_STATE_LENGTH], new long[CURL_STATE_LENGTH]);
            System.arraycopy(midCurlState.low, 0, midCurlStateCopy.low, 0, CURL_STATE_LENGTH);
            System.arraycopy(midCurlState.hi, 0, midCurlStateCopy.hi, 0, CURL_STATE_LENGTH);
            for (int i = threadIndex; i-- > 0; ) {
                increment(midCurlStateCopy.low, midCurlStateCopy.hi, 4, midLength);
            }

            while (state.get() == RUNNING) {
                if(increment(midCurlStateCopy.low, midCurlStateCopy.hi, midLength, length) && length < CURL_HASH_LENGTH) {
                    length += 3;
                }
                System.arraycopy(midCurlStateCopy.low, 0, curlState.low, 0, CURL_STATE_LENGTH);
                System.arraycopy(midCurlStateCopy.hi, 0, curlState.hi, 0, CURL_STATE_LENGTH);
                transform(curlState.low, curlState.hi, curlScratchpad.low, curlScratchpad.hi);

                int checksumIndex = checkChecksum(curlState, sumLength);
                if(checksumIndex == -1) continue;

                synchronized (syncObj) {
                    if (state.get() == RUNNING) {
                        int[] checksum = Converter.trits(midCurlStateCopy, checksumIndex);
                        int sum = ISS.checkChecksum(trits, Arrays.copyOf(checksum, length));
                        if(sum == 0) {
                            state.set(COMPLETED);
                            System.arraycopy(checksum, 0, out, 0, length);
                            checksumLength.set(length);
                            syncObj.notifyAll();
                            break;
                        }
                    }
                }
            }
        };
    }

    /**
     * The point of the checksum finder is to find a checksum such that the sum of all trits of the final hash is 0.
     * Here, we take the output of the final transform that would be run on `squeeze`, and we check that the number of
     * high trits equals the number of low trits. This is done by transposing the state function so that each column,
     * which was previously an individual state, is now in a row. We then find the first index where the hamming weight
     * of the low hash is equal to the hi hash.
     * the
     * @param midCurlState the low/hi state array
     * @return index
     */
    static int checkChecksum(Pair<long[], long[]> midCurlState, final int length) {
        Pair<BigInteger[], BigInteger[]> checks = transpose(midCurlState, 0, length);
        int out = -1;
        for(int i = 0; i < Long.SIZE; i++) {
            if(checks.low[i].bitCount() == checks.hi[i].bitCount()) {
                out = i;
                break;
            }
        }
        return out;
    }

    private static long[] identity = new long[Long.SIZE];
    static {
        for(int i = 0; i < identity.length; i++) {
            identity[i] = 1<<i;
        }
    }

    /**
     * This performs a vanilla binary transpose, making rows into columns and vice versa.
     * @param midCurlState
     * @param offset
     * @param length
     * @return transposed pair matrix
     */
    static Pair<BigInteger[], BigInteger[]> transpose(Pair<long[], long[]> midCurlState, final int offset, final int length) {
        Pair<BigInteger[], BigInteger[]> output = new Pair<>(new BigInteger[Long.SIZE], new BigInteger[Long.SIZE]);
        for(int j = 0; j < Long.SIZE; j++) {
            output.low[j] = new BigInteger(new byte[length]);
            output.hi[j] = new BigInteger(new byte[length]);
            for(int i = 0; i < length; i++) {
                if((midCurlState.low[offset + i] & identity[j]) != 0) {
                    output.low[j] = output.low[j].setBit(i);
                }
                if((midCurlState.hi[offset + i] & identity[j]) != 0) {
                    output.hi[j] = output.hi[j].setBit(i);
                }
            }
        }
        return output;
    }

    private static void transform(final long[] curlStateLow, final long[] curlStateHigh, final long[] curlScratchpadLow, final long[] curlScratchpadHigh) {

        int curlScratchpadIndex = 0;
        for (int round = 27; round-- > 0; ) {

            System.arraycopy(curlStateLow, 0, curlScratchpadLow, 0, CURL_STATE_LENGTH);
            System.arraycopy(curlStateHigh, 0, curlScratchpadHigh, 0, CURL_STATE_LENGTH);

            for (int curlStateIndex = 0; curlStateIndex < CURL_STATE_LENGTH; curlStateIndex++) {

                final long alpha = curlScratchpadLow[curlScratchpadIndex];
                final long beta = curlScratchpadHigh[curlScratchpadIndex];
                if (curlScratchpadIndex < 365) {
                    curlScratchpadIndex += 364;
                } else {
                    curlScratchpadIndex += -365;
                }
                final long gamma = curlScratchpadHigh[curlScratchpadIndex];
                final long delta = (alpha | (~gamma)) & (curlScratchpadLow[curlScratchpadIndex] ^ beta);

                curlStateLow[curlStateIndex] = ~delta;
                curlStateHigh[curlStateIndex] = (alpha ^ gamma) | delta;
            }
        }
    }

    private static boolean increment(final long[] midCurlStateCopyLow, final long[] midCurlStateCopyHigh, final int fromIndex, final int toIndex) {
        int i;
        for (i = fromIndex; i < toIndex; i++) {
            if (midCurlStateCopyLow[i] == 0b0000000000000000000000000000000000000000000000000000000000000000L) {
                midCurlStateCopyLow[i] = 0b1111111111111111111111111111111111111111111111111111111111111111L;
                midCurlStateCopyHigh[i] = 0b0000000000000000000000000000000000000000000000000000000000000000L;
            } else {
                if (midCurlStateCopyHigh[i] == 0b0000000000000000000000000000000000000000000000000000000000000000L) {
                    midCurlStateCopyHigh[i] = 0b1111111111111111111111111111111111111111111111111111111111111111L;
                } else {
                    midCurlStateCopyLow[i] = 0b0000000000000000000000000000000000000000000000000000000000000000L;
                }
                break;
            }
        }
        return i == toIndex && midCurlStateCopyHigh[i-1] == 0;
    }
}
