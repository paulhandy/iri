package com.iota.iri.crypto;

import com.iota.iri.model.Hash;
import com.iota.iri.model.HashFactory;
import com.iota.iri.utils.Converter;
import com.iota.iri.utils.Pair;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.Test;
//import org.junit.jupiter.api.Test;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.*;

/**
 * Created by paul on 7/23/17.
 */
public class ISSTest {
    static String seed = "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN";
    static String thedigest = "IAOP9MMCMUVKHPHUOCDTCRHOELK9QC99C9BMUWVJACTMFZXKIHVFMCNTZWJXYTJDCPLCHXXMXRPLUDDEC";
    static String message = "JCRNMXX9DIEVJJG9VW9QDUMVDGDVHANQDTCPPOPHLTBUBXULSIALRBVUINDPNGUFZLKDPOK9WBJMYCXF9" +
            "MFQN9ZKMROOXHULIDDXRNWMDENBWJWVVA9XPNHQUVDFSMQ9ETWKWGLOLYPWW9GQPVNDYJIRDBWVCBUHUE" +
            "GELSTLEXGAMMQAHSUEABKUSFOVGYRQBXJMORXIDTIPENPAFIUV9DOGZCAEPRJQOISRZDZBWWQQJVQDS9Y" +
            "GCMNADNVSUTXXAONPHBFCMWSVFYYXXWDZXFP9SZGLRCHHGKLNAQPMAXHFUUSQEKDAPH9GFVHMYDITCTFS" +
            "IJEZFADOJVDOEXOTDDPZYLKKDHCGPXYMGRKAGOEQYHTCTGKMZOKMZJLCQOYE9KFVRQLXDPBALUSEQSQDF" +
            "PPUYALCDYWSHANNQYKIMAZMKQQ9XVCSJHAWXLY9IIREZTSOFRMRGKDQPIEMDXTBDTY9DKOAIUEGNLUSRF" +
            "ZYPRNUOHFGDYIWFVKIUNYBGBHICRQTLDQQUTJX9DDSQANVKMCDZ9VEQBCHHSATVFIDYR9XUSDJHQDRBVK" +
            "9JUUZVWGCCWVXAC9ZIOKBWOKCTCJVXIJFBSTLNZCPJMAKDPYLTHMOKLFDNONJLLDBDXNFKPKUBKDU9QFS" +
            "XGVXS9PEDBDDBGFESSKCWUWMTOGHDLOPRILYYPSAQVTSQYLIPK9ATVMMYSTASHEZEFWBUNR9XKGCHR9MB";

    @Test
    public void newsiggy() throws Exception {
        int index = 9;
        int nof = 3;
        SpongeFactory.Mode mode = SpongeFactory.Mode.CURLP81;

        byte[] seedTrits = new byte[Sponge.HASH_LENGTH];

        Converter.trits(seed, seedTrits, 0);
        byte[] subseed = ISS.subseed(mode, seedTrits, index);
        byte[] key = ISS.key(mode, subseed, nof);


        Sponge curl = new Kerl();
        byte[] digtrits = Converter.allocateTritsForTrytes(thedigest.length());
        Converter.trits(thedigest, digtrits, 0);

        byte[] normalizedFragments = ISS.normalizedBundle(digtrits);
        List<byte[]> dd = new ArrayList<>();
        List<byte[]> ss = new ArrayList<>();
        for(int i = 0; i < 3; i++) {
            byte[] normalizedFragment = Arrays.copyOfRange(normalizedFragments, i * ISS.NUMBER_OF_FRAGMENT_CHUNKS,
                    (i + 1 ) * ISS.NUMBER_OF_FRAGMENT_CHUNKS);
            byte[] signature = ISS.signatureFragment(mode,
                    normalizedFragment,
                    Arrays.copyOfRange(key, i * ISS.FRAGMENT_LENGTH, (i+1) * ISS.FRAGMENT_LENGTH));
            byte[] sigDigest = ISS.digest(mode, normalizedFragment, signature);
            dd.add(sigDigest);
            ss.add(signature);
        }
        byte[] signedAddress = ISS.address(mode, dd.stream().reduce(ArrayUtils::addAll).get());
        byte[] digest = ISS.digests(mode, key);
        byte[] address = ISS.address(mode, digest);

        for(byte[] sig:ss) {
            String siggy = Converter.trytes(sig);
            System.out.println(siggy);
        }
        System.out.println(new Hash(address));
        assertTrue(Arrays.equals(address, signedAddress));
    }
    @Test
    public void treeGenerationISS() throws Exception {
        int index = 10;
        int depth = 6;
        int nof = 3;
        Merkle t = new Merkle(SpongeFactory.Mode.CURLP81, seed, 0, 64, nof);
        t.generate();
        System.out.println(new Hash(t.root()));
        //t.branch(6).stream().map(Hash::new).forEach(System.out::println);

        byte[] digtrits = Converter.allocateTritsForTrytes(thedigest.length());
        Converter.trits(thedigest, digtrits, 0);
        Pair<List<byte[]>, List<byte[]>> sig = t.sign(digtrits, index);

        sig.low.stream().map(Converter::trytes).forEach(System.out::println);
        sig.hi.stream().map(Converter::trytes).forEach(System.out::println);

    }

    @Test
    public void testSignatureResolvesToAddressISS() throws Exception {
        int index = 10;
        int nof = 1;
        SpongeFactory.Mode[] modes = {SpongeFactory.Mode.CURLP81, SpongeFactory.Mode.KERL};

        byte[] seedTrits = new byte[Sponge.HASH_LENGTH];

        for (SpongeFactory.Mode mode: modes) {
            Converter.trits(seed, seedTrits, 0);
            byte[] subseed = ISS.subseed(mode, seedTrits, index);
            byte[] key = ISS.key(mode, subseed, nof);


            Kerl curl = new Kerl();
            byte[] messageTrits = Converter.allocateTritsForTrytes(message.length());
            Converter.trits(message, messageTrits, 0);
            curl.absorb(messageTrits, 0, messageTrits.length);
            byte[] messageHash = new byte[Curl.HASH_LENGTH];
            curl.squeeze(messageHash, 0, Curl.HASH_LENGTH);
            byte[] normalizedFragment =
                    Arrays.copyOf(ISS.normalizedBundle(messageHash),
                            ISS.NUMBER_OF_FRAGMENT_CHUNKS);
            byte[] signature = ISS.signatureFragment(mode, normalizedFragment, key);
            byte[] sigDigest = ISS.digest(mode, normalizedFragment, signature);
            byte[] signedAddress = ISS.address(mode, sigDigest);
            byte[] digest = ISS.digests(mode, key);
            byte[] address = ISS.address(mode, digest);
            assertTrue(Arrays.equals(address, signedAddress));
        }
    }

    @Test
    public void addressGenerationISS() throws Exception {
        int index = 0;
        int nof = 2;
        SpongeFactory.Mode[] modes = {SpongeFactory.Mode.CURLP81, SpongeFactory.Mode.KERL};
        Hash[] hashes = {HashFactory.ADDRESS.create("D9XCNSCCAJGLWSQOQAQNFWANPYKYMCQ9VCOMROLDVLONPPLDFVPIZNAPVZLQMPFYJPAHUKIAEKNCQIYJZ"),
                HashFactory.ADDRESS.create("MDWYEJJHJDIUVPKDY9EACGDJUOP9TLYDWETUBOYCBLYXYYYJYUXYUTCTPTDGJYFKMQMCNZDQPTBE9AFIW")};
        for (int i=0;i<modes.length;i++) {
            SpongeFactory.Mode mode = modes[i];
            byte[] seedTrits = Converter.allocateTritsForTrytes(seed.length());
            Converter.trits(seed, seedTrits, 0);

            byte[] subseed = ISS.subseed(mode, seedTrits, index);
            byte[] key = ISS.key(mode, subseed, nof);
            byte[] digest = ISS.digests(mode, key);
            byte[] address = ISS.address(mode, digest);
            Hash addressTrytes = HashFactory.ADDRESS.create(address);
            assertEquals(hashes[i].toString(), addressTrytes.toString());
        }
    }

    public static Hash getRandomTransactionHash() {
        return HashFactory.TRANSACTION.create(getRandomTrits(Hash.SIZE_IN_TRITS));
    }
    final static Random rnd_seed = new Random();

    public static byte[] getRandomTrits(int length) {
        byte[] out = new byte[length];

        for(int i = 0; i < out.length; i++) {
            out[i] = (byte) (rnd_seed.nextInt(3) - 1);
        }

        return out;
    }

    //@Test
    public void generateNAddressesForSeed() throws Exception {
        int nof = 2;
        System.out.println("seed,address_0,address_1,address_2,address_3");
        for (int i = 0; i< 1000 ; i++) {
            Hash seed = getRandomTransactionHash();
            SpongeFactory.Mode mode = SpongeFactory.Mode.KERL;
            Hash[] addresses = new Hash[4];

            for (int j = 0; j< 4 ; j++) {
                byte[] subseed = ISS.subseed(mode, seed.trits(), j);
                byte[] key = ISS.key(mode, subseed, nof);
                byte[] digest = ISS.digests(mode, key);
                byte[] address = ISS.address(mode, digest);
                addresses[j] = HashFactory.ADDRESS.create(address);
            }
            System.out.println(String.format("%s,%s,%s,%s,%s", seed, addresses[0],addresses[1],addresses[2],addresses[3]));
        }
    }
}
