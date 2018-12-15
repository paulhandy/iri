package com.iota.iri.hash;

import com.iota.iri.model.Hash;
import com.iota.iri.utils.Converter;
import com.iota.iri.utils.Pair;
import org.apache.commons.lang3.ArrayUtils;

import java.util.*;
import java.util.stream.Collectors;

public class Merkle {
    private final SpongeFactory.Mode mode;
    private final int count;
    private final byte[] seed;
    private byte[] root = null;
    private final int offset;
    private final int nof;
    private List<List<byte[]>> tree;

    public Merkle(SpongeFactory.Mode m, String s, int o, int c, int n) {
        this.mode = m;
        this.count = c;
        this.offset = o;
        this.nof = n;

        this.seed = Converter.allocateTritsForTrytes(s.length());
        this.tree = new LinkedList<>();
        Converter.trits(s, this.seed, 0);
    }

    public int depth() {
        int d = 0;
        for(int i = 1; this.count > i << d; d++);
        return d;
    }

    public void generate() {
        int d = depth() + 1, nh = count, j = 0;
        List<Hash> hashes = new LinkedList<>();
        byte[] subseed, key, digest, address;
        Iterator<Hash> i;
        Sponge s = SpongeFactory.create(this.mode);

        address = Converter.allocateTritsForTrytes(Sponge.HASH_LENGTH / Converter.NUMBER_OF_TRITS_IN_A_TRYTE);

        for (int index = 0; index < count; index++) {
            subseed = ISS.subseed(mode, this.seed, offset + index);
            key = ISS.key(mode, subseed, nof);
            digest = ISS.digests(mode, key);
            hashes.add(new Hash(ISS.address(mode, digest)));
        }

        System.out.println(hashes.get(10));
        tree.add(hashes.stream().map(Hash::trits).collect(Collectors.toList()));
        if(hashes.size() <= 1) {
            return;
        }

        do {
            nh = (nh >> 1) + nh % 2;
            i = hashes.iterator();
            hashes = new LinkedList<>();
            s.reset();
            //System.out.println("next");
            Hash a;
            while(i.hasNext()) {
                a = i.next();
                //System.out.println(new Hash(address));
                s.absorb(a.trits(), 0, address.length);
                if(j++ > 0) {
                    j = 0;
                    s.squeeze(address, 0, address.length);
                    s.reset();
                    hashes.add(new Hash(address));
                }
            }
            if(j > 0) {
                j = 0;
                s.absorb(Hash.NULL_HASH.trits(), 0, Sponge.HASH_LENGTH);
                //System.out.println(new Hash(address));
                s.squeeze(address, 0, address.length);
                s.reset();
                hashes.add(new Hash(address));
            }
            tree.add(hashes.stream().map(Hash::trits).collect(Collectors.toList()));
        } while(d-- > 0 && hashes.size() > 1);
        root = tree.remove(tree.size() - 1).get(0);
    }

    public byte[] root() {
        return root;
    }

    public List<byte[]> branch(int index){
        List<byte[]> b;
        b = new LinkedList<>();
        if(index >= count) {
            return null;
        }
        int i = index + (index % 2 == 0 ? 1 : -1);
        for(List<byte[]> level : tree) {
            System.out.println(i);
            b.add(level.get(i));
            if(i!= 1) {
                i>>= 1;
                i+= i% 2 == 0 ? 1 : -1;
            }
        }
        b.stream().map(Hash::new).forEach(System.out::println);
        return b;
    }

    public Pair<List<byte[]>, List<byte[]>> sign(byte[] digest, int index) {
        byte[] seedTrits = new byte[Sponge.HASH_LENGTH];

        byte[] subseed = ISS.subseed(mode, seed, index);
        byte[] key = ISS.key(mode, subseed, nof);


        byte[] normalizedFragments = ISS.normalizedBundle(digest);
        List<byte[]> ss = new ArrayList<>();
        List<byte[]> dd = new ArrayList<>();
        for(int i = 0; i < 3; i++) {
            byte[] normalizedFragment = Arrays.copyOfRange(normalizedFragments, i * ISS.NUMBER_OF_FRAGMENT_CHUNKS,
                    (i + 1 ) * ISS.NUMBER_OF_FRAGMENT_CHUNKS);
            byte[] signature = ISS.signatureFragment(mode,
                    normalizedFragment,
                    Arrays.copyOfRange(key, i * ISS.FRAGMENT_LENGTH, (i+1) * ISS.FRAGMENT_LENGTH));
            dd.add(ISS.digest(mode, normalizedFragment, signature));
            ss.add(signature);
        }
        Hash h = new Hash(tree.get(0).get(index));
        Hash hi = new Hash(ISS.address(mode, dd.stream().reduce(ArrayUtils::addAll).get()));
        return new Pair(ss, branch(index));
    }

}
