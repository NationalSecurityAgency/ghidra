/* ###
 * IP: GHIDRA
 * REVIEWED: YES
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import java.math.BigInteger;

public class DecodeBitMasks {

	long tmask;
	long wmask;

	long immN, immr, imms;

	int M;

	int HighestSetBit(long x, int bitSize) {
		long mask = 0x1 << (bitSize - 1);
		for (int i = bitSize - 1; i >= 0; i--) {
			if ((mask & x) == mask) {
				return i;
			}
			mask = mask >> 1;
		}
		return -1;
	}

	long ZeroExtend(long x, int bitSize, int extSize) {
		long mask = Ones(bitSize);

		x = x & mask;

		return x;
	}

	private long Ones(int bitSize) {
		long mask = 0x0;

		for (int i = 0; i < bitSize; i++) {
			mask = (mask << 1) | 1;
		}

		return mask;
	}

	long Replicate(long x, int bitSize, int startBit, int repSize, int extSize) {
		long repval = (x >> startBit) & Ones(repSize);
		int times = extSize / repSize;
		long val = 0;
		for (int i = 0; i < times; i++) {
			val = (val << repSize) | repval;
		}
		repval = val << startBit;

		x = x | repval;
		return x;
	}

	long ROR(long x, int esize, long rotate) {
		long a = x << (esize - rotate) & Ones(esize);
		long r = x >> (rotate) & Ones(esize);
		return ((a | r) & Ones(esize));
	}

	boolean decode(long iN, long is, long ir, boolean immediate, int Msize) {

		immN = iN;
		imms = is;
		immr = ir;

		M = Msize;

		tmask = wmask = 0;

		long levels;

		// Compute log2 of element size
		// 2^len must be in range [2, M]
		//                   immN:NOT(imms));
		int len = HighestSetBit(immN << 6 | ((~imms) & Ones(6)), 7);

		if (len < 1) {
			System.out.println("bad value " + immN + ":" + immr + ":" + imms);
			return false;
		}

		assert (M >= (1 << len));

		// Determine S, R and S - R parameters
		levels = ZeroExtend(Ones(len), 6, 6);

		// For logical immediates an all-ones value of S is reserved
		// since it would generate a useless all-ones result (many times)
		if (immediate && (imms & levels) == levels) {
			System.out.println("All-Ones " + immN + ":" + immr + ":" + imms);
			return false;
		}

		long S = imms & levels;
		long R = immr & levels;

		long diff = S - R; // 6-bit subtract with borrow

		int esize = 1 << len;

		long d = diff & Ones(len - 1);

		long welem = ZeroExtend(Ones((int) (S + 1)), esize, esize);
		long telem = ZeroExtend(Ones((int) (d + 1)), esize, esize);

		//wmask = Replicate(ROR(welem, R));

		wmask = Replicate(ROR(welem, esize, R), esize, 0, esize, M);

		// Replicate(telem);
		tmask = Replicate(telem, esize, 0, esize, M);

		return true;
	}

	static String bitStr(long value, int bitSize) {
		BigInteger val = BigInteger.valueOf(value);
		val = val.and(new BigInteger("FFFFFFFFFFFFFFFF", 16));

		String str = val.toString(2);
		int len = str.length();
		for (; len < bitSize; len++) {
			str = "0" + str;
		}
		return str;
	}

	void printit() {
		System.out.println(bitStr(immN, 1) + ":" + bitStr(immr, 6) + ":" + bitStr(imms, 6) + " = " +
			bitStr(wmask, M) + "   " + bitStr(tmask, M));
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		DecodeBitMasks bm = new DecodeBitMasks();
		boolean valid;
		
		valid = bm.decode(0, 0, 0, true, 64);
		if (valid) {
			bm.printit();
		}
		
		int immN = 0;
		//for (int immN = 0; immN <= 1; immN++) {
		for (int immr = 0; immr <= 0x3f; immr++) {
			for (int imms = 0; imms <= 0x3f; imms++) {
				valid = bm.decode(immN, imms, immr, true, 32);
				if (valid) {
					bm.printit();
				}
			}
		}
		//}

		//for (int immr = 0; immr <= 0x3f; immr++) {
		for (int imms = 0; imms <= 0x3f; imms++) {
			valid = bm.decode(immN, imms, 0, true, 32);
			if (valid) {
				bm.printit();
			}
		}
		//}

		if (bm.decode(0, 0x1E, 0x1F, true, 32)) {
			bm.printit();
		}

		if (bm.decode(0, 0x1D, 0x1E, true, 32)) {
			bm.printit();
		}
		
		
		immN = 0;
		for (int immr = 0; immr <= 0x3f; immr++) {
			for (int imms = 0; imms <= 0x3f; imms++) {
				valid = bm.decode(immN, imms, immr, true, 64);
				if (valid) {
					bm.printit();
				}
			}
		}
		
		immN = 1;
		for (int immr = 0; immr <= 0x3f; immr++) {
			for (int imms = 0; imms <= 0x3f; imms++) {
				valid = bm.decode(immN, imms, immr, true, 64);
				if (valid) {
					bm.printit();
				}
			}
		}
		
		immN = 0;
		for (int imms = 0; imms <= 0x3f; imms++) {
			valid = bm.decode(immN, imms, 0, true, 64);
			if (valid) {
				bm.printit();
			}
		}
		
		immN = 1;
		for (int imms = 0; imms <= 0x3f; imms++) {
			valid = bm.decode(immN, imms, 0, true, 64);
			if (valid) {
				bm.printit();
			}
		}
	}

}
