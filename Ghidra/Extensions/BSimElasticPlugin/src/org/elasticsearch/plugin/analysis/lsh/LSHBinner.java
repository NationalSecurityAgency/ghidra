/* ###
 * IP: GHIDRA
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
package org.elasticsearch.plugin.analysis.lsh;

import generic.lsh.vector.HashEntry;
import ghidra.features.bsim.query.elastic.Base64Lite;

/**
 * Class for calculating the bin ids on LSHVectors as part of the LSH indexing process
 *
 */
public class LSHBinner {

	private static final char[] hashSignTable = new char[512];
	private static int VEC_SIZE_UPPER = 5;		// Size above which to use FFT to calculate dotproduct family
	private static int LSH_HASHBASE = 0xd7e6a299;
	private static int HASH_MULTIPLIER = 1103515245;
	private static int HASH_ADDEND = 12345;
	
	public static class BytesRef {
		public char[] buffer;
		public BytesRef(int size) { buffer = new char[size]; }
	}

	private int k;						// Number of bits per bin id
	private int L;						// Number of binnings
	private double doubleBuffer[];		// Scratch space for dot-product calculation
	private BytesRef tokenList[];		// Final token list used by lucene

	static {
		/**
		 * This is a precalculated table for generating dot-products with the random family of vectors directly
		 * The first vector r_0 is expressed as a hashing function on the dimension index and the other vectors
		 * are derived from r_0 using an FFT.  The table is formed by precalculating the FFT on basis vectors in this table
		 */
		int i, j;
		int[] arr = new int[16];
		int hibit0ptr;
		int hibit1ptr;

		for (i = 0; i < 16; ++i) { /* For each 4-bit position */
			hibit0ptr = i * 16;
			hibit1ptr = (i + 16) * 16;
			for (j = 0; j < 16; ++j)
				arr[j] = 0;

			arr[i] = 1;
			hashFft16(arr);
			for (j = 0; j < 16; ++j) {
				if (arr[j] > 0) {
					hashSignTable[hibit0ptr + j] = '+';
					hashSignTable[hibit1ptr + j] = '-';
				} else {
					hashSignTable[hibit0ptr + j] = '-';
					hashSignTable[hibit1ptr + j] = '+';
				}
			}
		}
	}

	/**
	 * Raw Fast Fourier Transform on 16 wide integer array
	 * @param arr is the 16-long array
	 */
	private static void hashFft16(int[] arr) {
	  int x,y;
	  
	  x = arr[0]; y = arr[8]; arr[0] = x + y; arr[8] = x - y;
	  x = arr[1]; y = arr[9]; arr[1] = x + y; arr[9] = x - y;
	  x = arr[2]; y = arr[10]; arr[2] = x + y; arr[10] = x - y;
	  x = arr[3]; y = arr[11]; arr[3] = x + y; arr[11] = x - y;
	  x = arr[4]; y = arr[12]; arr[4] = x + y; arr[12] = x - y;
	  x = arr[5]; y = arr[13]; arr[5] = x + y; arr[13] = x - y;
	  x = arr[6]; y = arr[14]; arr[6] = x + y; arr[14] = x - y;
	  x = arr[7]; y = arr[15]; arr[7] = x + y; arr[15] = x - y;

	  x = arr[0]; y = arr[4]; arr[0] = x + y; arr[4] = x - y;
	  x = arr[1]; y = arr[5]; arr[1] = x + y; arr[5] = x - y;
	  x = arr[2]; y = arr[6]; arr[2] = x + y; arr[6] = x - y;
	  x = arr[3]; y = arr[7]; arr[3] = x + y; arr[7] = x - y;
	  x = arr[8]; y = arr[12]; arr[8] = x + y; arr[12] = x - y;
	  x = arr[9]; y = arr[13]; arr[9] = x + y; arr[13] = x - y;
	  x = arr[10]; y = arr[14]; arr[10] = x + y; arr[14] = x - y;
	  x = arr[11]; y = arr[15]; arr[11] = x + y; arr[15] = x - y;

	  x = arr[0]; y = arr[2]; arr[0] = x + y; arr[2] = x - y;
	  x = arr[1]; y = arr[3]; arr[1] = x + y; arr[3] = x - y;
	  x = arr[4]; y = arr[6]; arr[4] = x + y; arr[6] = x - y;
	  x = arr[5]; y = arr[7]; arr[5] = x + y; arr[7] = x - y;
	  x = arr[8]; y = arr[10]; arr[8] = x + y; arr[10] = x - y;
	  x = arr[9]; y = arr[11]; arr[9] = x + y; arr[11] = x - y;
	  x = arr[12]; y = arr[14]; arr[12] = x + y; arr[14] = x - y;
	  x = arr[13]; y = arr[15]; arr[13] = x + y; arr[15] = x - y;

	  x = arr[0]; y = arr[1]; arr[0] = x + y; arr[1] = x - y;
	  x = arr[2]; y = arr[3]; arr[2] = x + y; arr[3] = x - y;
	  x = arr[4]; y = arr[5]; arr[4] = x + y; arr[5] = x - y;
	  x = arr[6]; y = arr[7]; arr[6] = x + y; arr[7] = x - y;
	  x = arr[8]; y = arr[9]; arr[8] = x + y; arr[9] = x - y;
	  x = arr[10]; y = arr[11]; arr[10] = x + y; arr[11] = x - y;
	  x = arr[12]; y = arr[13]; arr[12] = x + y; arr[13] = x - y;
	  x = arr[14]; y = arr[15]; arr[14] = x + y; arr[15] = x - y;
	}

	/**
	 * Raw Fast Fourier Transform on 16 wide array of doubles
	 * @param arr is the 16-long array
	 */
	private static void hashFft16(double[] arr) {
	  double x,y;
	  
	  x = arr[0]; y = arr[8]; arr[0] = x + y; arr[8] = x - y;
	  x = arr[1]; y = arr[9]; arr[1] = x + y; arr[9] = x - y;
	  x = arr[2]; y = arr[10]; arr[2] = x + y; arr[10] = x - y;
	  x = arr[3]; y = arr[11]; arr[3] = x + y; arr[11] = x - y;
	  x = arr[4]; y = arr[12]; arr[4] = x + y; arr[12] = x - y;
	  x = arr[5]; y = arr[13]; arr[5] = x + y; arr[13] = x - y;
	  x = arr[6]; y = arr[14]; arr[6] = x + y; arr[14] = x - y;
	  x = arr[7]; y = arr[15]; arr[7] = x + y; arr[15] = x - y;

	  x = arr[0]; y = arr[4]; arr[0] = x + y; arr[4] = x - y;
	  x = arr[1]; y = arr[5]; arr[1] = x + y; arr[5] = x - y;
	  x = arr[2]; y = arr[6]; arr[2] = x + y; arr[6] = x - y;
	  x = arr[3]; y = arr[7]; arr[3] = x + y; arr[7] = x - y;
	  x = arr[8]; y = arr[12]; arr[8] = x + y; arr[12] = x - y;
	  x = arr[9]; y = arr[13]; arr[9] = x + y; arr[13] = x - y;
	  x = arr[10]; y = arr[14]; arr[10] = x + y; arr[14] = x - y;
	  x = arr[11]; y = arr[15]; arr[11] = x + y; arr[15] = x - y;

	  x = arr[0]; y = arr[2]; arr[0] = x + y; arr[2] = x - y;
	  x = arr[1]; y = arr[3]; arr[1] = x + y; arr[3] = x - y;
	  x = arr[4]; y = arr[6]; arr[4] = x + y; arr[6] = x - y;
	  x = arr[5]; y = arr[7]; arr[5] = x + y; arr[7] = x - y;
	  x = arr[8]; y = arr[10]; arr[8] = x + y; arr[10] = x - y;
	  x = arr[9]; y = arr[11]; arr[9] = x + y; arr[11] = x - y;
	  x = arr[12]; y = arr[14]; arr[12] = x + y; arr[14] = x - y;
	  x = arr[13]; y = arr[15]; arr[13] = x + y; arr[15] = x - y;

	  x = arr[0]; y = arr[1]; arr[0] = x + y; arr[1] = x - y;
	  x = arr[2]; y = arr[3]; arr[2] = x + y; arr[3] = x - y;
	  x = arr[4]; y = arr[5]; arr[4] = x + y; arr[5] = x - y;
	  x = arr[6]; y = arr[7]; arr[6] = x + y; arr[7] = x - y;
	  x = arr[8]; y = arr[9]; arr[8] = x + y; arr[9] = x - y;
	  x = arr[10]; y = arr[11]; arr[10] = x + y; arr[11] = x - y;
	  x = arr[12]; y = arr[13]; arr[12] = x + y; arr[13] = x - y;
	  x = arr[14]; y = arr[15]; arr[14] = x + y; arr[15] = x - y;
	}

	public LSHBinner() {
		doubleBuffer = new double[16];
		k = -1;
		L = -1;
		tokenList = null;
	}

	public void setKandL(int k,int L) {
		this.k = k;
		this.L = L;
		int numBits = 1;
		while( (1 << numBits) <= L )
			numBits += 1;
		numBits += k;
		int numChar = numBits / 6;
		if ((numBits % 6)!= 0)
			numChar += 1;
		tokenList = new BytesRef[L];
		for(int i=0;i<L;++i) {
			tokenList[i] = new BytesRef(numChar);
		}
	}

	public BytesRef[] getTokenList() {
		return tokenList;
	}

	/**
	 * Generate a dot product of the hash vector in -vec- with a random family of 16 vectors, { r }
	 * r_0 is a randomly generated set of +1 -1 coefficients across all the dimensions (indexed by uint32 vec[i].hash)
	 *   The coefficient is calculated as a hashing function from the seed -hashcur- and the index (vec[i].hash),
	 *   so it should be balanced between +1 and -1.
	 * All the other vectors are generated from an FFT of r_0.  This allows the dotproduct with vec to be calculated
	 *   using an FFT if -vec- has many non-zero coefficients.  If -vec- has only a few non-zero coefficients,
	 *   the dotproduct if calculated with each vector in the family directly for better efficiency.
	 * The resulting dotproducts are converted into a 16-long bitvector based on the sign of the dotproduct and
	 *   placed in -bucket-
	 * @param bucket is the (possibly partially filled) accumulator for dotproduct bits
	 * @param vec is the HashEntry vector to calculate the dot-products on
	 * @param hashcur is the index of the hash subfamily to representing r_0
	 * @param res is space (a 16-long double array) for the in-place FFT
	 * @return the bucket with new accumulated dot-product bits
	 */
	private int hash16DotProduct(int bucket,HashEntry[] vec,int hashcur)

	{
		int i, j;
		int rowNum;
		int signPtr;

		for (i = 0; i < 16; ++i)
			doubleBuffer[i] = 0.0;							// Initialize the dotproduct results to zero

		if (vec.length < VEC_SIZE_UPPER) {					// If there are a small number of non-zero coefficients in -vec-
			for (i = 0; i < vec.length; ++i) {
				rowNum = vec[i].getHash() ^ hashcur;		// Calculate the rest of the r_0 hashing function
				rowNum = (rowNum * HASH_MULTIPLIER) + HASH_ADDEND;
				rowNum = (rowNum >>> 24) & 0x1f;
				signPtr = rowNum * 16;
				for (j = 0; j < 16; ++j) {				// Based on the precalculated coeff table calculate this portion of dotproduct
					if (hashSignTable[signPtr + j] == '+')
						doubleBuffer[j] += vec[i].getCoeff(); // Dot product with +1 // coeff
					else
						doubleBuffer[j] -= vec[i].getCoeff(); // Dot product with -1 // coeff
				}
			}
		}
		else {											// If we have many non-zero coefficients in -vec-
			for (i = 0; i < vec.length; ++i) {
				rowNum = vec[i].getHash() ^ hashcur;	// Calculate the rest of the r_0 hashing function
				rowNum = (rowNum * HASH_MULTIPLIER) + HASH_ADDEND;
				rowNum = (rowNum >>> 24) & 0x1f;
				if (rowNum < 0x10) // Set-up for the FFT
					doubleBuffer[rowNum] += vec[i].getCoeff();
				else
					doubleBuffer[rowNum & 0xf] -= vec[i].getCoeff();
			}
			hashFft16(doubleBuffer);					// Calculate the remaining dot-products be performing FFT
		}

		for (i = 0; i < 16; ++i) {						// Convert the dot-product results to a bit-vector
			bucket <<= 1;
			if (doubleBuffer[i] > 0.0)
				bucket |= 1;
		}
		return bucket;
	}

	public void generateBinIds(HashEntry[] vec)

	{
	  int bucket = 0;
	  int bucketcnt = 0;
	  int i,bitsleft;
	  int curid;
	  int mask,val;
	  int hashbase = LSH_HASHBASE;

		for (i = 0; i < L; ++i) {
			curid = i;				// Tack-on bits that indicate the particular table this bin id belongs to
			bitsleft = k;
			do {
				if (bucketcnt == 0) {
					hashbase = (hashbase * HASH_MULTIPLIER) + HASH_ADDEND;
					bucket = hash16DotProduct(bucket, vec, hashbase);
					bucketcnt += 16;
				}
				if (bucketcnt >= bitsleft) {
					curid <<= bitsleft;
					mask = 1;
					mask = (mask << bitsleft) - 1;
					val = bucket >>> (bucketcnt - bitsleft);
					curid |= (val & mask);
					bucketcnt -= bitsleft;
					bitsleft = 0;
				} else {
					curid <<= bucketcnt;
					mask = 1;
					mask = (mask << bucketcnt) - 1;
					curid |= (bucket & mask);
					bitsleft -= bucketcnt;
					bucketcnt = 0;
				}
			} while (bitsleft > 0);
			char[] token = tokenList[i].buffer;
			for(int j=0;j<token.length;++j) {
				token[j] = Base64Lite.encode[curid & 0x3f];		// encode 6 bits
				curid >>= 6;												// move to next 6 bits
			}
		}
	}
}
