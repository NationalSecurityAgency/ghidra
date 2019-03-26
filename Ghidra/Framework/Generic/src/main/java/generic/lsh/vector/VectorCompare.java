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
package generic.lsh.vector;

/**
 * Class for containing intermediate results of doing the LSHVector compare operation
 *
 */
public class VectorCompare {

	public double dotproduct;		// Result of the dot product
	public int acount;				// total number of hashes in first vector
	public int bcount;				// total number of hashes in second vector
	public int intersectcount;		// total number of hashes in common
	public int min;				// Minimum vector count
	public int max;				// Maximum vector count
	public int numflip;			// Number of hashes flipped
	public int diff;			// Difference in number of hashes

	/**
	 * Assume the dotproduct, acount, bcount, and intersectcount are filled in
	 * Calculate the remaining values: min, max, numflip, and diff
	 * Assume small vector is produced by flipping and removing hashes from big vector
	 * Calculate the number of flipped hashes (numflip) from a VectorCompare result
	 * Calculate the difference in the number of hashes (diff) from a VectorCompare result
	 */
	public void fillOut() {
		if (acount < bcount) {
			min = acount;			// Smallest vector is a
			max = bcount;
		}
		else {
			min = bcount;			// Smallest vector is b
			max = acount;
		}
		diff = max - min;			// Subtract to get a positive difference
		numflip = min - intersectcount;	// Number of hashes in smallest vector not in intersection
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("\nVectorCompare: ");
		buffer.append("\n  Result of the dot product     = " + dotproduct);
		buffer.append("\n  # of hashes in first vector   = " + acount);
		buffer.append("\n  # of hashes in second vector  = " + bcount);
		buffer.append("\n  # of hashes in common         = " + intersectcount);
		buffer.append("\n  Minimum vector count          = " + min);
		buffer.append("\n  Maximum vector count          = " + max);
		buffer.append("\n  Number of hashes flipped      = " + numflip);
		buffer.append("\n  Difference in # of hashes     = " + diff);
		return buffer.toString();
	}
}
