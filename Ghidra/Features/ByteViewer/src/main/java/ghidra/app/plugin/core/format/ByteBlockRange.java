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
package ghidra.app.plugin.core.format;

import java.math.BigInteger;

/**
 * Class to define a range within a byte block.
 */
public class ByteBlockRange {

	private ByteBlock block;
	private BigInteger startIndex;
	private BigInteger endIndex;

	/**
	 * Constructor
	 */
	public ByteBlockRange(ByteBlock block, BigInteger startIndex, BigInteger endIndex) {
		this.block = block;
		this.startIndex = startIndex;
		this.endIndex = endIndex;
	}

	/**
	 * Get the byte block.
	 */
	public ByteBlock getByteBlock() {
		return block;
	}

	/**
	 * Get the start index for the range.
	 */
	public BigInteger getStartIndex() {
		return startIndex;
	}

	/**
	 * Get the end index (inclusive) for the range.
	 * 
	 * @return int
	 */
	public BigInteger getEndIndex() {
		return endIndex;
	}

	/**
	 * Indicates whether some other object is "equal to" this one.
	 * <p>
	 * The <tt>equals</tt> method for class <code>Object</code> implements
	 * the most discriminating possible equivalence relation on objects;
	 * that is, for any reference values <code>x</code> and <code>y</code>,
	 * this method returns <code>true</code> if and only if <code>x</code> and
	 * <code>y</code> refer to the same object (<code>x==y</code> has the
	 * value <code>true</code>).
	 *
	 * @param   obj   the reference object with which to compare.
	 * @return  <code>true</code> if this object is the same as the obj
	 *          argument; <code>false</code> otherwise.
	 * @see     java.lang.Boolean#hashCode()
	 * @see     java.util.Hashtable
	 */
	@Override
	public boolean equals(Object obj) {

		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}
		ByteBlockRange r = (ByteBlockRange) obj;

		return block == r.block && startIndex.equals(r.startIndex) && endIndex.equals(r.endIndex);
	}

	/**
	 * Returns a hash code value for the object. This method is
	 * supported for the benefit of hashtables such as those provided by
	 * <code>java.util.Hashtable</code>.
	 * <p>
	 *
	 * @return  a hash code value for this object.
	 */
	@Override
	public int hashCode() {
		return block.hashCode() + startIndex.hashCode() + endIndex.hashCode();
	}

	/**
	 * Return string representation for debugging purposes.
	 */
	@Override
	public String toString() {
		return "Block at " + block.getLocationRepresentation(BigInteger.ZERO) + ", startIndex=> " +
			startIndex + ", endIndex => " + endIndex;
	}

}
