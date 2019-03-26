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
package ghidra.app.plugin.core.format;

import java.math.BigInteger;

public interface ByteBlock {

	/**
	 * Get the location representation for the given index.
	 * @param index byte index into this block
	 * @throws IndexOutOfBoundsException if the given index is not in this
	 */
	public String getLocationRepresentation(BigInteger index);

	/**
	 * Returns the number of characters of the largest index representation.
	 */
	public int getMaxLocationRepresentationSize();

	/**
	 * Return the name to be used for describing the indexes into the
	 * byte block.
	 */
	public String getIndexName();

	/**
	 * Get the number of bytes in this block.
	 */
	public BigInteger getLength();

	/**
	 * Get the byte at the given index.
	 * @param index byte index
	 * @throws ByteBlockAccessException if the block cannot be read
	 * @throws IndexOutOfBoundsException if the given index is not in this
	 * block.
	 */
	public byte getByte(BigInteger index) throws ByteBlockAccessException;

	/**
	 * Returns true if this ByteBlock has byte values at the specified index.
	 *
	 * @param index byte index
	 * @return boolean true if has initialized values, false if no values.
	 */
	default public boolean hasValue(BigInteger index) {
		return true;
	}

	/**
	 * Get the int value at the given index.
	 * @param index byte index
	 * @throws ByteBlockAccessException if the block cannot be read
	 * @throws IndexOutOfBoundsException if the given index is not in this
	 * block.
	 */
	public int getInt(BigInteger index) throws ByteBlockAccessException;

	/**
	 * Get the long at the given index.
	 * @param index byte index
	 * @throws ByteBlockAccessException if the block cannot be read
	 * @throws IndexOutOfBoundsException if the given index is not in this
	 * block.
	 */
	public long getLong(BigInteger index) throws ByteBlockAccessException;

	/**
	 * Set the byte at the given index.
	 * @param index byte index
	 * @param value value to set
	 * @throws ByteBlockAccessException if the block cannot be updated
	 * @throws IndexOutOfBoundsException if the given index is not in this
	 * block.
	 */
	public void setByte(BigInteger index, byte value) throws ByteBlockAccessException;

	/**
	 * Set the int at the given index.
	 * @param index byte index
	 * @param value value to set
	 * @throws ByteBlockAccessException if the block cannot be updated
	 * @throws IndexOutOfBoundsException if the given index is not in this
	 * block.
	 */
	public void setInt(BigInteger index, int value) throws ByteBlockAccessException;

	/**
	 * Set the long at the given index.
	 * @param index byte index
	 * @param value value to set
	 * @throws ByteBlockAccessException if the block cannot be updated
	 * @throws IndexOutOfBoundsException if the given index is not in this
	 * block.
	 */
	public void setLong(BigInteger index, long value) throws ByteBlockAccessException;

	/**
	 * Return true if this block can be modified.
	 */
	public boolean isEditable();

	/**
	 * Set the block according to the bigEndian parameter.
	 * @param bigEndian true means big endian; false means little endian
	 */
	public void setBigEndian(boolean bigEndian);

	/**
	 * Return true if the block is big endian.
	 * @return false if the block is little endian
	 */
	public boolean isBigEndian();

	/**
	 * Returns the natural alignment (offset) for the given radix.  If there is
	 * no natural alignment, it should return 0.  A natural alignment only exists if
	 * there is some underlying indexing structure that isn't based at 0.  For example,
	 * if the underlying structure is address based and the starting address is not 0,
	 * then the natural alignment is the address offset mod the radix (if the starting
	 * address is 10 and the radix is 4, then then the alignment is 2)).
	 */
	public int getAlignment(int radix);
}
