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

/**
 * Class to hold block and offset into the block.
 */
public class ByteBlockInfo {

	private ByteBlock block;
	private BigInteger offset;
	private int column;

	public ByteBlockInfo(ByteBlock block, BigInteger offset) {
		this(block, offset, 0);
	}

	public ByteBlockInfo(ByteBlock block, BigInteger offset, int column) {
		this.block = block;
		this.offset = offset;
		this.column = column;
	}

	/**
	 * Get the block
	 * @return the block
	 */
	public ByteBlock getBlock() {
		return block;
	}

	/**
	 * Get the offset into the block.
	 * @return the offset
	 */
	public BigInteger getOffset() {
		return offset;
	}

	/**
	 * The the column within the UI byte field
	 * @return the column
	 */
	public int getColumn() {
		return column;
	}

	/**
	 * Return string representation for debugging purposes.
	 */
	@Override
	public String toString() {
		return "ByteBlockInfo: block start=" + block.getLocationRepresentation(BigInteger.ZERO) +
			", offset=" + offset + ", column=" + column;
	}

	@Override
	public int hashCode() {
		return block.hashCode() + offset.hashCode() + column;
	}

	@Override
	public boolean equals(Object other) {

		if (other == null) {
			return false;
		}
		if (other == this) {
			return true;
		}

		if (getClass() != other.getClass()) {
			return false;
		}

		ByteBlockInfo info = (ByteBlockInfo) other;
		return block == info.block && offset.equals(info.offset) && column == info.column;
	}
}
