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

import ghidra.program.model.address.Address;

import java.math.BigInteger;

/**
 * Info about a byte block edit.
 * 
 * 
 */
public class ByteEditInfo {

	private Address blockStartAddr;
	private BigInteger offset;
	private byte[] oldValue;
	private byte[] newValue;

	/**
	 * Construct a new byte edit info 
	 * @param blockStartAddr starting address of the block
	 * @param offset offset into the block
	 * @param oldValue old value of the bytes
	 * @param newValue new value of the bytes
	 */
	public ByteEditInfo(Address blockStartAddr, BigInteger offset, byte[] oldValue, byte[] newValue) {

		this.blockStartAddr = blockStartAddr;
		this.offset = offset;
		this.oldValue = oldValue;
		this.newValue = newValue;
	}

	/**
	 * Get the old value.
	 */
	public byte[] getOldValue() {
		return oldValue;
	}

	/**
	 * Get the new value.
	 */
	public byte[] getNewValue() {
		return newValue;
	}

	/**
	 * Get the block offset.
	 */
	public BigInteger getOffset() {
		return offset;
	}

	/**
	 * Get the block address
	 */
	public Address getBlockAddress() {
		return blockStartAddr;
	}

}
