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
package ghidra.program.model.lang;

import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

import java.io.Serializable;

/**
 * Implements the Mask interface as a byte array.
 */
public class MaskImpl implements Mask, Serializable {
	private final static long serialVersionUID = 1;

	private byte[] mask;

	/**
	* Construct a mask from a byte array.
	*
	* @param msk the bits that make up the mask.
	*/

	public MaskImpl(byte[] msk) {
		if (msk == null)
			throw new IllegalArgumentException();
		mask = new byte[msk.length];
		System.arraycopy(msk, 0, mask, 0, msk.length);
	}

	/**
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof Mask) {
			return equals(((Mask) obj).getBytes());
		}
		return false;

	}

	/**
	 * 
	 * @see ghidra.program.model.lang.Mask#equals(byte[])
	 */
	public boolean equals(byte[] otherMask) {
		if (otherMask == null || otherMask.length != mask.length) {
			return false;
		}

		for (int i = 0; i < mask.length; i++) {
			if (mask[i] != otherMask[i])
				return false;
		}

		return true;
	}

	/**
	 * 
	 * @see ghidra.program.model.lang.Mask#applyMask(byte[], byte[])
	 */
	public byte[] applyMask(byte[] cde, byte[] result) throws IncompatibleMaskException {
		if ((cde == null) || (result == null))
			throw new IncompatibleMaskException();
		if ((cde.length < mask.length) || (result.length < cde.length))
			throw new IncompatibleMaskException();
		for (int i = 0; i < mask.length; i++)
			result[i] = (byte) (mask[i] & cde[i]);
		for (int i = mask.length; i < cde.length; i++)
			result[i] = cde[i];
		return result;
	}

	@Override
	public void applyMask(byte[] cde, int cdeOffset, byte[] results, int resultsOffset)
			throws IncompatibleMaskException {
		if ((cde == null) || (results == null))
			throw new IncompatibleMaskException();
		if ((cde.length - cdeOffset < mask.length) ||
			(results.length - resultsOffset < mask.length))
			throw new IncompatibleMaskException();
		for (int i = 0; i < mask.length; i++)
			results[resultsOffset++] = (byte) (mask[i] & cde[cdeOffset++]);
	}

	/**
	 * @see ghidra.program.model.lang.Mask#applyMask(ghidra.program.model.mem.MemBuffer)
	 */
	public byte[] applyMask(MemBuffer buffer) throws MemoryAccessException {
		byte[] bytes = new byte[mask.length];
		buffer.getBytes(bytes, 0);
		for (int i = 0; i < mask.length; i++) {
			bytes[i] &= mask[i];
		}
		return bytes;
	}

	/**
	 * 
	 * @see ghidra.program.model.lang.Mask#equalMaskedValue(byte[], byte[])
	 */
	public boolean equalMaskedValue(byte[] cde, byte[] target) throws IncompatibleMaskException {
		if ((cde == null) || (target == null))
			throw new IncompatibleMaskException();
		if ((cde.length < mask.length) || (target.length < mask.length))
			throw new IncompatibleMaskException();
		for (int i = 0; i < mask.length; i++)
			if (target[i] != (byte) (mask[i] & cde[i]))
				return false;
		return true;
	}

	/**
	 * 
	 * @see ghidra.program.model.lang.Mask#subMask(byte[])
	 */
	public boolean subMask(byte[] msk) throws IncompatibleMaskException {
		if (msk == null)
			throw new IncompatibleMaskException();
		if (mask.length < msk.length)
			return false;
		for (int i = 0; i < msk.length; i++) {
			byte b = mask[i];
			b ^= 0x0ff;
			b &= msk[i];
			if (0 != b)
				return false;
		}
		return true;
	}

	/**
	 * 
	 * @see ghidra.program.model.lang.Mask#complementMask(byte[], byte[])
	 */
	public byte[] complementMask(byte[] msk, byte[] results) throws IncompatibleMaskException {
		if ((msk == null) || (results == null))
			throw new IncompatibleMaskException();
		if ((results.length < mask.length) || (results.length < msk.length))
			throw new IncompatibleMaskException();
		int k = mask.length;
		if (k < msk.length)
			k = msk.length;
		byte b;
		for (int i = 0; i < k; i++) {
			if (i < mask.length)
				b = (byte) (mask[i] ^ 0xff);
			else
				b = (byte) 0xff;
			if (i < msk.length)
				b &= msk[i];
			else
				b = 0;
			results[i] = b;
		}
		return results;
	}

	/**
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		int b;
		String s = "", t;
		for (int i = 0; i < mask.length; i++) {
			b = 0x0ff & mask[i];
			t = Integer.toString(b, 16);
			if (1 == t.length())
				t = "0" + t;
			s += t;
		}
		return s.toUpperCase();
	}

	/**
	 * 
	 * @see ghidra.program.model.lang.Mask#getBytes()
	 */
	public byte[] getBytes() {
		return mask;
	}
}
