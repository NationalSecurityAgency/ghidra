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

import ghidra.util.NumericUtilities;
import ghidra.util.exception.AssertException;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Class for representing register values that keep track of which bits are actually set.  
 * Values are stored as big-endian: MSB of mask is stored at bytes index 0,
 * MSB of value is stored at (bytes.length/2).
 * 
 * Bytes storage example for 4-byte register:
 *    Index:  0   1   2   3   4   5   6   7
 *          |MSB|   |   |LSB|MSB|   |   |LSB|
 *          | ----MASK----- | ----VALUE---- |
 * 
 */
public class RegisterValue {
	private static final int[] START_BYTE_MASK = new int[] { 0xFF, 0x7F, 0x3F, 0x1F, 0xF, 0x7, 0x3,
		0x1, 0 };
	private static final int[] END_BYTE_MASK = new int[] { 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC,
		0xFE, 0xFF };

	private byte[] bytes;
	private int startBit;
	private int endBit;
	private Register register;

	/**
	 * Creates a new RegisterValue for a register that has no value (all mask bits are 0);
	 * @param register the register associated with this value.
	 */
	public RegisterValue(Register register) {
		this.register = register;
		startBit = (register.getLeastSignificatBitInBaseRegister());
		endBit = startBit + register.getBitLength() - 1;
		byte[] mask = register.getBaseMask();
		bytes = new byte[mask.length * 2];
	}

	/**
	 * Constructs a new RegisterValue object for the given register and value.
	 * @param value the value to set. All mask bits for the given register are set to "valid" (on).
	 */
	public RegisterValue(Register register, BigInteger value) {
		this.register = register;
		byte[] mask = register.getBaseMask();
		startBit = register.getLeastSignificatBitInBaseRegister();
		endBit = startBit + register.getBitLength() - 1;
		value = value.shiftLeft(startBit);
		byte[] valueBytes = value.toByteArray();
		int lengthDiff = mask.length - valueBytes.length;

		byte signextend = (byte) ((value.signum() < 0) ? -1 : 0);

		bytes = new byte[mask.length * 2];
		int n = mask.length;
		for (int i = 0; i < mask.length; i++) {
			bytes[i] = mask[i];
			int valueByteIndex = i - lengthDiff;
			bytes[i + n] =
				valueByteIndex >= 0 ? (byte) (valueBytes[valueByteIndex] & mask[i]) : signextend;
		}
	}

	/**
	 * Constructs a new RegisterValue using a specified value and mask
	 * @param register
	 * @param value value corresponding to specified register
	 * @param mask value mask identifying which value bits are valid
	 */
	public RegisterValue(Register register, BigInteger value, BigInteger mask) {
		this(register, value);
		byte[] maskBytes = mask.shiftLeft(startBit).toByteArray();

		int baseMaskLen = bytes.length / 2;

		int maskIndex = maskBytes.length - 1;
		for (int i = baseMaskLen - 1; i >= 0; --i, --maskIndex) {
			if (maskIndex < 0) {
				bytes[i] = 0;
			}
			else {
				bytes[i] = maskBytes[maskIndex];
			}
			bytes[baseMaskLen + i] &= bytes[i];
		}

	}

	/**
	 * Constructs a new RegisterValue object for the given register and the mask/value byte array
	 * @param register the register associated with this value.  The register specifies which bits
	 * int the total mask/value arrays are used for this register which may be a sub-register of
	 * some larger register.  The byte[] always is sized for the largest Register that contains
	 * the given register.
	 * @param bytes the mask/value array - the first n/2 bytes are the mask and the last n/2 bytes
	 * are the value bits.
	 */
	public RegisterValue(Register register, byte[] bytes) {
		this.register = register;
		this.bytes = adjustBytes(register.getBaseRegister(), bytes);
		applyRegisterMask(register.getBaseMask());
		startBit = register.getLeastSignificatBitInBaseRegister();
		endBit = startBit + register.getBitLength() - 1;
	}

	private void applyRegisterMask(byte[] baseMask) {
		if (baseMask.length != (bytes.length / 2)) {
			throw new AssertException();
		}
		int valueOffset = baseMask.length;
		for (int i = 0; i < baseMask.length; i++) {
			bytes[i] &= baseMask[i];
			bytes[valueOffset + i] &= baseMask[i];
		}
	}

	private static byte[] adjustBytes(Register baseRegister, byte[] bytes) {
		int oldSize = bytes.length;
		byte[] baseMask = baseRegister.getBaseMask();
		int newSize = baseMask.length * 2;
		if (oldSize == newSize) {
			return bytes.clone();
		}

		byte[] newBytes = new byte[newSize];

		boolean isContext = baseRegister.isProcessorContext();

		int oldFieldLen = bytes.length / 2;
		int newFieldLen = baseMask.length;

		int keepLen = (oldSize < newSize) ? oldFieldLen : newFieldLen;

		int oldValIndex;
		int newValIndex;
		int oldMaskIndex;
		int newMaskIndex;

		if (isContext) {
			// processor context is left justified
			oldValIndex = oldFieldLen;
			newValIndex = newFieldLen;
			oldMaskIndex = 0;
			newMaskIndex = 0;
		}
		else {
			oldValIndex = oldSize - keepLen;
			newValIndex = newSize - keepLen;
			oldMaskIndex = oldFieldLen - keepLen;
			newMaskIndex = newFieldLen - keepLen;
			// TODO: if growing and old mask is all ff's set new upper mask bits
		}

		int maskFill = newMaskIndex;

		for (int i = 0; i < keepLen; i++) {
			byte maskByte = bytes[oldMaskIndex++];
			if (maskByte != (byte) 0xff) {
				maskFill = 0;
			}
			newBytes[newValIndex++] = (byte) (bytes[oldValIndex++] & maskByte);
			newBytes[newMaskIndex++] = maskByte;
		}

		for (int i = 0; i < maskFill; i++) {
			newBytes[i] = (byte) 0xff;
		}

		return newBytes;
	}

	/**
	 * Returns the register used in this register value object.
	 * @return the register used in this register value object
	 */
	public Register getRegister() {
		return register;
	}

	/**
	 * Creates a new RegisterValue. 
	 * The resulting value is a combination of this RegisterValue and the given RegisterValue,
	 * where the given RegisterValue's value bits take precedence over this RegisterValue's value. 
	 * 
	 * Each value bit is determined as follows: 
	 * If the mask bit in <code>otherValue</code> is "ON", then <code>otherValue</code>'s value bit is used. Otherwise,
	 * <code>this</code> value bit used.
	 * 
	 * The mask bits are OR'd together to form the new mask bits. 
	 * 
	 * @param otherValue the currently stored mask and value bytes.  The base register must match the base register 
	 * of this register value.
	 * @return a new RegisterValue object containing the original value bits where the new array 
	 * mask bits are "OFF" and the new value bits where the new array mask bits are "ON".
	 * If the registers differ the resulting register value will be relative to the base register.
	 */
	public RegisterValue combineValues(RegisterValue otherValue) {
		if (otherValue == null) {
			return this;
		}
		checkBaseRegister(otherValue.register);
		Register baseRegister = register.getBaseRegister();
		Register resultRegister = register;
		if (register != otherValue.getRegister()) {
			resultRegister = baseRegister;
		}

		byte[] resultBytes = new byte[otherValue.bytes.length];
		int n = bytes.length / 2;
		for (int i = 0; i < n; i++) {
			int mask = otherValue.bytes[i];
			int clearMask = ~mask;
			resultBytes[n + i] =
				(byte) ((otherValue.bytes[n + i] & mask) | (bytes[n + i] & clearMask));
			resultBytes[i] = (byte) (bytes[i] | otherValue.bytes[i]);
		}
		return new RegisterValue(resultRegister, resultBytes);
	}

	private void checkBaseRegister(Register reg) {
		Register baseRegister = register.getBaseRegister();
		if (reg.getBaseRegister() != baseRegister) {
			throw new IllegalArgumentException("Register " + reg.getName() +
				" does not share common base register " + baseRegister.getName());
		}
	}

	/**
	 * Returns this register value in terms of the base register
	 */
	public RegisterValue getBaseRegisterValue() {
		return new RegisterValue(register.getBaseRegister(), bytes);
	}

	/**
	 * Returns the value mask that indicates which bits relative to the base register have a
	 * valid value.
	 */
	public byte[] getBaseValueMask() {
		byte[] mask = register.getBaseMask();
		byte[] valueMask = new byte[mask.length];
		for (int i = 0; i < mask.length; i++) {
			valueMask[i] = (byte) (mask[i] & bytes[i]);
		}
		return valueMask;
	}

	/**
	 * Returns a value mask which is sized based upon the register
	 */
	public BigInteger getValueMask() {
		BigInteger valueMask = new BigInteger(1, getBaseValueMask());
		return valueMask.shiftRight(startBit);
	}

	/**
	 * Assign the value to a portion of this register value
	 * @param subRegister identifies a piece of this register value to be assigned
	 * @param value new value
	 * @return new register value after assignment
	 */
	public RegisterValue assign(Register subRegister, RegisterValue value) {
		checkBaseRegister(subRegister);
		RegisterValue otherValue =
			new RegisterValue(subRegister, value.getUnsignedValueIgnoreMask(), value.getValueMask());
		return combineValues(otherValue);
	}

	/**
	 * Assign the value to a portion of this register value
	 * @param subRegister identifies a piece of this register value to be assigned
	 * @param value new value
	 * @return new register value after assignment
	 */
	public RegisterValue assign(Register subRegister, BigInteger value) {
		checkBaseRegister(subRegister);
		RegisterValue otherValue = new RegisterValue(subRegister, value);
		return combineValues(otherValue);
	}

	/**
	 * Clears the value bits corresponding to the "ON" bits in the given mask.
	 * @param mask the byte array containing the mask bits to clear.
	 * @return a new MaskedBytes object containg the original value bits and mask bits cleared 
	 * where the passed in mask bits were "on".
	 */
	public RegisterValue clearBitValues(byte[] mask) {
		if (mask.length != bytes.length / 2) {
			throw new IllegalArgumentException(
				"Mask length must be the same length as this objects mask");
		}
		byte[] resultBytes = new byte[bytes.length];
		int n = mask.length;
		for (int i = 0; i < n; i++) {
			int clearMask = ~mask[i];
			resultBytes[n + i] = (byte) (bytes[n + i] & clearMask);
			resultBytes[i] = (byte) (bytes[i] & clearMask);
		}
		return new RegisterValue(register, resultBytes);
	}

	/**
	 * Returns the mask/value bytes for this register value.
	 * @return the mask/value bytes for this register value.
	 */
	public byte[] toBytes() {
		return bytes;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;

		result = prime * result + register.hashCode();
		result = prime * result + Arrays.hashCode(bytes);
		result = prime * result + startBit;
		result = prime * result + endBit;
		return result;
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (this == obj) {
			return true;
		}
		if (obj.getClass() != this.getClass()) {
			return false;
		}
		RegisterValue other = (RegisterValue) obj;
		return register == other.register && Arrays.equals(bytes, other.bytes);
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		int len = bytes.length / 2;
		String maskStr = NumericUtilities.convertBytesToString(bytes, 0, len, "");
		String valStr = NumericUtilities.convertBytesToString(bytes, len, len, "");
		return "RegisterValue(" + register.getName() + "): mask=0x" + maskStr + " value=0x" +
			valStr;
	}

	/**
	 * Tests if this RegisterValue contains valid value bits for the entire register.  In otherwords
	 * getSignedValue() or getUnsignedValue will not return null.
	 * @return true if all mask bits for the associated register are "ON".
	 */
	public boolean hasValue() {

		// translate bit positions to change 0 to mean the most significant bit for internal use
		int totalBitLength = bytes.length * 4;
		int start = totalBitLength - endBit - 1;
		int end = totalBitLength - startBit - 1;

		int startByte = start / 8;
		int endByte = end / 8;
		int bitInStartByte = start % 8;
		int bitInEndByte = end % 8;

		if (startByte == endByte) {
			int mask = START_BYTE_MASK[bitInStartByte] & END_BYTE_MASK[bitInEndByte];
			return (bytes[startByte] & mask) == mask;
		}

		if ((bytes[startByte] & START_BYTE_MASK[bitInStartByte]) != START_BYTE_MASK[bitInStartByte]) {
			return false;
		}

		if ((bytes[endByte] & END_BYTE_MASK[bitInEndByte]) != END_BYTE_MASK[bitInEndByte]) {
			return false;
		}

		for (int i = startByte + 1; i < endByte; i++) {
			if (bytes[i] != -1) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Returns the unsigned value for this register if all the appropriate mask bits are "ON". Otherwise,
	 * null is return.
	 * @return the value for this register if all the appropriate mask bits are "ON". Otherwise,
	 * returns null.
	 */
	public BigInteger getUnsignedValue() {
		if (isMaskOn()) {
			return getUnsignedValueIgnoreMask();
		}
		return null;
	}

	/**
	 * Returns the unsigned value for this register regardless of the mask bits.  Bits that have "OFF" mask
	 * bits will have the value of 0.
	 * @return the unsigned value for this register regardless of the mask bits.  Bits that have "OFF" mask
	 * bits will have the value of 0.
	 */
	public BigInteger getUnsignedValueIgnoreMask() {
		// translate bit positions to change 0 to mean the most significant bit for internal use
		int totalBitLength = bytes.length * 4;
		int start = totalBitLength - endBit - 1;
		int end = totalBitLength - startBit - 1;

		int numBits = end - start + 1;
		int size = (end - start) / 8 + 1;
		int extraBytes = 0;

		// see if we need an extra byte of zeros so that it is treated
		// as unsigned by BigInteger
		if (size * 8 == numBits && getBit(start) == 1) {
			extraBytes = 1;
		}
		byte[] result = new byte[size + extraBytes];

		int endByte = end / 8 + bytes.length / 2;
		int bitInEndByte = end % 8;

		int lowShift = 7 - bitInEndByte;
		int highShift = bitInEndByte + 1;

		int highByteMask = START_BYTE_MASK[size * 8 - (end - start + 1)];

		for (int i = size - 1; i >= 0; i--) {
			int lowPart = (bytes[endByte] & END_BYTE_MASK[bitInEndByte]) >>> lowShift;
			int highPart = (bytes[endByte - 1] & START_BYTE_MASK[bitInEndByte + 1]) << highShift;
			result[i + extraBytes] = (byte) (highPart | lowPart);
			if (i == 0) {
				result[i + extraBytes] = (byte) (result[i + extraBytes] & highByteMask);
			}
			endByte--;
		}

		return new BigInteger(result);
	}

	/**
	 * Returns the signed value for this register if all the appropriate mask bits are "ON". Otherwise,
	 * null is return.
	 * @return the signed value for this register if all the appropriate mask bits are "ON". Otherwise,
	 * returns null.
	 */
	public BigInteger getSignedValue() {
		if (isMaskOn()) {
			return getSignedValueIgnoreMask();
		}
		return null;
	}

	/**
	 * Returns the signed value for this register regardless of the mask bits.  Bits that have "OFF" mask
	 * bits will have the value of 0.
	 * @return the signed value for this register regardless of the mask bits.  Bits that have "OFF" mask
	 * bits will have the value of 0.
	 */
	public BigInteger getSignedValueIgnoreMask() {
		// translate bit positions to change 0 to mean the most significant bit for internal use
		int totalBitLength = bytes.length * 4;
		int start = totalBitLength - endBit - 1;
		int end = totalBitLength - startBit - 1;

		int size = (end - start) / 8 + 1;
		byte[] result = new byte[size];

		int endByte = end / 8 + bytes.length / 2;
		int bitInEndByte = end % 8;

		int lowShift = 7 - bitInEndByte;
		int highShift = bitInEndByte + 1;

		for (int i = size - 1; i >= 0; i--) {
			int lowPart = (bytes[endByte] & END_BYTE_MASK[bitInEndByte]) >>> lowShift;
			int highPart = (bytes[endByte - 1] & START_BYTE_MASK[bitInEndByte + 1]) << highShift;
			result[i] = (byte) (highPart | lowPart);
			if (i == 0) {
				if (getBit(start) == 1) {
					result[i] = (byte) (result[i] | END_BYTE_MASK[size * 8 - (end - start + 1)]);
				}
				else {
					result[i] = (byte) (result[i] & START_BYTE_MASK[size * 8 - (end - start + 1)]);
				}
			}
			endByte--;
		}

		return new BigInteger(result);
	}

	private int getBit(int bitIndex) {
		int byteIndex = bitIndex / 8;
		int bitInByte = bitIndex % 8;

		int value = bytes[byteIndex + bytes.length / 2];
		value = value & START_BYTE_MASK[bitInByte] & END_BYTE_MASK[bitInByte];
		if (value == 0) {
			return 0;
		}
		return 1;
	}

	/**
	 * Tests if the all the mask bits from startBit (least significant bit) to endBit (most significant bit)
	 * are on.
	 * @param startBit the least significant bit position 
	 * @param endBit the most significant bit position
	 * @return true if all mask bits from startBit to endBit are on.
	 */
	private boolean isMaskOn() {
		// translate bit positions to change 0 to mean the most significant bit for internal use
		int totalBitLength = bytes.length * 4;
		int start = totalBitLength - endBit - 1;
		int end = totalBitLength - startBit - 1;

		int startByte = start / 8;
		int endByte = end / 8;
		int bitInStartByte = start % 8;
		int bitInEndByte = end % 8;

		if (startByte == endByte) {
			int mask = START_BYTE_MASK[bitInStartByte] & END_BYTE_MASK[bitInEndByte];
			return (bytes[startByte] & mask) == mask;
		}

		if ((bytes[startByte] & START_BYTE_MASK[bitInStartByte]) != START_BYTE_MASK[bitInStartByte]) {
			return false;
		}

		if ((bytes[endByte] & END_BYTE_MASK[bitInEndByte]) != END_BYTE_MASK[bitInEndByte]) {
			return false;
		}
		for (int i = startByte + 1; i < endByte; i++) {
			if (bytes[i] != -1) {
				return false;
			}
		}

		return true;
	}

	private static boolean isMaskAllOn(byte[] bytes) {
		int cnt = bytes.length / 2;
		for (int i = 0; i < cnt; i++) {
			if (bytes[i] != -1) {
				return false;
			}
		}
		return true;
	}

	public boolean hasAnyValue() {
		int byteLength = bytes.length / 2;
		for (int i = 0; i < byteLength; i++) {
			if (bytes[i] != 0) {
				return true;
			}
		}
		return false;
	}

	public RegisterValue getRegisterValue(Register newRegister) {
		if (register == newRegister) {
			return this;
		}
		checkBaseRegister(newRegister);
		return new RegisterValue(newRegister, bytes);

	}

}
