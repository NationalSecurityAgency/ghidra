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
package ghidra.app.plugin.core.searchmem.mask;

/**
 * Stores information about the instruction and mask.
 * 
 */
class MaskValue {
	private byte[] mask;
	private byte[] value;
	private String textRepresentation;

	/**
	 * Constructor.
	 * 
	 * @param mask
	 * @param value
	 */
	public MaskValue(byte[] mask, byte[] value) {
		this.mask = mask;
		this.value = value;
	}

	/**
	 * Constructor.
	 * 
	 * @param mask
	 * @param value
	 * @param textRepresentation
	 */
	public MaskValue(byte[] mask, byte[] value, String textRepresentation) {
		this.mask = mask;
		this.value = value;
		this.textRepresentation = textRepresentation;
	}

	/**
	 * 
	 */
	@Override
	public String toString() {
		String rep = textRepresentation == null ? "" : textRepresentation;
		return getClass().getSimpleName() + " - " + rep + " [mask=" + mask + ", value=" + value +
			"]";
	}

	/**
	 * Performs a bitwise OR on the given byte array and mask.  Results are stored internally in
	 * the 'mask' object.
	 * 
	 * @param other
	 */
	public void orMask(byte[] other) {
		if (mask == null) {
			return;
		}

		mask = byteArrayOr(mask, other);
	}

	/**
	 * Performs a bitwise OR on the given byte array and instruction value.  Results are stored internally
	 * in the 'value' object.
	 * 
	 * @param other
	 */
	public void orValue(byte[] other) {
		if (value == null) {
			return;
		}
		value = byteArrayOr(value, other);
	}

	/**
	 * Takes two byte arrays and performs a bitwise OR on them.  The arrays must be of the same length.
	 * 
	 * @param arr1
	 * @param arr2
	 * @return null if the inputs are not valid
	 */
	private byte[] byteArrayOr(byte[] arr1, byte[] arr2) {
		byte[] result = new byte[arr1.length];

		if (arr1.length != arr2.length) {
			return null;
		}

		for (int x = 0; x < arr1.length; x++) {
			result[x] = (byte) (arr1[x] | arr2[x]);
		}

		return result;
	}
	
	public void setMask(byte[] mask) {
		this.mask = mask;
	}

	public void setValue(byte[] value) {
		this.value = value;
	}

	public byte[] getValue() {
		return value;
	}

	public byte[] getMask() {
		return mask;
	}
}
