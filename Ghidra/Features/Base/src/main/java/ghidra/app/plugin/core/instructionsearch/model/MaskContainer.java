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
package ghidra.app.plugin.core.instructionsearch.model;

import ghidra.app.plugin.core.instructionsearch.util.InstructionSearchUtils;
import ghidra.util.exception.InvalidInputException;

/**
 * Contains the mask/value information for a single mnemonic or operand.
 */
public class MaskContainer {

	private byte[] mask;
	private byte[] value;

	/**
	 * 
	 * @param mask
	 * @param value
	 * @throws InvalidInputException
	 */
	public MaskContainer(byte[] mask, byte[] value) throws IllegalArgumentException {

		// Mask and value arrays must be the same size, and not be null. 
		if (mask == null || value == null) {
			throw new IllegalArgumentException(
				"Mask container initialization error: mask and/or value arrays cannot be null");
		}

		if (mask.length != value.length) {
			throw new IllegalArgumentException(
				"Mask container initialization error: mask/value arrays must be the same size");
		}
		this.mask = mask;
		this.value = value;
	}

	/**
	 * @return the mask
	 */
	public byte[] getMask() {
		return mask;
	}

	/**
	 * 
	 * @return
	 */
	public String getMaskAsBinaryString() {
		StringBuilder str = new StringBuilder();

		for (int i = 0; i < mask.length; i++) {
			str.append(InstructionSearchUtils.toBinaryString(mask[i]));
		}

		return str.toString();
	}

	/**
	 * @param mask the mask to set
	 */
	public void setMask(byte[] mask) {
		this.mask = mask;
	}

	/**
	 * @return the value
	 */
	public byte[] getValue() {
		return value;
	}

	/**
	 * 
	 * @return
	 */
	public String getValueAsBinaryString() {
		StringBuilder str = new StringBuilder();

		for (int i = 0; i < value.length; i++) {
			str.append(InstructionSearchUtils.toBinaryString(value[i]));
		}

		return str.toString();
	}

	/**
	 * @param value the value to set
	 */
	public void setValue(byte[] value) {
		this.value = value;
	}

	/**
	 * Returns the bytes and masking merged together, as a binary string.
	 * 
	 * @param mask
	 * @param value
	 * @return list containing the value (index 0) and mask (index 1).
	 */
	public String toBinaryString() {

		StringBuilder valueString = new StringBuilder();
		StringBuilder maskString = new StringBuilder();

		for (int i = 0; i < value.length; i++) {
			valueString.append(InstructionSearchUtils.toBinaryString(value[i]));
		}
		for (int i = 0; i < mask.length; i++) {
			maskString.append(InstructionSearchUtils.toBinaryString(mask[i]));
		}

		String combinedString = "";
		try {
			combinedString = InstructionSearchUtils.formatSearchString(valueString.toString(),
				maskString.toString());
		}
		catch (InvalidInputException e) {
			e.printStackTrace();
		}

		return combinedString;
	}
}
