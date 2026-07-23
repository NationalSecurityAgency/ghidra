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
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

/**
 * Contains the mask/value information for a single mnemonic or operand.
 */
public class MaskContainer {

	private byte[] mask;
	private byte[] value;

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

	public byte[] getMask() {
		return mask;
	}

	public String getMaskAsBinaryString() {
		StringBuilder str = new StringBuilder();

		for (byte element : mask) {
			str.append(InstructionSearchUtils.toBinaryString(element));
		}

		return str.toString();
	}

	public void setMask(byte[] mask) {
		this.mask = mask;
	}

	public byte[] getValue() {
		return value;
	}

	public String getValueAsBinaryString() {
		StringBuilder str = new StringBuilder();

		for (byte element : value) {
			str.append(InstructionSearchUtils.toBinaryString(element));
		}

		return str.toString();
	}

	public void setValue(byte[] value) {
		this.value = value;
	}

	public String toBinaryString() {

		StringBuilder valueString = new StringBuilder();
		StringBuilder maskString = new StringBuilder();

		for (byte element : value) {
			valueString.append(InstructionSearchUtils.toBinaryString(element));
		}
		for (byte element : mask) {
			maskString.append(InstructionSearchUtils.toBinaryString(element));
		}

		String combinedString = "";
		try {
			combinedString = InstructionSearchUtils.formatSearchString(valueString.toString(),
				maskString.toString());
		}
		catch (InvalidInputException e) {
			Msg.error(this, e.getMessage(), e);
		}

		return combinedString;
	}
}
