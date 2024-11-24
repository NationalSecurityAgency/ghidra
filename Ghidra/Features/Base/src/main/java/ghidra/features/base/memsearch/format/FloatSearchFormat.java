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
package ghidra.features.base.memsearch.format;

import java.util.StringTokenizer;

import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.matcher.*;
import ghidra.util.HTMLUtilities;

/**
 * {@link SearchFormat} for parsing and display bytes in a float or double format. 
 */
class FloatSearchFormat extends SearchFormat {
	private String longName;
	private int byteSize;

	FloatSearchFormat(String name, String longName, int size) {
		super(name);
		if (size != 8 && size != 4) {
			throw new IllegalArgumentException("Only supports 4 or 8 byte floating point numbers");
		}
		this.longName = longName;
		this.byteSize = size;
	}

	@Override
	public ByteMatcher parse(String input, SearchSettings settings) {
		input = input.trim();
		if (input.isBlank()) {
			return new InvalidByteMatcher("");
		}

		StringTokenizer tokenizer = new StringTokenizer(input);
		int tokenCount = tokenizer.countTokens();
		byte[] bytes = new byte[tokenCount * byteSize];
		int bytesPosition = 0;
		while (tokenizer.hasMoreTokens()) {
			String tok = tokenizer.nextToken();
			NumberParseResult result = parseNumber(tok, settings);
			if (result.errorMessage() != null) {
				return new InvalidByteMatcher(result.errorMessage(), result.validInput());
			}
			System.arraycopy(result.bytes(), 0, bytes, bytesPosition, byteSize);
			bytesPosition += byteSize;
		}
		return new MaskedByteSequenceByteMatcher(input, bytes, settings);
	}

	private NumberParseResult parseNumber(String tok, SearchSettings settings) {
		if (tok.equals("-") || tok.equals("-.")) {
			return new NumberParseResult(null, "Incomplete negative floating point number", true);
		}
		if (tok.equals(".")) {
			return new NumberParseResult(null, "Incomplete floating point number", true);
		}
		if (tok.endsWith("E") || tok.endsWith("e") || tok.endsWith("E-") || tok.endsWith("e-")) {
			return new NumberParseResult(null, "Incomplete floating point number", true);
		}
		try {
			long value = getValue(tok);
			return new NumberParseResult(getBytes(value, settings), null, true);

		}
		catch (NumberFormatException e) {
			return new NumberParseResult(null, "Floating point parse error: " + e.getMessage(),
				false);
		}
	}

	private long getValue(String tok) {
		switch (byteSize) {
			case 4:
				float floatValue = Float.parseFloat(tok);
				return Float.floatToIntBits(floatValue);
			case 8:
			default:
				double dvalue = Double.parseDouble(tok);
				return Double.doubleToLongBits(dvalue);
		}
	}

	private byte[] getBytes(long value, SearchSettings settings) {
		byte[] bytes = new byte[byteSize];
		for (int i = 0; i < byteSize; i++) {
			byte b = (byte) value;
			bytes[i] = b;
			value >>= 8;
		}
		if (settings.isBigEndian()) {
			reverse(bytes);
		}
		return bytes;
	}

	@Override
	public String getToolTip() {
		return HTMLUtilities.toHTML(
			"Interpret values as a sequence of\n" + longName + " numbers, separated by spaces");
	}

	@Override
	public int compareValues(byte[] bytes1, byte[] bytes2, SearchSettings settings) {
		boolean isBigEndian = settings.isBigEndian();
		// check each value one at a time, and return the first one different
		for (int i = 0; i < bytes1.length / byteSize; i++) {
			double value1 = getValue(bytes1, i, isBigEndian);
			double value2 = getValue(bytes2, i, isBigEndian);
			if (value1 != value2) {
				return Double.compare(value1, value2);
			}
		}
		return 0;
	}

	public Double getValue(byte[] bytes, int index, boolean isBigEndian) {
		long bits = fromBytes(bytes, index, isBigEndian);
		switch (byteSize) {
			case 4:
				float f = Float.intBitsToFloat((int) bits);
				return (double) f;
			case 8:
			default:
				return Double.longBitsToDouble(bits);
		}
	}

	private long fromBytes(byte[] bytes, int index, boolean isBigEndian) {
		byte[] bigEndianBytes = new byte[byteSize];
		System.arraycopy(bytes, index * byteSize, bigEndianBytes, 0, byteSize);
		if (!isBigEndian) {
			reverse(bigEndianBytes);
		}

		long value = 0;
		for (int i = 0; i < bigEndianBytes.length; i++) {
			value = (value << 8) | (bigEndianBytes[i] & 0xff);
		}
		return value;
	}

	@Override
	public String getValueString(byte[] bytes, SearchSettings settings) {
		StringBuilder buffer = new StringBuilder();
		int numValues = bytes.length / byteSize;
		for (int i = 0; i < numValues; i++) {
			double value = getValue(bytes, i, settings.isBigEndian());
			buffer.append(Double.toString(value));
			if (i != numValues - 1) {
				buffer.append(", ");
			}
		}
		return buffer.toString();
	}

	@Override
	public String convertText(String text, SearchSettings oldSettings, SearchSettings newSettings) {
		SearchFormat oldFormat = oldSettings.getSearchFormat();
		switch (oldFormat.getFormatType()) {
			case BYTE:
				return getTextFromBytes(text, oldFormat, oldSettings);
			case FLOATING_POINT:
			case STRING_TYPE:
			case INTEGER:
			default:
				return isValidText(text, newSettings) ? text : "";

		}
	}

	private String getTextFromBytes(String text, SearchFormat oldFormat, SearchSettings settings) {
		ByteMatcher byteMatcher = oldFormat.parse(text, settings);
		if ((byteMatcher instanceof MaskedByteSequenceByteMatcher matcher)) {
			byte[] bytes = matcher.getBytes();
			if (bytes.length >= byteSize) {
				String valueString = getValueString(bytes, settings);
				return valueString.replaceAll(",", "");
			}
		}
		return isValidText(text, settings) ? text : "";
	}

	@Override
	public SearchFormatType getFormatType() {
		return SearchFormatType.FLOATING_POINT;
	}
}
