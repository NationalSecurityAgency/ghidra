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

import java.math.BigInteger;
import java.util.StringTokenizer;

import org.bouncycastle.util.Arrays;

import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.matcher.*;
import ghidra.util.HTMLUtilities;

/**
 * {@link SearchFormat} for parsing and display bytes in a decimal format. It supports sizes of
 * 2,4,8,16 and can be either signed or unsigned.
 */
class DecimalSearchFormat extends SearchFormat {

	DecimalSearchFormat() {
		super("Decimal");
	}

	@Override
	public ByteMatcher parse(String input, SearchSettings settings) {
		input = input.trim();
		if (input.isBlank()) {
			return new InvalidByteMatcher("");
		}
		int byteSize = settings.getDecimalByteSize();
		StringTokenizer tokenizer = new StringTokenizer(input);
		int tokenCount = tokenizer.countTokens();
		byte[] bytes = new byte[tokenCount * byteSize];
		int bytesPosition = 0;
		while (tokenizer.hasMoreTokens()) {
			String token = tokenizer.nextToken();
			NumberParseResult result = parseNumber(token, settings);
			if (result.errorMessage() != null) {
				return new InvalidByteMatcher(result.errorMessage(), result.validInput());
			}
			System.arraycopy(result.bytes(), 0, bytes, bytesPosition, byteSize);
			bytesPosition += byteSize;
		}
		return new MaskedByteSequenceByteMatcher(input, bytes, settings);
	}

	private NumberParseResult parseNumber(String tok, SearchSettings settings) {
		BigInteger min = getMin(settings);
		BigInteger max = getMax(settings);
		try {
			if (tok.equals("-")) {
				if (settings.isDecimalUnsigned()) {
					return new NumberParseResult(null,
						"Negative numbers not allowed for unsigned values", false);
				}
				return new NumberParseResult(null, "Incomplete negative number", true);
			}
			BigInteger value = new BigInteger(tok);
			if (value.compareTo(min) < 0 || value.compareTo(max) > 0) {
				return new NumberParseResult(null,
					"Number must be in the range [" + min + ", " + max + "]", false);
			}
			long longValue = value.longValue();
			return createBytesResult(longValue, settings);
		}
		catch (NumberFormatException e) {
			return new NumberParseResult(null, "Number parse error: " + e.getMessage(), false);
		}
	}

	private BigInteger getMax(SearchSettings settings) {
		boolean unsigned = settings.isDecimalUnsigned();
		int size = settings.getDecimalByteSize();
		int shift = unsigned ? 8 * size : 8 * size - 1;
		return BigInteger.ONE.shiftLeft(shift).subtract(BigInteger.ONE);
	}

	private BigInteger getMin(SearchSettings settings) {
		boolean unsigned = settings.isDecimalUnsigned();
		int size = settings.getDecimalByteSize();
		if (unsigned) {
			return BigInteger.ZERO;
		}
		return BigInteger.ONE.shiftLeft(8 * size - 1).negate();
	}

	private NumberParseResult createBytesResult(long value, SearchSettings settings) {
		int byteSize = settings.getDecimalByteSize();
		byte[] bytes = new byte[byteSize];
		for (int i = 0; i < byteSize; i++) {
			byte b = (byte) value;
			bytes[i] = b;
			value >>= 8;
		}
		if (settings.isBigEndian()) {
			reverse(bytes);
		}
		return new NumberParseResult(bytes, null, true);
	}

	@Override
	public String getToolTip() {
		return HTMLUtilities.toHTML(
			"Interpret values as a sequence of decimal numbers, separated by spaces");
	}

	@Override
	public int compareValues(byte[] bytes1, byte[] bytes2, SearchSettings settings) {
		int byteSize = settings.getDecimalByteSize();
		// check each value one at a time, and return the first one different
		for (int i = 0; i < bytes1.length / byteSize; i++) {
			long value1 = getValue(bytes1, i * byteSize, settings);
			long value2 = getValue(bytes2, i * byteSize, settings);
			if (value1 != value2) {
				if (byteSize == 8 && settings.isDecimalUnsigned()) {
					return Long.compareUnsigned(value1, value2);
				}
				return Long.compare(value1, value2);
			}
		}
		return 0;
	}

	public long getValue(byte[] bytes, int index, SearchSettings settings) {
		boolean isBigEndian = settings.isBigEndian();
		int byteSize = settings.getDecimalByteSize();
		boolean isUnsigned = settings.isDecimalUnsigned();

		byte[] bigEndianBytes = getBigEndianBytes(bytes, index, isBigEndian, byteSize);
		long value = isUnsigned ? bigEndianBytes[0] & 0xff : bigEndianBytes[0];
		for (int i = 1; i < byteSize; i++) {
			value = (value << 8) | (bigEndianBytes[i] & 0xff);
		}
		return value;
	}

	private byte[] getBigEndianBytes(byte[] bytes, int index, boolean isBigEndian, int byteSize) {
		byte[] bigEndianBytes = new byte[byteSize];
		System.arraycopy(bytes, index * byteSize, bigEndianBytes, 0, byteSize);
		if (!isBigEndian) {
			reverse(bigEndianBytes);
		}
		return bigEndianBytes;
	}

	@Override
	public String getValueString(byte[] bytes, SearchSettings settings) {
		return getValueString(bytes, settings, false);
	}

	protected String getValueString(byte[] bytes, SearchSettings settings, boolean padNegative) {
		int byteSize = settings.getDecimalByteSize();
		boolean isBigEndian = settings.isBigEndian();
		boolean isUnsigned = settings.isDecimalUnsigned();
		StringBuilder buffer = new StringBuilder();
		int numValues = bytes.length / byteSize;
		for (int i = 0; i < numValues; i++) {
			long value = getValue(bytes, i, settings);
			String text = isUnsigned ? Long.toUnsignedString(value) : Long.toString(value);
			buffer.append(text);
			if (i != numValues - 1) {
				buffer.append(", ");
			}
		}
		int remainder = bytes.length - numValues * byteSize;
		if (remainder > 0) {
			byte[] remainderBytes = new byte[remainder];
			System.arraycopy(bytes, numValues * byteSize, remainderBytes, 0, remainder);
			byte[] padded = padToByteSize(remainderBytes, byteSize, isBigEndian, padNegative);
			long value = getValue(padded, 0, settings);
			String text = isUnsigned ? Long.toUnsignedString(value) : Long.toString(value);
			if (!buffer.isEmpty()) {
				buffer.append(", ");
			}
			buffer.append(text);
		}

		return buffer.toString();
	}

	@Override
	public String convertText(String text, SearchSettings oldSettings, SearchSettings newSettings) {
		SearchFormat oldFormat = oldSettings.getSearchFormat();
		switch (oldFormat.getFormatType()) {
			case BYTE:
				return getTextFromBytes(text, oldSettings, newSettings);
			case INTEGER:
				return convertFromDifferentNumberFormat(text, oldSettings, newSettings);

			case STRING_TYPE:
			case FLOATING_POINT:
			default:
				return isValidText(text, newSettings) ? text : "";

		}
	}

	private String convertFromDifferentNumberFormat(String text, SearchSettings oldSettings,
			SearchSettings newSettings) {
		int oldSize = oldSettings.getDecimalByteSize();
		int newSize = newSettings.getDecimalByteSize();
		boolean oldUnsigned = oldSettings.isDecimalUnsigned();
		boolean newUnsigned = newSettings.isDecimalUnsigned();

		if (oldSize == newSize && oldUnsigned == newUnsigned) {
			return text;
		}
		// if the new format is smaller, first try re-parsing to avoid unnecessary 0's
		if (oldSize > newSize) {
			if (isValidText(text, newSettings)) {
				return text;
			}
		}
		return getTextFromBytes(text, oldSettings, newSettings);
	}

	private String getTextFromBytes(String text, SearchSettings oldSettings,
			SearchSettings newSettings) {
		byte[] bytes = getBytes(oldSettings.getSearchFormat(), text, oldSettings);
		if (bytes == null) {
			return "";
		}
		boolean padNegative = shouldPadNegative(text);
		String valueString = getValueString(bytes, newSettings, padNegative);
		return valueString.replaceAll(",", "");
	}

	private boolean shouldPadNegative(String text) {
		if (text.isBlank()) {
			return false;
		}
		int lastIndexOf = text.trim().lastIndexOf(" ");
		if (lastIndexOf < 0) {
			// only pad negative if there is only one word in the text and it begins with '-'
			return text.charAt(0) == '-';
		}
		return false;
	}

	private byte[] getBytes(SearchFormat oldFormat, String text, SearchSettings settings) {
		ByteMatcher byteMatcher = oldFormat.parse(text, settings);
		if (byteMatcher instanceof MaskedByteSequenceByteMatcher matcher) {
			return matcher.getBytes();
		}
		return null;
	}

	private byte[] padToByteSize(byte[] bytes, int byteSize, boolean isBigEndian,
			boolean padNegative) {
		if (bytes.length >= byteSize) {
			return bytes;
		}
		byte[] newBytes = new byte[byteSize];
		if (padNegative) {
			Arrays.fill(newBytes, (byte) -1);
		}
		int startIndex = isBigEndian ? byteSize - bytes.length : 0;
		System.arraycopy(bytes, 0, newBytes, startIndex, bytes.length);

		return newBytes;
	}

	@Override
	public SearchFormatType getFormatType() {
		return SearchFormatType.INTEGER;
	}
}
