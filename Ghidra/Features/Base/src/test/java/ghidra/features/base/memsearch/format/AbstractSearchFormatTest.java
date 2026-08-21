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

import static org.junit.Assert.*;

import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.matcher.MaskedByteSequenceByteMatcher;

public class AbstractSearchFormatTest {
	protected SearchFormat format;
	protected MaskedByteSequenceByteMatcher matcher;
	protected SearchSettings settings = new SearchSettings().withBigEndian(true);

	protected SearchSettings hexSettings = settings.withSearchFormat(SearchFormat.HEX);
	protected SearchSettings binarySettings = settings.withSearchFormat(SearchFormat.BINARY);
	protected SearchSettings decimalSettings = settings.withSearchFormat(SearchFormat.DECIMAL);
	protected SearchSettings int1Settings = decimalSettings.withDecimalByteSize(1);
	protected SearchSettings int2Settings = decimalSettings.withDecimalByteSize(2);
	protected SearchSettings int4Settings = decimalSettings.withDecimalByteSize(4);
	protected SearchSettings int8Settings = decimalSettings.withDecimalByteSize(8);
	protected SearchSettings uint1Settings = int1Settings.withDecimalUnsigned(true);
	protected SearchSettings uint2Settings = int2Settings.withDecimalUnsigned(true);
	protected SearchSettings uint4Settings = int4Settings.withDecimalUnsigned(true);
	protected SearchSettings uint8Settings = int8Settings.withDecimalUnsigned(true);
	protected SearchSettings floatSettings = settings.withSearchFormat(SearchFormat.FLOAT);
	protected SearchSettings doubleSettings = settings.withSearchFormat(SearchFormat.DOUBLE);
	protected SearchSettings stringSettings = settings.withSearchFormat(SearchFormat.STRING);
	protected SearchSettings regExSettings = settings.withSearchFormat(SearchFormat.REG_EX);

	protected AbstractSearchFormatTest(SearchFormat format) {
		this.format = format;
		this.settings = settings.withSearchFormat(format);
	}

	protected MaskedByteSequenceByteMatcher parse(String string) {
		ByteMatcher byteMatcher = format.parse(string, settings);
		if (byteMatcher instanceof MaskedByteSequenceByteMatcher m) {
			return m;
		}
		fail("Expected MaskedByteSequenceByteMatcher, but got " + byteMatcher);
		return null;
	}

	protected static byte[] bytes(int... byteValues) {
		byte[] bytes = new byte[byteValues.length];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) byteValues[i];
		}
		return bytes;
	}

	protected void assertBytes(int... expectedValues) {
		byte[] bytes = matcher.getBytes();
		byte[] expectedBytes = bytes(expectedValues);
		assertArrayEquals(expectedBytes, bytes);
	}

	protected void assertMask(int... expectedValues) {
		byte[] bytes = matcher.getMask();
		byte[] expectedBytes = bytes(expectedValues);
		assertArrayEquals(expectedBytes, bytes);
	}

	protected int compareBytes(String input1, String input2) {
		byte[] bytes1 = getBytes(input1);
		byte[] bytes2 = getBytes(input2);
		return format.compareValues(bytes1, bytes2, settings);
	}

	protected byte[] getBytes(String input) {
		matcher = parse(input);
		return matcher.getBytes();
	}

	protected String str(long value) {
		return Long.toString(value);
	}

	protected String convertText(SearchSettings oldSettings, String text) {
		return format.convertText(text, oldSettings, settings);
	}

}
