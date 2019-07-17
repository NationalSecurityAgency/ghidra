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
package ghidra.util.ascii;

import ghidra.program.model.data.*;
import ghidra.program.model.lang.Endian;
import ghidra.util.DataConverter;

public class MultiByteCharMatcher implements ByteStreamCharMatcher {

	private MinLengthCharSequenceMatcher charMatcher;
	private long index = -1;
	private long offset;
	private byte[] bytes;
	private DataConverter converter;
	private int bytesPerChar;
	private final CharWidth charWidth;

	public MultiByteCharMatcher(int minLength, CharSetRecognizer charSet, CharWidth charWidth,
			Endian endian, int alignment, int offset) {
		if (offset < 0 || offset >= charWidth.size()) {
			throw new IllegalArgumentException("offset must be between 0 and bytesPerChar");
		}
		this.charWidth = charWidth;
		this.bytesPerChar = charWidth.size();
		this.offset = offset;
		int charAlignment = computeCharSequenceAlignemt(alignment, bytesPerChar);
		charMatcher = new MinLengthCharSequenceMatcher(minLength, charSet, charAlignment);
		converter = DataConverter.getInstance(endian.isBigEndian());
		bytes = new byte[charWidth.size()];
	}

	private int computeCharSequenceAlignemt(int alignment, int bytesInChar) {
		return Math.max(alignment / bytesInChar, 1);
	}

	@Override
	public boolean add(byte b) {
		if (charWidth == CharWidth.UTF8) { // if only one byte per char, take shortcut
			return charMatcher.addChar(b & 0xff);
		}

		index++;
		if (index < offset) {
			return false;
		}
		int mod = (int) (index - offset) % bytesPerChar;
		bytes[mod] = b;

		if (mod < bytesPerChar - 1) {
			return false;
		}
		int c = bytesPerChar == 2 ? converter.getShort(bytes) : converter.getInt(bytes);
		return charMatcher.addChar(c);
	}

	@Override
	public Sequence getSequence() {
		Sequence sequence = charMatcher.getSequence();
		if (sequence == null || charWidth == CharWidth.UTF8) {
			return sequence;		// no adjustments required
		}
		long start = sequence.getStart() * bytesPerChar + offset;
		long end = sequence.getEnd() * bytesPerChar + bytesPerChar - 1 + offset;
		AbstractStringDataType stringDatatype =
			charWidth == CharWidth.UTF16 ? UnicodeDataType.dataType : Unicode32DataType.dataType;
		return new Sequence(start, end, stringDatatype, sequence.isNullTerminated());
	}

	@Override
	public boolean endSequence() {
		return charMatcher.endSequence();
	}

	@Override
	public void reset() {
		index = -1;
		charMatcher.reset();
	}
}
