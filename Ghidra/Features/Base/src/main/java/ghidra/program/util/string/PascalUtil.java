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
package ghidra.program.util.string;

import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.ascii.Sequence;

public class PascalUtil {

	private static final int ONE_BYTE_OFFSET = -1;
	private static final int TWO_BYTE_OFFSET = -2;
	private static final int NO_OFFSET = 0;
	private static final int ASCII_CHAR_WIDTH = 1;
	private static final int UNICODE16_CHAR_WIDTH = 2;
	private static final int PASCAL_LENGTH_SIZE = 2;
	private static final int PASCAL255_LENGTH_SIZE = 1;

	/**
	 * Looks for Pascal strings given a sequence of bytes that represent a sequence of ascii chars.
	 * @param buf the Memory buffer containing the bytes that make up the string.
	 * @param sequence the sequence that specifies the start, end, and type of ascii sequence (i.e. ascii,
	 * unicode16).  This method looks for both 2 byte and 1 byte leading pascal lengths both before
	 * and at the beginning of the given sequence.
	 *
	 * @return a new sequence that has been adjusted  to represent a pascal string or null if
	 * a pascal string was not found.
	 */
	public static Sequence findPascalSequence(MemBuffer buf, Sequence sequence, int alignment) {
		DataType stringDataType = sequence.getStringDataType();
		if ((stringDataType instanceof PascalUnicodeDataType) ||
			(stringDataType instanceof UnicodeDataType)) {
			return findUnicodePascal(buf, sequence);
		}
		if ((stringDataType instanceof PascalStringDataType) ||
			(stringDataType instanceof PascalString255DataType) ||
			(stringDataType instanceof StringDataType)) {
			return findAsciiPascal(buf, sequence, alignment);
		}
		return null;
	}

	private static Sequence findUnicodePascal(MemBuffer buf, Sequence sequence) {
		Sequence pascalSequence = checkForPascalUnicodeSequence(buf, sequence, TWO_BYTE_OFFSET);
		if (pascalSequence != null) {
			return pascalSequence;
		}
		pascalSequence = checkForPascalUnicodeSequence(buf, sequence, NO_OFFSET);
		return pascalSequence;
	}

	private static Sequence findAsciiPascal(MemBuffer buf, Sequence sequence, int alignment) {
		Sequence pascalSequence = checkForPascalAsciiSequence(buf, sequence, TWO_BYTE_OFFSET);
		if (pascalSequence != null) {
			return pascalSequence;
		}
		if (alignment == 1) {
			pascalSequence = checkForPascal255AsciiSequence(buf, sequence, ONE_BYTE_OFFSET);
			if (pascalSequence != null) {
				return pascalSequence;
			}
			pascalSequence = checkForPascalAsciiSequence(buf, sequence, ONE_BYTE_OFFSET);
			if (pascalSequence != null) {
				return pascalSequence;
			}
		}
		pascalSequence = checkForPascal255AsciiSequence(buf, sequence, NO_OFFSET);
		if (pascalSequence != null) {
			return pascalSequence;
		}
		pascalSequence = checkForPascalAsciiSequence(buf, sequence, NO_OFFSET);
		return pascalSequence;
	}

	private static Sequence checkForPascalUnicodeSequence(MemBuffer buf, Sequence sequence,
			int offset) {
		int pascalLengthOffset = (int) sequence.getStart() + offset;
		if (pascalLengthOffset < 0) {
			return null;
		}
		int length = getShort(buf, pascalLengthOffset);
		int sequenceLength =
			(sequence.getLength() - offset - PASCAL_LENGTH_SIZE) / UNICODE16_CHAR_WIDTH;
		if (sequence.isNullTerminated()) {
			sequenceLength -= 1;
			if (length == sequenceLength) {
				return new Sequence(pascalLengthOffset, sequence.getEnd() - UNICODE16_CHAR_WIDTH,
					PascalUnicodeDataType.dataType, false);
			}
		}
		else if (length == sequenceLength) {
			return new Sequence(pascalLengthOffset, sequence.getEnd(),
				PascalUnicodeDataType.dataType, false);
		}
		return null;
	}

	private static Sequence checkForPascalAsciiSequence(MemBuffer buf, Sequence sequence,
			int offset) {
		int pascalLengthOffset = (int) sequence.getStart() + offset;
		if (pascalLengthOffset < 0) {
			return null;
		}
		int length = getShort(buf, pascalLengthOffset);
		int sequenceLength = sequence.getLength() - offset - PASCAL_LENGTH_SIZE;
		if (sequence.isNullTerminated()) {
			sequenceLength -= 1;
			if (length == sequenceLength) {
				return new Sequence(pascalLengthOffset, sequence.getEnd() - ASCII_CHAR_WIDTH,
					PascalStringDataType.dataType, false);
			}
		}
		else if (length == sequenceLength) {
			return new Sequence(pascalLengthOffset, sequence.getEnd(),
				PascalStringDataType.dataType, false);
		}
		return null;
	}

	private static Sequence checkForPascal255AsciiSequence(MemBuffer buf, Sequence sequence,
			int offset) {
		int pascalLengthOffset = (int) sequence.getStart() + offset;
		if (pascalLengthOffset < 0) {
			return null;
		}
		int length = getByte(buf, pascalLengthOffset);
		int sequenceLength = sequence.getLength() - offset - PASCAL255_LENGTH_SIZE;
		if (sequence.isNullTerminated()) {
			sequenceLength -= 1;
			if (length == sequenceLength) {
				return new Sequence(pascalLengthOffset, sequence.getEnd() - ASCII_CHAR_WIDTH,
					PascalString255DataType.dataType, false);
			}
		}
		else if (length == sequenceLength) {
			return new Sequence(pascalLengthOffset, sequence.getEnd(),
				PascalString255DataType.dataType, false);
		}
		return null;

	}

	private static int getShort(MemBuffer buf, int offset) {
		try {
			return buf.getShort(offset);
		}
		catch (MemoryAccessException e) {
			return ONE_BYTE_OFFSET;
		}
	}

	private static int getByte(MemBuffer buf, int offset) {
		try {
			return buf.getByte(offset) & 0xff;
		}
		catch (MemoryAccessException e) {
			return ONE_BYTE_OFFSET;
		}
	}

}
