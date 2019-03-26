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

import static ghidra.util.ascii.CharWidth.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Endian;

public class MultiByteCharMatcherTest extends AbstractGenericTest {
	private static final AsciiCharSetRecognizer CHAR_SET = new AsciiCharSetRecognizer();
	static int OFFSET_0 = 0;
	static int OFFSET_1 = 1;
	static int OFFSET_2 = 2;
	static int OFFSET_3 = 3;

	static int ALIGNMENT_1 = 1;
	static int ALIGNMENT_2 = 2;
	static int ALIGNMENT_4 = 4;

	@Test
	public void testBasicUnicode16BigEndian0() {
		// @formatter:off
		// Offset: 0
		// Size:   2
		//

		byte[] byteStream = new byte[] {
					0, 'a',
					0, 'b',
					0, 'c',
					0, 'd',
					0, 0,
					0, 0 };
		// @formatter:on

		List<Sequence> sequenceList = new ArrayList<>();
		ByteStreamCharMatcher matcher;

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF16, Endian.BIG, 1, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch16(0, 9, sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF16, Endian.BIG, 1, OFFSET_1);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);
	}

	@Test
	public void testBasicUnicode16BigEndian1() {
		// @formatter:off
		// Offset: 1
		// Size:   2
		//

		byte[] byteStream = new byte[] {
					0,
					0, 'a',
					0, 'b',
					0, 'c',
					0, 'd',
					0, 0,
					0, 0 };
		// @formatter:on

		List<Sequence> sequenceList = new ArrayList<>();
		ByteStreamCharMatcher matcher;

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF16, Endian.BIG, 1, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF16, Endian.BIG, 1, OFFSET_1);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch16(1, 10, sequenceList);

	}

	@Test
	public void testBasicUnicode16LittleEndian0() {
		// @formatter:off
		// Offset: 0
		// Size:   2
		//

		byte[] byteStream = new byte[] {
				'a', 0,
				'b', 0,
				'c', 0,
				'd', 0,
				 0,  0,
				 0,  0 };
		// @formatter:on

		List<Sequence> sequenceList = new ArrayList<>();
		ByteStreamCharMatcher matcher;

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF16, Endian.LITTLE, 1, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch16(0, 9, sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF16, Endian.LITTLE, 1, OFFSET_1);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);
	}

	@Test
	public void testBasicUnicode16LittleEndian1() {
		// @formatter:off
		// Offset: 1
		// Size:   2
		//

		byte[] byteStream = new byte[] {
				0,
				'a', 0,
				'b', 0,
				'c', 0,
				'd', 0,
				 0,  0,
				 0,  0 };
		// @formatter:on

		List<Sequence> sequenceList = new ArrayList<>();
		ByteStreamCharMatcher matcher;

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF16, Endian.LITTLE, 1, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF16, Endian.LITTLE, 1, OFFSET_1);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch16(1, 10, sequenceList);
	}

	@Test
	public void testBasicUnicode32BigEndian0() {
		// @formatter:off
		// Offset: 0
		// Size:   4
		//

		byte[] byteStream = new byte[] {
				0, 0, 0, 'a', 		// string starts at offset 0; 4 bytes; big endian
				0, 0, 0, 'b',
				0, 0, 0, 'c',
				0, 0, 0, 'd',
				0, 0, 0, 0, 			// string ends at offset 19, null terminated
				0, 0, 0, 0 };
		// @formatter:on

		List<Sequence> sequenceList = new ArrayList<>();
		ByteStreamCharMatcher matcher;

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch32(0, 19, sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_1);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_2);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_3);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

	}

	@Test
	public void testBasicUnicode32BigEndian1() {
		// @formatter:off

		//
		// Offset: 1
		// Size:   4
		//
		byte[] byteStream = new byte[] {
				0,   			// padding to make string start on alignment/offset of 1
				0, 0, 0, 'a',   // string starts at offset 1; 4 bytes; big endian
				0, 0, 0, 'b',
				0, 0, 0, 'c',
				0, 0, 0, 'd',
				0, 0, 0, 0,     // zero terminated; offset 20
				0, 0, 0, 0 };
		// @formatter:on

		List<Sequence> sequenceList = new ArrayList<>();
		ByteStreamCharMatcher matcher;

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_1);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch32(1, 20, sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_2);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_3);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);
	}

	@Test
	public void testBasicUnicode32BigEndian2() {
		// @formatter:off

		//
		// Offset: 2
		// Size:   4
		//
		byte[] byteStream = new byte[] {
				0, 0,  			// padding to make string start on alignment/offset of 2
				0, 0, 0, 'a',   // string starts at offset 2; 4 bytes; big endian
				0, 0, 0, 'b',
				0, 0, 0, 'c',
				0, 0, 0, 'd',
				0, 0, 0, 0,     // zero terminated; offset 21
				0, 0, 0, 0 };
		// @formatter:on

		List<Sequence> sequenceList = new ArrayList<>();
		ByteStreamCharMatcher matcher;

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_1);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_2);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch32(2, 21, sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_3);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);
	}

	@Test
	public void testBasicUnicode32BigEndian3() {
		// @formatter:off

		//
		// Offset: 3
		// Size:   4
		//
		byte[] byteStream = new byte[] {
				0, 0, 0,  		// padding to make string start on alignment/offset of 3
				0, 0, 0, 'a',   // string starts at offset 3; 4 bytes; big endian
				0, 0, 0, 'b',
				0, 0, 0, 'c',
				0, 0, 0, 'd',
				0, 0, 0, 0,     // zero terminated; offset 22
				0, 0, 0, 0 };
		// @formatter:on

		List<Sequence> sequenceList = new ArrayList<>();
		ByteStreamCharMatcher matcher;

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_1);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_2);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_3);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch32(3, 22, sequenceList);
	}

	@Test
	public void testBasicUnicode32LittleEndian0() {
		// @formatter:off

		//
		// Offset: 0
		// Size:   4
		//
		byte[] byteStream = new byte[] {
				'a', 0, 0, 0,   // string starts at offset 0; 4 bytes; big endian
				'b', 0, 0, 0,
				'c', 0, 0, 0,
				'd', 0, 0, 0,
				0, 0, 0, 0, 		// zero terminated; offset 19
				0, 0, 0, 0 };
		// @formatter:on

		List<Sequence> sequenceList = new ArrayList<>();
		ByteStreamCharMatcher matcher;

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.LITTLE, 1, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch32(0, 19, sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.LITTLE, 1, OFFSET_1);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.LITTLE, 1, OFFSET_2);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.LITTLE, 1, OFFSET_3);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);
	}

	@Test
	public void testBasicUnicode32LittleEndian1() {
		// @formatter:off

		//
		// Offset: 1
		// Size:   4
		//
		byte[] byteStream = new byte[] {
				0,				// padding to make string start on alignment/offset of 1
				'a', 0, 0, 0,   // string starts at offset 1; 4 bytes; big endian
				'b', 0, 0, 0,
				'c', 0, 0, 0,
				'd', 0, 0, 0,
				0, 0, 0, 0, 		// zero terminated; offset 20
				0, 0, 0, 0 };
		// @formatter:on

		List<Sequence> sequenceList = new ArrayList<>();
		ByteStreamCharMatcher matcher;

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.LITTLE, 1, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.LITTLE, 1, OFFSET_1);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch32(1, 20, sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.LITTLE, 1, OFFSET_2);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.LITTLE, 1, OFFSET_3);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

	}

	@Test
	public void testBasicUnicode32LittleEndian2() {
		// @formatter:off

		//
		// Offset: 2
		// Size:   4
		//
		byte[] byteStream = new byte[] {
				0, 0,			// padding to make string start on alignment/offset of 2
				'a', 0, 0, 0,   // string starts at offset 2; 4 bytes; big endian
				'b', 0, 0, 0,
				'c', 0, 0, 0,
				'd', 0, 0, 0,
				0, 0, 0, 0, 		// zero terminated; offset 21
				0, 0, 0, 0 };
		// @formatter:on

		List<Sequence> sequenceList = new ArrayList<>();
		ByteStreamCharMatcher matcher;

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.LITTLE, 1, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.LITTLE, 1, OFFSET_1);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.LITTLE, 1, OFFSET_2);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch32(2, 21, sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.LITTLE, 1, OFFSET_3);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);
	}

	@Test
	public void testBasicUnicode32LittleEndian3() {
		// @formatter:off

		//
		// Offset: 3
		// Size:   4
		//
		byte[] byteStream = new byte[] {
				0,	 0, 0,		// padding to make string start on alignment/offset of 3
				'a', 0, 0, 0,   // string starts at offset 3; 4 bytes; big endian
				'b', 0, 0, 0,
				'c', 0, 0, 0,
				'd', 0, 0, 0,
				0, 0, 0, 0, 		// zero terminated; offset 22
				0, 0, 0, 0 };
		// @formatter:on

		List<Sequence> sequenceList = new ArrayList<>();
		ByteStreamCharMatcher matcher;

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.LITTLE, 1, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.LITTLE, 1, OFFSET_1);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.LITTLE, 1, OFFSET_2);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertNoMatches(sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.LITTLE, 1, OFFSET_3);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch32(3, 22, sequenceList);
	}

	@Test
	public void testAlignmentUTF8() {
		byte[] byteStream = new byte[] { 0, 'a', 'b', 'c', 'd', 'e', 'f', 0 };

		List<Sequence> sequenceList = new ArrayList<>();
		ByteStreamCharMatcher matcher;

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF8, Endian.BIG, 1, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch8(1, 7, sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF8, Endian.BIG, 2, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch8(2, 7, sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF8, Endian.BIG, 4, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch8(4, 7, sequenceList);
	}

	@Test
	public void testAlignmentUTF16() {
		byte[] byteStream =
			new byte[] { 0, 0, 0, 'a', 0, 'b', 0, 'c', 0, 'd', 0, 'e', 0, 'f', 0, 0, 0 };

		List<Sequence> sequenceList = new ArrayList<>();
		ByteStreamCharMatcher matcher;

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF16, Endian.BIG, 1, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch16(2, 15, sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF16, Endian.BIG, 2, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch16(2, 15, sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF16, Endian.BIG, 4, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch16(4, 15, sequenceList);

	}

	@Test
	public void testAlignmentUTF32() {
		byte[] byteStream = new byte[] { 0, 0, 0, 0, 0, 0, 0, 'a', 0, 0, 0, 'b', 0, 0, 0, 'c', 0, 0,
			0, 'd', 0, 0, 0, 'e', 0, 0, 0, 'f', 0, 0, 0, 0, 0, 0, 0 };

		List<Sequence> sequenceList = new ArrayList<>();
		ByteStreamCharMatcher matcher;

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 1, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch32(4, 31, sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 2, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch32(4, 31, sequenceList);

		matcher = new MultiByteCharMatcher(3, CHAR_SET, UTF32, Endian.BIG, 4, OFFSET_0);
		runBytesThroughMatcher(matcher, byteStream, sequenceList);
		assertOneMatch32(4, 31, sequenceList);

	}

	private void assertOneMatch8(int start, int end, List<Sequence> matches) {
		assertEquals(1, matches.size());
		assertEquals(new Sequence(start, end, StringDataType.dataType, true), matches.get(0));
	}

	private void assertOneMatch16(int start, int end, List<Sequence> matches) {
		assertEquals(1, matches.size());
		assertEquals(new Sequence(start, end, UnicodeDataType.dataType, true), matches.get(0));
	}

	private void assertOneMatch32(int start, int end, List<Sequence> matches) {
		assertEquals(1, matches.size());
		assertEquals(new Sequence(start, end, Unicode32DataType.dataType, true), matches.get(0));
	}

	private void assertNoMatches(List<Sequence> matches) {
		assertTrue(matches.isEmpty());
	}

	private void runBytesThroughMatcher(ByteStreamCharMatcher matcher, byte[] byteStream,
			List<Sequence> sequenceList) {

		sequenceList.clear();
		for (byte value : byteStream) {
			if (matcher.add(value)) {
				sequenceList.add(matcher.getSequence());
			}
		}
	}

}
