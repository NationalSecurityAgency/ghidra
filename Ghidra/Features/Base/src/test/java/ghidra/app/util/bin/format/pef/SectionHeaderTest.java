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
package ghidra.app.util.bin.format.pef;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.Test;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.util.task.TaskMonitor;

public class SectionHeaderTest {

	private static final int HEADER_SIZE = 28;

	/**
	 * Builds a big-endian PEF section header for a packed data section, immediately followed
	 * by the given packed data bytes.
	 */
	private SectionHeader packedSection(int unpackedLength, int... packed) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		writeInt(out, SectionHeader.NO_NAME_OFFSET); // nameOffset
		writeInt(out, 0); // defaultAddress
		writeInt(out, unpackedLength); // totalLength
		writeInt(out, unpackedLength); // unpackedLength
		writeInt(out, packed.length); // containerLength
		writeInt(out, HEADER_SIZE); // containerOffset
		out.write(SectionKind.PackedData.getValue()); // sectionKind
		out.write(0); // shareKind
		out.write(0); // alignment
		out.write(0); // reservedA
		for (int b : packed) {
			out.write(b);
		}
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(out.toByteArray()), false);
		return new SectionHeader(reader);
	}

	private static void writeInt(ByteArrayOutputStream out, int value) {
		out.write(value >>> 24);
		out.write(value >>> 16);
		out.write(value >>> 8);
		out.write(value);
	}

	@Test
	public void testUnpack_valid() throws Exception {
		SectionHeader section = packedSection(6, //
			0x22, 'A', 'B', // block copy 2 bytes
			0x02, // zero fill 2 bytes
			0x41, 0x01, 'C' // repeat 1 byte, 1+1 times
		);
		assertArrayEquals(new byte[] { 'A', 'B', 0, 0, 'C', 'C' },
			section.getUnpackedData(TaskMonitor.DUMMY));
	}

	@Test
	public void testUnpack_blockExceedsUnpackedLength() throws Exception {
		// block copy of 8 bytes into a 4 byte section, previously ArrayIndexOutOfBoundsException
		SectionHeader section = packedSection(4, 0x28, 1, 2, 3, 4, 5, 6, 7, 8);
		try {
			section.getUnpackedData(TaskMonitor.DUMMY);
			fail("Should have thrown IllegalStateException");
		}
		catch (IllegalStateException e) {
			// good
		}
	}

	@Test
	public void testUnpack_repeatExceedsUnpackedLength() throws Exception {
		// repeat 1 byte 100+1 times into a 4 byte section
		SectionHeader section = packedSection(4, 0x41, 100, 'C');
		try {
			section.getUnpackedData(TaskMonitor.DUMMY);
			fail("Should have thrown IllegalStateException");
		}
		catch (IllegalStateException e) {
			// good
		}
	}

	@Test
	public void testUnpack_hugeCustomSizeDoesNotAllocate() throws Exception {
		// repeat-zero with customSize 0xffffff, previously allocated it (16MB) before failing
		SectionHeader section = packedSection(4, 0x81, 0x87, 0xff, 0xff, 0x7f, 0x01);
		try {
			section.getUnpackedData(TaskMonitor.DUMMY);
			fail("Should have thrown IllegalStateException");
		}
		catch (IllegalStateException e) {
			// good
		}
	}

	@Test
	public void testUnpack_negativeUnpackedLength() throws Exception {
		// previously NegativeArraySizeException
		SectionHeader section = packedSection(-1, 0x01);
		try {
			section.getUnpackedData(TaskMonitor.DUMMY);
			fail("Should have thrown IllegalStateException");
		}
		catch (IllegalStateException e) {
			// good
		}
	}

	@Test
	public void testUnpack_zeroFillPastEndIsTolerated() throws Exception {
		// historical behavior: trailing zero fill past the end is ignored
		SectionHeader section = packedSection(2, 0x22, 'A', 'B', 0x05);
		assertArrayEquals(new byte[] { 'A', 'B' }, section.getUnpackedData(TaskMonitor.DUMMY));
	}
}
