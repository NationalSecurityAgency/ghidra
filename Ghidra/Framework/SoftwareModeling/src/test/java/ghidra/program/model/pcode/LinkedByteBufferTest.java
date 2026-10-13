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
package ghidra.program.model.pcode;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.pcode.LinkedByteBuffer.Position;

public class LinkedByteBufferTest extends AbstractGenericTest {

	private static byte[] allocateArray(int size, int val) {
		byte[] array = new byte[size];
		for (int i = 0; i < size; ++i)
			array[i] = (byte) val;
		return array;
	}

	@Test
	public void testBufferSizeExceeded() {
		LinkedByteBuffer buffer = new LinkedByteBuffer(16, "teststream");
		byte[] array = allocateArray(32, 0xff);
		ByteArrayInputStream inStream = new ByteArrayInputStream(array);
		boolean sawException = false;
		try {
			buffer.ingestStream(inStream);
		}
		catch (IOException e) {
			sawException = true;
		}
		assertTrue(sawException);
		buffer = new LinkedByteBuffer(16, "teststream2");
		inStream = new ByteArrayInputStream(array);
		sawException = false;
		try {
			buffer.ingestStreamToNextTerminator(inStream);
		}
		catch (IOException e) {
			sawException = true;
		}
		assertTrue(sawException);
	}

	@Test
	public void testIngestStream() throws IOException, DecoderException {
		LinkedByteBuffer buffer = new LinkedByteBuffer(1 << 24, "teststream");
		byte[] array = allocateArray(LinkedByteBuffer.BUFFER_SIZE + 30, 0x7f);
		array[0] = 11;
		array[50] = 3;
		array[LinkedByteBuffer.BUFFER_SIZE] = 10;
		ByteArrayInputStream inStream = new ByteArrayInputStream(array);
		buffer.ingestStream(inStream);
		buffer.endIngest();
		Position pos = buffer.allocatePosition();
		pos.setToStart();
		assertTrue(pos.getNextByte() == 11);
		for (int i = 1; i < 50; ++i) {
			byte val = pos.getNextByte();
			assertTrue(val == 0x7f);
		}
		assertTrue(pos.getByte() == 3);
		assertTrue(pos.getNextByte() == 3);
		for (int i = 51; i < LinkedByteBuffer.BUFFER_SIZE; ++i) {
			byte val = pos.getNextByte();
			assertTrue(val == 0x7f);
		}
		assertTrue(pos.getNextByte() == 10);
		pos.advancePosition(28);
		assertTrue(pos.getNextByte() == 0x7f);
		boolean sawEndOfStream = false;
		try {
			pos.getNextByte();
		}
		catch (DecoderException ex) {
			sawEndOfStream = true;
		}
		assertTrue(sawEndOfStream);
	}

	@Test
	public void testIngestToTerminator() throws IOException, DecoderException {
		LinkedByteBuffer buffer = new LinkedByteBuffer(1 << 24, "teststream");
		byte[] array = allocateArray(LinkedByteBuffer.BUFFER_SIZE + 30, 0x7f);
		array[300] = 0;
		ByteArrayInputStream inStream = new ByteArrayInputStream(array);
		buffer.ingestStreamToNextTerminator(inStream);
		buffer.endIngest();
		Position pos = buffer.allocatePosition();
		pos.setToStart();
		pos.advancePosition(300);
		boolean sawEndOfStream = false;
		try {
			pos.getNextByte();
		}
		catch (DecoderException ex) {
			sawEndOfStream = true;
		}
		assertTrue(sawEndOfStream);
	}

	@Test
	public void testIngestAsNeeded() throws IOException, DecoderException {
		LinkedByteBuffer buffer = new LinkedByteBuffer(1 << 24, "teststream");
		Position pos = buffer.allocatePosition();
		byte[] array = allocateArray(LinkedByteBuffer.BUFFER_SIZE + 30, 0x7f);
		array[LinkedByteBuffer.BUFFER_SIZE + 10] = 100;
		ByteArrayInputStream inStream = new ByteArrayInputStream(array);
		buffer.ingestStreamAsNeeded(inStream, pos);
		assertTrue(inStream.available() == 30);
		for (int i = 0; i < LinkedByteBuffer.BUFFER_SIZE + 10; ++i) {
			assertTrue(pos.getNextByte() == 0x7f);
		}
		assertTrue(pos.getNextByte() == 100);
		pos.advancePosition(19);
		boolean sawEndOfStream = false;
		try {
			pos.getNextByte();
		}
		catch (DecoderException ex) {
			sawEndOfStream = true;
		}
		assertTrue(sawEndOfStream);
	}

	@Test
	public void testString() throws IOException, DecoderException {
		LinkedByteBuffer buffer = new LinkedByteBuffer(1 << 24, "teststream");
		Position pos = buffer.allocatePosition();
		byte[] array = allocateArray(LinkedByteBuffer.BUFFER_SIZE + 30, 0x7f);
		int j = LinkedByteBuffer.BUFFER_SIZE - 4;
		array[j++] = 'c';
		array[j++] = 'r';
		array[j++] = 'o';
		array[j++] = 's';
		array[j++] = 's';
		array[j++] = 'i';
		array[j++] = 'n';
		array[j++] = 'g';
		j++;
		array[j++] = 'c';
		array[j++] = 'a';
		array[j++] = 't';
		ByteArrayInputStream inStream = new ByteArrayInputStream(array);
		buffer.ingestStream(inStream);
		pos.setToStart();
		pos.advancePosition(LinkedByteBuffer.BUFFER_SIZE - 4);
		String str = pos.getNextString(8);
		assertTrue(str.equals("crossing"));
		assertTrue(pos.getNextByte() == 0x7f);
		str = pos.getNextString(3);
		assertTrue(str.equals("cat"));
	}
}
