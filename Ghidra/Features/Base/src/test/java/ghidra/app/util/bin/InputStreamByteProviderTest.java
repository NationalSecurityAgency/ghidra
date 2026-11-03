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
package ghidra.app.util.bin;

import static org.junit.Assert.*;

import java.io.*;

import org.junit.Test;

public class InputStreamByteProviderTest {

	/**
	 * A legal InputStream that returns at most 1 byte per bulk read/skip call (like many
	 * decompressing or network streams do).
	 */
	private static class TrickleInputStream extends FilterInputStream {
		TrickleInputStream(byte[] bytes) {
			super(new ByteArrayInputStream(bytes));
		}

		@Override
		public int read(byte[] b, int off, int len) throws IOException {
			return super.read(b, off, Math.min(len, 1));
		}

		@Override
		public long skip(long n) throws IOException {
			return super.skip(Math.min(n, 1));
		}
	}

	@Test
	public void testReadBytes_shortReads() throws IOException {
		byte[] bytes = { 1, 2, 3, 4, 5, 6, 7, 8 };
		InputStreamByteProvider bp =
			new InputStreamByteProvider(new TrickleInputStream(bytes), bytes.length);
		assertArrayEquals(new byte[] { 1, 2, 3 }, bp.readBytes(0, 3));
		assertArrayEquals(new byte[] { 6, 7 }, bp.readBytes(5, 2)); // forward skip of 2
		assertEquals(8, bp.readByte(7)); // forward skip of 1
	}

	@Test(expected = EOFException.class)
	public void testReadBytes_pastEnd() throws IOException {
		byte[] bytes = { 1, 2, 3 };
		InputStreamByteProvider bp =
			new InputStreamByteProvider(new TrickleInputStream(bytes), bytes.length);
		bp.readBytes(1, 5);
	}
}
