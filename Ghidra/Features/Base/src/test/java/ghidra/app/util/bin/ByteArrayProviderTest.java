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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;

import org.junit.Test;

public class ByteArrayProviderTest {

	private ByteArrayProvider bap(int... values) {
		byte[] bytes = new byte[values.length];
		for (int i = 0; i < values.length; i++) {
			bytes[i] = (byte) values[i];
		}
		return new ByteArrayProvider(bytes);
	}

	@Test
	public void testInputStream() throws IOException {
		ByteArrayProvider bap = bap(1, 2, 3, 4, 5, 6);

		InputStream is = bap.getInputStream(0);
		assertEquals(1, is.read());
		assertEquals(2, is.read());

		InputStream is2 = bap.getInputStream(4);
		assertEquals(5, is2.read());
		assertEquals(6, is2.read());
		assertEquals(-1, is2.read());

		InputStream is3 = bap.getInputStream(6);
		assertEquals(-1, is3.read());
	}

	@Test
	public void testReadBytes_EOFBoundary() throws IOException {
		ByteArrayProvider bap = bap(1, 2, 3, 4, 5, 6);

		// ensure we don't get IOException reading to (but not past) end of buffer
		bap.readBytes(0, 6);
		bap.readBytes(5, 1);
		bap.readBytes(6, 0);

		// ensure we do get IOException when reading past end of buffer
		try {
			bap.readBytes(6, 1);
			fail("Should have triggered IOException");
		}
		catch (IOException ioe) {
			// good
		}
	}

}
