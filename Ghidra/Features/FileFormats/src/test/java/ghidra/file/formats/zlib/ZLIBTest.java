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
package ghidra.file.formats.zlib;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.Test;

import generic.test.AbstractGTest;

public class ZLIBTest extends AbstractGTest {

	@Test
	public void testCompressDecompress() throws Exception {

		ZLIB zlib = new ZLIB();

		byte[] data = new byte[100000];
		SecureRandom random = new SecureRandom();
		random.nextBytes(data);

		// TODO: ZLIB API should be revised to avoid senseless exposure of ByteArrayOutputStream

		try (ByteArrayOutputStream compress = zlib.compress(data)) {
			byte[] compressedBytes = compress.toByteArray();
			new ByteArrayInputStream(compressedBytes);

			ByteArrayOutputStream decompressOut =
				zlib.decompress(new ByteArrayInputStream(compressedBytes), data.length);
			byte[] decompressedBytes = decompressOut.toByteArray();

			assertTrue("Zlib round-trip failed", Arrays.equals(data, decompressedBytes));
		}
	}
}
