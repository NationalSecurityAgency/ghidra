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
package ghidra.file.formats.cart;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.util.task.DummyCancellableTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class CartV1PayloadExtractorTest {
	CartV1PayloadExtractor cartPayloadExtractor;

	ByteArrayProvider provider;
	ByteArrayOutputStream os;
	CartV1File cartFile;

	@Before
	public void setupCartV1PayloadExtractor() {
		try {
			provider = new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_STD_KEY);

			os = new ByteArrayOutputStream(CartV1TestConstants.TEST_ORIGINAL_DATA.length * 2);
			cartFile = new CartV1File(provider);
		}
		catch (Exception e) {
			fail("Exception setting up CaRT payload extractor tests.");
		}
	}

	@Test
	public void testCartV1PayloadExtactorByteProviderOutputStreamCartV1File() {
		CartV1PayloadExtractor extractor = null;

		try {
			extractor = new CartV1PayloadExtractor(provider, os, cartFile);
		}
		catch (Exception e) {
			assertNull("Exception creating normal CaRT payload extractor.", extractor);
		}
	}

	@Test
	public void testCartV1PayloadExtactorBinaryReaderOutputStreamCartV1FilePassesWithLittleEndian() {
		CartV1PayloadExtractor extractor = null;

		try {
			extractor = new CartV1PayloadExtractor(new BinaryReader(provider, true), os, cartFile);
		}
		catch (Exception e) {
			assertNull("Exception creating CaRT payload extractor from BinaryReader.", extractor);
		}
	}

	@Test(expected = IOException.class)
	public void testCartV1PayloadExtactorBinaryReaderOutputStreamCartV1FileThrowsWithBigEndian()
			throws Exception {
		CartV1PayloadExtractor extractor =
			new CartV1PayloadExtractor(new BinaryReader(provider, false), os, cartFile);

		// assertNull here is equivalent to fail() but creates a used reference to extractor
		assertNull("CaRT file shouldn't be parsed as big-endian", extractor);
	}

	@Test
	public void testExtract() throws Exception {
		CartV1PayloadExtractor extractor =
			new CartV1PayloadExtractor(new BinaryReader(provider, true), os, cartFile);

		TaskMonitor monitor = new DummyCancellableTaskMonitor();
		extractor.extract(monitor);

		assertArrayEquals(CartV1TestConstants.TEST_ORIGINAL_DATA, os.toByteArray());
	}

	@Test
	public void testExtractionTrueWithCorrectKey() throws Exception {
		assertTrue(CartV1PayloadExtractor.testExtraction(new BinaryReader(provider, true), cartFile,
			CartV1TestConstants.TEST_STD_KEY));
	}

	@Test
	public void testExtractionFalseWithWrongKey() throws Exception {
		assertFalse(CartV1PayloadExtractor.testExtraction(new BinaryReader(provider, true),
			cartFile, CartV1TestConstants.TEST_PRIVATE_KEY));
	}

	@Test(expected = CartInvalidARC4KeyException.class)
	public void testExtractionThrowsOnNullKey() throws Exception {
		// Expected to throw, encrypted bytes don't matter
		CartV1PayloadExtractor.testExtraction(new BinaryReader(provider, true), cartFile, null);
		fail("CartV1PayloadExtractor should not accept a null key");
	}

	@Test(expected = CartInvalidARC4KeyException.class)
	public void testExtractionThrowsOnShortKey() throws Exception {
		// Expected to throw, encrypted bytes don't matter
		CartV1PayloadExtractor.testExtraction(new BinaryReader(provider, true), cartFile,
			new byte[] { 0x01, 0x02 });
		fail("CartV1PayloadExtractor should not accept a short key");
	}

	@Test(expected = CartInvalidARC4KeyException.class)
	public void testExtractionThrowsOnLongKey() throws Exception {
		byte[] longKey = new byte[CartV1Constants.ARC4_KEY_LENGTH + 1];
		System.arraycopy(CartV1TestConstants.TEST_STD_KEY, 0, longKey, 0,
			CartV1TestConstants.TEST_STD_KEY.length);

		// Expected to throw, encrypted bytes don't matter
		CartV1PayloadExtractor.testExtraction(new BinaryReader(provider, true), cartFile, longKey);
		fail("CartV1PayloadExtractor should not accept a long key");
	}
}
