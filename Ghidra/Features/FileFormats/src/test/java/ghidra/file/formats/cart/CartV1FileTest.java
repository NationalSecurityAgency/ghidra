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

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.util.HashUtilities;

public class CartV1FileTest {
	CartV1File cartFile;

	@Before
	public void setupCartV1File() {
		try {
			ByteArrayProvider provider =
				new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_STD_KEY);
			cartFile = new CartV1File(provider);
		}
		catch (Exception e) {
			fail("Exception setting up CaRT file tests.");
		}
	}

	@Test
	public void testCartV1FileByteProvider() {
		CartV1File cartFileByteProvider = null;

		try {
			cartFileByteProvider =
				new CartV1File(new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_STD_KEY));
		}
		catch (Exception e) {
			assertNull("Exception creating normal CaRT file.", cartFileByteProvider);
		}
	}

	@Test
	public void testCartV1FileByteProviderString() {
		CartV1File cartFileByteProvider = null;

		try {
			cartFileByteProvider = new CartV1File(
				new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_PRIVATE_KEY_ABC),
				CartV1TestConstants.PRIVATE_KEY);
		}
		catch (Exception e) {
			assertNull("Exception creating normal CaRT file with private key.",
				cartFileByteProvider);
		}
	}

	@Test
	public void testCartV1FileBinaryReaderPassesWithLittleEndian() {
		CartV1File cartFileBinaryReader = null;

		try {
			cartFileBinaryReader = new CartV1File(new BinaryReader(
				new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_STD_KEY), true));
		}
		catch (Exception e) {
			assertNull("Exception creating CaRT file from BinaryReader.", cartFileBinaryReader);
		}
	}

	@Test(expected = IOException.class)
	public void testCartV1FileBinaryReaderThrowsWithBigEndian() throws Exception {
		ByteArrayProvider provider =
			new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_STD_KEY);

		CartV1File cartFileBinaryReader = new CartV1File(new BinaryReader(provider, false));

		// assertNull here is equivalent to fail() but creates a used reference to the object
		assertNull("CaRT file shouldn't be parsed as big-endian", cartFileBinaryReader);
	}

	@Test
	public void testCartV1FileBinaryReaderStringPassesWithLittleEndian() {
		CartV1File cartFileBinaryReader = null;

		try {
			cartFileBinaryReader = new CartV1File(new BinaryReader(
				new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_PRIVATE_KEY_ABC), true),
				CartV1TestConstants.PRIVATE_KEY);
		}
		catch (Exception e) {
			assertNull("Exception creating CaRT file with private key from BinaryReader.",
				cartFileBinaryReader);
		}
	}

	@Test(expected = IOException.class)
	public void testCartV1FileBinaryReaderStringThrowsWithBigEndian() throws Exception {
		ByteArrayProvider provider =
			new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_PRIVATE_KEY_ABC);

		CartV1File cartFileBinaryReader =
			new CartV1File(new BinaryReader(provider, false), CartV1TestConstants.PRIVATE_KEY);

		// assertNull here is equivalent to fail() but creates a used reference to the object
		assertNull("CaRT file shouldn't be parsed as big-endian", cartFileBinaryReader);
	}

	@Test
	public void testGetName() throws Exception {
		String testingName = "Test_Name";

		ByteArrayProvider provider =
			new ByteArrayProvider(testingName, CartV1TestConstants.TEST_CART_GOOD_STD_KEY);

		CartV1File namedCartFile = new CartV1File(provider);
		assertEquals(testingName, namedCartFile.getName());
	}

	@Test
	public void testGetPath() throws Exception {
		assertEquals(CartV1TestConstants.CARTED_FILE_NAME, cartFile.getPath());
	}

	@Test
	public void testGetDataOffset() throws Exception {
		assertEquals(CartV1Constants.HEADER_LENGTH + cartFile.getHeader().optionalHeaderLength(),
			cartFile.getDataOffset());
	}

	@Test
	public void testGetDataSize() throws Exception {
		assertEquals(CartV1TestConstants.CARTED_FILE_SIZE, cartFile.getDataSize());
	}

	@Test
	public void testGetPackedSize() throws Exception {
		assertEquals(CartV1TestConstants.CARTED_COMPRESSED_FILE_SIZE, cartFile.getPackedSize());
	}

	@Test
	public void testGetFooterHashMd5() throws Exception {
		assertEquals(CartV1TestConstants.TEST_MD5,
			new String(HashUtilities.hexDump(cartFile.getFooterHash("md5"))));
	}

	@Test
	public void testGetFooterHashSha1() throws Exception {
		assertEquals(CartV1TestConstants.TEST_SHA1,
			new String(HashUtilities.hexDump(cartFile.getFooterHash("sha1"))));
	}

	@Test
	public void testGetFooterHashSha256() throws Exception {
		assertEquals(CartV1TestConstants.TEST_SHA256,
			new String(HashUtilities.hexDump(cartFile.getFooterHash("sha256"))));
	}

	@Test
	public void testGetHeader() throws Exception {
		assertNotNull(cartFile.getHeader());
	}

	@Test
	public void testGetFooter() throws Exception {
		assertNotNull(cartFile.getFooter());
	}

	@Test
	public void testGetDecryptor() throws Exception {
		assertNotNull(cartFile.getDecryptor());
	}

	@Test
	public void testGetMetadata() throws Exception {
		assertNotNull(cartFile.getMetadata());
	}
}
