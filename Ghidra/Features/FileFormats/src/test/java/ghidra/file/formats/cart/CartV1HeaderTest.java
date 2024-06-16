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

public class CartV1HeaderTest {
	CartV1Header cartHeader;

	@Before
	public void setupCartV1Header() {
		try {
			ByteArrayProvider provider =
				new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_STD_KEY);

			cartHeader = new CartV1Header(provider);
		}
		catch (Exception e) {
			fail("Exception setting up CaRT header tests.");
		}
	}

	@Test
	public void testCartV1HeaderByteProvider() {
		CartV1Header cartHeaderByteProvider = null;

		try {
			cartHeaderByteProvider =
				new CartV1Header(new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_STD_KEY));
		}
		catch (Exception e) {
			assertNull("Exception creating normal CaRT header.", cartHeaderByteProvider);
		}
	}

	@Test
	public void testCartV1HeaderBinaryReaderPassesWithLittleEndian() {
		CartV1Header cartHeaderBinaryReader = null;

		try {
			cartHeaderBinaryReader = new CartV1Header(new BinaryReader(
				new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_STD_KEY), true));
		}
		catch (Exception e) {
			assertNull("Exception creating CaRT header from BinaryReader.", cartHeaderBinaryReader);
		}
	}

	@Test(expected = IOException.class)
	public void testCartV1HeaderBinaryReaderThrowsWithBigEndian() throws Exception {
		ByteArrayProvider provider =
			new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_STD_KEY);

		CartV1Header cartHeaderBinaryReader = new CartV1Header(new BinaryReader(provider, false));

		// assertNull here is equivalent to fail() but creates a used reference to the object
		assertNull("CaRT file shouldn't be parsed as big-endian", cartHeaderBinaryReader);
	}

	@Test
	public void testMagic() throws Exception {
		assertEquals(CartV1Constants.HEADER_MAGIC, cartHeader.magic());
	}

	@Test
	public void testVersion() throws Exception {
		assertEquals(CartV1Constants.HEADER_VERSION, cartHeader.version());
	}

	@Test
	public void testArc4Key() throws Exception {
		assertArrayEquals(CartV1TestConstants.TEST_STD_KEY, cartHeader.arc4Key());

		ByteArrayProvider provider =
			new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_PRIVATE_KEY_ABC);

		CartV1Header cartHeaderPrivateKey = new CartV1Header(provider);

		assertArrayEquals(CartV1Constants.PRIVATE_ARC4_KEY_PLACEHOLDER,
			cartHeaderPrivateKey.arc4Key());
	}

	@Test
	public void testDataStart() throws Exception {
		assertEquals(cartHeader.optionalHeaderLength() + CartV1Constants.HEADER_LENGTH,
			cartHeader.dataStart());
	}

	@Test
	public void testOptionalHeaderLength() throws Exception {
		assertEquals(CartV1TestConstants.OPTIONAL_HEADER_LENGTH, cartHeader.optionalHeaderLength());
	}

	@Test
	public void testOptionalHeaderData() throws Exception {
		cartHeader.loadOptionalHeader(new CartV1Decryptor(CartV1TestConstants.TEST_STD_KEY));
		assertNotNull(cartHeader.optionalHeaderData());

		assertEquals(CartV1TestConstants.OPTIONAL_HEADER_DATA, cartHeader.optionalHeaderData());
	}

	@Test
	public void testLoadOptionalHeader() throws Exception {
		cartHeader.loadOptionalHeader(new CartV1Decryptor(CartV1TestConstants.TEST_STD_KEY));
		assertNotNull(cartHeader.optionalHeaderData());
	}
}
