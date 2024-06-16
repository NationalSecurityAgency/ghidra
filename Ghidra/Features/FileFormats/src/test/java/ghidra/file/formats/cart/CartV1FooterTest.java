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

public class CartV1FooterTest {
	CartV1File cartFile;
	CartV1Footer cartFooter;

	@Before
	public void setupCartV1Footer() {
		try {
			ByteArrayProvider provider =
				new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_STD_KEY);

			cartFile = new CartV1File(provider);
			cartFooter = cartFile.getFooter();
			assertNotNull(cartFooter);
		}
		catch (Exception e) {
			fail("Exception setting up CaRT footer tests.");
		}
	}

	@Test
	public void testCartV1FooterByteProvider() {
		CartV1Footer cartFooterByteProvider = null;

		try {
			cartFooterByteProvider =
				new CartV1Footer(new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_STD_KEY));
		}
		catch (Exception e) {
			assertNull("Exception creating normal CaRT footer.", cartFooterByteProvider);
		}
	}

	@Test
	public void testCartV1FooterBinaryReaderPassesWithLittleEndian() {
		CartV1Footer cartFooterBinaryReader = null;

		try {
			cartFooterBinaryReader = new CartV1Footer(new BinaryReader(
				new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_STD_KEY), true));
		}
		catch (Exception e) {
			assertNull("Exception creating CaRT footer from BinaryReader.", cartFooterBinaryReader);
		}
	}

	@Test(expected = IOException.class)
	public void testCartV1FooterBinaryReaderThrowsWithBigEndian() throws Exception {
		ByteArrayProvider provider =
			new ByteArrayProvider(CartV1TestConstants.TEST_CART_GOOD_STD_KEY);

		CartV1Footer cartFooterBinaryReader = new CartV1Footer(new BinaryReader(provider, false));

		// assertNull here is equivalent to fail() but creates a used reference to the object
		assertNull("CaRT file shouldn't be parsed as big-endian", cartFooterBinaryReader);
	}

	@Test
	public void testMagic() throws Exception {
		assertEquals(CartV1Constants.FOOTER_MAGIC, cartFooter.magic());
	}

	@Test
	public void testOptionalFooterPosition() throws Exception {
		assertEquals(cartFile.getDataOffset() + cartFile.getPackedSize(),
			cartFooter.optionalFooterPosition());
	}

	@Test
	public void testOptionalFooterLength() throws Exception {
		assertEquals(CartV1TestConstants.OPTIONAL_FOOTER_LENGTH, cartFooter.optionalFooterLength());
	}

	@Test
	public void testOptionalFooterData() throws Exception {
		cartFooter.loadOptionalFooter(new CartV1Decryptor(CartV1TestConstants.TEST_STD_KEY));
		assertNotNull(cartFooter.optionalFooterData());

		assertEquals(CartV1TestConstants.OPTIONAL_FOOTER_DATA, cartFooter.optionalFooterData());
	}

	@Test
	public void testLoadOptionalFooter() throws Exception {
		cartFooter.loadOptionalFooter(new CartV1Decryptor(CartV1TestConstants.TEST_STD_KEY));
		assertNotNull(cartFooter.optionalFooterData());
	}

}
