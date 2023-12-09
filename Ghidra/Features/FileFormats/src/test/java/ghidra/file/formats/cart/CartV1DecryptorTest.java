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

import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

public class CartV1DecryptorTest {
	CartV1Decryptor cartDecryptor;

	@Before
	public void setupCartV1Decryptor() {
		try {
			cartDecryptor = new CartV1Decryptor(CartV1TestConstants.TEST_STD_KEY);
		}
		catch (Exception e) {
			fail("Failed to create CartV1Decryptor with standard test key.");
		}
	}

	@Test
	public void testCartV1Decryptor() {
		// If the @Before doesn't assert then this test passes be default
		return;
	}

	@Test
	public void testThrowIfInvalid() throws Exception {
		cartDecryptor.throwIfInvalid();
	}

	@Test
	public void testThrowIfInvalidByteArrayPassesWhenValid() throws Exception {
		cartDecryptor.throwIfInvalid(CartV1TestConstants.TEST_STD_KEY);
	}

	@Test(expected = CartInvalidARC4KeyException.class)
	public void testThrowIfInvalidByteArrayThrowsOnNullKey() throws Exception {
		cartDecryptor.throwIfInvalid(null);
		fail("CartV1Decryptor should not accept a null key");
	}

	@Test(expected = CartInvalidARC4KeyException.class)
	public void testThrowIfInvalidByteArrayThrowsOnShortKey() throws Exception {
		cartDecryptor.throwIfInvalid(new byte[] { 0x01, 0x02 });
		fail("CartV1Decryptor should not accept a short key");
	}

	@Test(expected = CartInvalidARC4KeyException.class)
	public void testThrowIfInvalidByteArrayThrowsOnLongKey() throws Exception {
		byte[] longKey = new byte[CartV1Constants.ARC4_KEY_LENGTH + 1];
		System.arraycopy(CartV1TestConstants.TEST_STD_KEY, 0, longKey, 0,
			CartV1TestConstants.TEST_STD_KEY.length);

		cartDecryptor.throwIfInvalid(longKey);
		fail("CartV1Decryptor should not accept a long key");
	}

	@Test
	public void testSetKeyAcceptsStandardKey() throws Exception {
		cartDecryptor.setKey(CartV1TestConstants.TEST_STD_KEY);
	}

	@Test
	public void testSetKeyAcceptsPrivateKey() throws Exception {
		cartDecryptor.setKey(CartV1TestConstants.TEST_PRIVATE_KEY);
	}

	@Test(expected = CartInvalidARC4KeyException.class)
	public void testSetKeyThrowsOnNullKey() throws Exception {
		cartDecryptor.setKey(null);
		fail("CartV1Decryptor should not accept a null key");
	}

	@Test(expected = CartInvalidARC4KeyException.class)
	public void testSetKeyThrowsOnShortKey() throws Exception {
		cartDecryptor.setKey(new byte[] { 0x01, 0x02 });
		fail("CartV1Decryptor should not accept a short key");
	}

	@Test(expected = CartInvalidARC4KeyException.class)
	public void testSetKeyThrowsOnLongKey() throws Exception {
		byte[] longKey = new byte[CartV1Constants.ARC4_KEY_LENGTH + 1];
		System.arraycopy(CartV1TestConstants.TEST_STD_KEY, 0, longKey, 0,
			CartV1TestConstants.TEST_STD_KEY.length);

		cartDecryptor.setKey(longKey);
		fail("CartV1Decryptor should not accept a long key");
	}

	@Test
	public void testDecryptByteArrayByteArrayDecryptsCorrectKey() throws Exception {
		byte[] optionalHeader = Arrays.copyOfRange(CartV1TestConstants.TEST_CART_GOOD_STD_KEY,
			CartV1Constants.HEADER_LENGTH,
			CartV1Constants.HEADER_LENGTH + (int) CartV1TestConstants.OPTIONAL_HEADER_LENGTH);

		byte[] decryptedOptionalHeader =
			CartV1Decryptor.decrypt(CartV1TestConstants.TEST_STD_KEY, optionalHeader);

		assertEquals(CartV1TestConstants.OPTIONAL_HEADER_DATA_RAW,
			new String(decryptedOptionalHeader));
	}

	@Test(expected = CartInvalidARC4KeyException.class)
	public void testDecryptByteArrayByteArrayThrowsOnNullKey() throws Exception {
		// Expected to throw, encrypted bytes don't matter
		CartV1Decryptor.decrypt(null, new byte[] { 0x01, 0x02 });
		fail("CartV1Decryptor should not accept a null key");
	}

	@Test(expected = CartInvalidARC4KeyException.class)
	public void testDecryptByteArrayByteArrayThrowsOnShortKey() throws Exception {
		// Expected to throw, encrypted bytes don't matter
		CartV1Decryptor.decrypt(new byte[] { 0x01, 0x02 }, new byte[] { 0x01, 0x02 });
		fail("CartV1Decryptor should not accept a short key");
	}

	@Test(expected = CartInvalidARC4KeyException.class)
	public void testDecryptByteArrayByteArrayThrowsOnLongKey() throws Exception {
		byte[] longKey = new byte[CartV1Constants.ARC4_KEY_LENGTH + 1];
		System.arraycopy(CartV1TestConstants.TEST_STD_KEY, 0, longKey, 0,
			CartV1TestConstants.TEST_STD_KEY.length);

		// Expected to throw, encrypted bytes don't matter
		CartV1Decryptor.decrypt(longKey, new byte[] { 0x01, 0x02 });
		fail("CartV1Decryptor should not accept a long key");
	}

	@Test
	public void testDecryptByteArray() throws Exception {
		byte[] optionalHeader = Arrays.copyOfRange(CartV1TestConstants.TEST_CART_GOOD_STD_KEY,
			CartV1Constants.HEADER_LENGTH,
			CartV1Constants.HEADER_LENGTH + (int) CartV1TestConstants.OPTIONAL_HEADER_LENGTH);

		byte[] decryptedOptionalHeader = cartDecryptor.decrypt(optionalHeader);

		assertEquals(CartV1TestConstants.OPTIONAL_HEADER_DATA_RAW,
			new String(decryptedOptionalHeader));
	}

	@Test
	public void testDecryptToStringByteArrayByteArrayDecryptsCorrectKey() throws Exception {
		byte[] optionalHeader = Arrays.copyOfRange(CartV1TestConstants.TEST_CART_GOOD_STD_KEY,
			CartV1Constants.HEADER_LENGTH,
			CartV1Constants.HEADER_LENGTH + (int) CartV1TestConstants.OPTIONAL_HEADER_LENGTH);

		String decryptedOptionalHeader =
			CartV1Decryptor.decryptToString(CartV1TestConstants.TEST_STD_KEY, optionalHeader);

		assertEquals(CartV1TestConstants.OPTIONAL_HEADER_DATA_RAW, decryptedOptionalHeader);
	}

	@Test(expected = CartInvalidARC4KeyException.class)
	public void testDecryptToStringByteArrayByteArrayThrowsOnNullKey() throws Exception {
		// Expected to throw, encrypted bytes don't matter
		CartV1Decryptor.decryptToString(null, new byte[] { 0x01, 0x02 });
		fail("CartV1Decryptor should not accept a null key");
	}

	@Test(expected = CartInvalidARC4KeyException.class)
	public void testDecryptToStringByteArrayByteArrayThrowsOnShortKey() throws Exception {
		// Expected to throw, encrypted bytes don't matter
		CartV1Decryptor.decryptToString(new byte[] { 0x01, 0x02 }, new byte[] { 0x01, 0x02 });
		fail("CartV1Decryptor should not accept a short key");
	}

	@Test(expected = CartInvalidARC4KeyException.class)
	public void testDecryptToStringByteArrayByteArrayThrowsOnLongKey() throws Exception {
		byte[] longKey = new byte[CartV1Constants.ARC4_KEY_LENGTH + 1];
		System.arraycopy(CartV1TestConstants.TEST_STD_KEY, 0, longKey, 0,
			CartV1TestConstants.TEST_STD_KEY.length);

		// Expected to throw, encrypted bytes don't matter
		CartV1Decryptor.decryptToString(longKey, new byte[] { 0x01, 0x02 });
		fail("CartV1Decryptor should not accept a long key");
	}

	@Test
	public void testDecryptToStringByteArray() throws Exception {
		byte[] optionalHeader = Arrays.copyOfRange(CartV1TestConstants.TEST_CART_GOOD_STD_KEY,
			CartV1Constants.HEADER_LENGTH,
			CartV1Constants.HEADER_LENGTH + (int) CartV1TestConstants.OPTIONAL_HEADER_LENGTH);

		String decryptedOptionalHeader = cartDecryptor.decryptToString(optionalHeader);

		assertEquals(CartV1TestConstants.OPTIONAL_HEADER_DATA_RAW, decryptedOptionalHeader);
	}

	@Test
	public void testGetARC4KeyAcceptsStdTestKey() throws Exception {
		cartDecryptor.setKey(CartV1TestConstants.TEST_STD_KEY);
		assertArrayEquals(CartV1TestConstants.TEST_STD_KEY, cartDecryptor.getARC4Key());
	}

	@Test
	public void testGetARC4KeyAcceptsPlaceholderKey() throws Exception {
		cartDecryptor.setKey(CartV1Constants.PRIVATE_ARC4_KEY_PLACEHOLDER);
		assertArrayEquals(CartV1Constants.PRIVATE_ARC4_KEY_PLACEHOLDER, cartDecryptor.getARC4Key());
	}

	@Test
	public void testGetARC4KeyAcceptsDefaultKey() throws Exception {
		cartDecryptor.setKey(CartV1Constants.DEFAULT_ARC4_KEY);
		assertArrayEquals(CartV1Constants.DEFAULT_ARC4_KEY, cartDecryptor.getARC4Key());
	}

}
