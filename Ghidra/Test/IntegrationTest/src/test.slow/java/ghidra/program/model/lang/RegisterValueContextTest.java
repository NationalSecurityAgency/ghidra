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
package ghidra.program.model.lang;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Before;
import org.junit.Test;

import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class RegisterValueContextTest extends AbstractGhidraHeadlessIntegrationTest {

	private Language language;

	private Register regContext;

	@Before
	public void setUp() throws Exception {
		LanguageService languageService = getLanguageService();
		language = languageService.getLanguage(new LanguageID("x86:LE:32:default"));

		regContext = language.getContextBaseRegister();// 4-byte context reg
	}

	@Test
	public void testRegisterValueMask() {

		RegisterValue val = new RegisterValue(regContext, BigInteger.valueOf(0x12345678));
		BigInteger value = val.getUnsignedValue();
		assertEquals(0x12345678, value.longValue());
		BigInteger valueMask = val.getValueMask();
		assertEquals(0xffffffffffffffffL, valueMask.longValue());

		RegisterValue newValue = new RegisterValue(regContext, value, valueMask);
		assertEquals(0x12345678, newValue.getUnsignedValue().longValue());
		assertEquals(0xffffffffffffffffL, newValue.getValueMask().longValue());

	}

	@Test
	public void testBytes() {

		RegisterValue val = new RegisterValue(regContext,
			new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, 1, 2, 3, 4, 5, 6, 7, 8 });

		assertEquals(0x0102030405060708L, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x0102030405060708L, val.getSignedValueIgnoreMask().longValue());
		assertEquals(0x0102030405060708L, val.getUnsignedValue().longValue());
		assertEquals(0x0102030405060708L, val.getSignedValue().longValue());
		assertEquals(0x0ffffffffffffffffL, val.getValueMask().longValue());

		val = new RegisterValue(regContext,
			new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xf0, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, 1, 2, 3, 4, 5, 6, 7, 8 });

		assertEquals(0x0102030405060708L, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x0102030405060708L, val.getSignedValueIgnoreMask().longValue());
		assertEquals(null, val.getUnsignedValue());
		assertEquals(null, val.getSignedValue());
		assertEquals(0x0fffff0ffffffffffL, val.getValueMask().longValue());
	}

	@Test
	public void testBytesGrow() {

		RegisterValue val =
			new RegisterValue(regContext, new byte[] { (byte) 0xff, (byte) 0xff, 0x12, 0x34 });

		assertEquals(0x1234000000000000L, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x1234000000000000L, val.getSignedValueIgnoreMask().longValue());
		assertEquals(null, val.getUnsignedValue());
		assertEquals(null, val.getSignedValue());
		assertEquals(0x0ffff000000000000L, val.getValueMask().longValue());

		val = new RegisterValue(regContext, new byte[] { (byte) 0x10, (byte) 0xff, 0x12, 0x34 });

		assertEquals(0x1034000000000000L, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x1034000000000000L, val.getSignedValueIgnoreMask().longValue());
		assertEquals(null, val.getUnsignedValue());
		assertEquals(null, val.getSignedValue());
		assertEquals(0x10ff000000000000L, val.getValueMask().longValue());
	}

	@Test
	public void testBytesShrink() {

		RegisterValue val = new RegisterValue(regContext, new byte[] { (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0, 0, 0,
			0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });

		assertEquals(0x1234567800000000L, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x1234567800000000L, val.getSignedValueIgnoreMask().longValue());
		assertEquals(0x1234567800000000L, val.getUnsignedValue().longValue());
		assertEquals(0x1234567800000000L, val.getSignedValue().longValue());
		assertEquals(0xffffffffffffffffL, val.getValueMask().longValue());

		val = new RegisterValue(regContext, new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xf0,
			(byte) 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0 });

		assertEquals(0x1234507800000000L, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x1234507800000000L, val.getSignedValueIgnoreMask().longValue());
		assertEquals(null, val.getUnsignedValue());
		assertEquals(null, val.getSignedValue());
		assertEquals(0xfffff0ff00000000L, val.getValueMask().longValue());
	}

}
