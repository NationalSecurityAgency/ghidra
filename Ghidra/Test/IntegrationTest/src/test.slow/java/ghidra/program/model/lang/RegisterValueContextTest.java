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

import static org.junit.Assert.assertEquals;

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
		assertEquals(0xffffffffL, valueMask.longValue());

		RegisterValue newValue = new RegisterValue(regContext, value, valueMask);
		assertEquals(0x12345678, newValue.getUnsignedValue().longValue());
		assertEquals(0xffffffffL, newValue.getValueMask().longValue());

	}

	@Test
	public void testBytes() {

		RegisterValue val = new RegisterValue(regContext,
			new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 1, 2, 3, 4 });

		assertEquals(0x01020304, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x01020304, val.getSignedValueIgnoreMask().longValue());
		assertEquals(0x01020304, val.getUnsignedValue().longValue());
		assertEquals(0x01020304, val.getSignedValue().longValue());
		assertEquals(0x0ffffffffL, val.getValueMask().longValue());

		val = new RegisterValue(regContext,
			new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xf0, (byte) 0xff, 1, 2, 3, 4 });

		assertEquals(0x01020304, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x01020304, val.getSignedValueIgnoreMask().longValue());
		assertEquals(null, val.getUnsignedValue());
		assertEquals(null, val.getSignedValue());
		assertEquals(0x0fffff0ffL, val.getValueMask().longValue());
	}

	@Test
	public void testBytesGrow() {

		RegisterValue val =
			new RegisterValue(regContext, new byte[] { (byte) 0xff, (byte) 0xff, 0x12, 0x34 });

		assertEquals(0x12340000, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x12340000, val.getSignedValueIgnoreMask().longValue());
		assertEquals(null, val.getUnsignedValue());
		assertEquals(null, val.getSignedValue());
		assertEquals(0x0ffff0000L, val.getValueMask().longValue());

		val = new RegisterValue(regContext, new byte[] { (byte) 0x10, (byte) 0xff, 0x12, 0x34 });

		assertEquals(0x10340000, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x10340000, val.getSignedValueIgnoreMask().longValue());
		assertEquals(null, val.getUnsignedValue());
		assertEquals(null, val.getSignedValue());
		assertEquals(0x10ff0000, val.getValueMask().longValue());
	}

	@Test
	public void testBytesShrink() {

		RegisterValue val = new RegisterValue(regContext, new byte[] { (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0 });

		assertEquals(0x12345678, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x12345678, val.getSignedValueIgnoreMask().longValue());
		assertEquals(0x12345678, val.getUnsignedValue().longValue());
		assertEquals(0x12345678, val.getSignedValue().longValue());
		assertEquals(0x0ffffffffL, val.getValueMask().longValue());

		val = new RegisterValue(regContext, new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xf0,
			(byte) 0xff, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0 });

		assertEquals(0x12345078, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x12345078, val.getSignedValueIgnoreMask().longValue());
		assertEquals(null, val.getUnsignedValue());
		assertEquals(null, val.getSignedValue());
		assertEquals(0x0fffff0ffL, val.getValueMask().longValue());
	}

}
