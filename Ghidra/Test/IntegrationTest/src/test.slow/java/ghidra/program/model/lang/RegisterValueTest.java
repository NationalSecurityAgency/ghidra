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

public class RegisterValueTest extends AbstractGhidraHeadlessIntegrationTest {

	private Language language;

	private Register regEAX;
	private Register regAX;
	private Register regAH;
	private Register regAL;

	private Register regEBX;
	private Register regBX;
	private Register regBH;
	private Register regBL;

	private Register regCF;

	@Before
	public void setUp() throws Exception {
		LanguageService languageService = getLanguageService();
		language = languageService.getLanguage(new LanguageID("x86:LE:32:default"));

		regEAX = language.getRegister("EAX");// 4-byte reg within 8-byte parent
		regAX = language.getRegister("AX");
		regAH = language.getRegister("AH");
		regAL = language.getRegister("AL");

		regEBX = language.getRegister("EBX");// 4-byte reg within 8-byte parent
		regBX = language.getRegister("BX");
		regBH = language.getRegister("BH");
		regBL = language.getRegister("BL");

		regCF = language.getRegister("CF");// 1-byte reg (basereg)
	}

	@Test
	public void testRegisterValueMask() {

		RegisterValue valAH = new RegisterValue(regAH, BigInteger.valueOf(0x55));
		BigInteger value = valAH.getUnsignedValue();
		assertEquals(0x55, value.longValue());
		BigInteger valueMask = valAH.getValueMask();
		assertEquals(0xff, valueMask.longValue());

		RegisterValue newValue = new RegisterValue(regBH, value, valueMask);
		assertEquals(0x55, newValue.getUnsignedValue().longValue());
		assertEquals(0xff, newValue.getValueMask().longValue());

		newValue = newValue.getRegisterValue(regEBX);
		assertEquals(0x5500, newValue.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0xff00, newValue.getValueMask().longValue());

		newValue = new RegisterValue(regBL, value, valueMask);
		assertEquals(0x55, newValue.getUnsignedValue().longValue());
		assertEquals(0xff, newValue.getValueMask().longValue());

		RegisterValue valEAX = valAH.getRegisterValue(regEAX).assign(regAL, newValue);
		assertEquals(0x5555, valEAX.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0xffff, valEAX.getValueMask().longValue());

	}

	@Test
	public void testBytes() {

		RegisterValue val = new RegisterValue(regEBX,
			new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, 0, 0, 0, 0, 0, 0, 0x12, 0x34 });

		assertEquals(0x1234, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x1234, val.getSignedValueIgnoreMask().longValue());
		assertEquals(0x1234, val.getUnsignedValue().longValue());
		assertEquals(0x1234, val.getSignedValue().longValue());
		assertEquals(0x0ffffffffL, val.getValueMask().longValue());

		val = new RegisterValue(regEBX,
			new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xf0, (byte) 0xff, 0, 0, 0, 0, 0, 0, 0x12, 0x34 });

		assertEquals(0x1034, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x1034, val.getSignedValueIgnoreMask().longValue());
		assertEquals(null, val.getUnsignedValue());
		assertEquals(null, val.getSignedValue());
		assertEquals(0x0fffff0ffL, val.getValueMask().longValue());
	}

	@Test
	public void testBytesGrow() {

		RegisterValue val =
			new RegisterValue(regEBX, new byte[] { (byte) 0xff, (byte) 0xff, 0x12, 0x34 });

		assertEquals(0x1234, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x1234, val.getSignedValueIgnoreMask().longValue());
		assertEquals(0x1234, val.getUnsignedValue().longValue());
		assertEquals(0x1234, val.getSignedValue().longValue());
		assertEquals(0x0ffffffffL, val.getValueMask().longValue());

		val = new RegisterValue(regEBX, new byte[] { (byte) 0x10, (byte) 0xff, 0x12, 0x34 });

		assertEquals(0x1034, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x1034, val.getSignedValueIgnoreMask().longValue());
		assertEquals(null, val.getUnsignedValue());
		assertEquals(null, val.getSignedValue());
		assertEquals(0x10ff, val.getValueMask().longValue());
	}

	@Test
	public void testBytesShrink() {

		RegisterValue val =
			new RegisterValue(regCF, new byte[] { (byte) 0xff, (byte) 0xff, 0x12, 0x34 });

		assertEquals(0x34, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x34, val.getSignedValueIgnoreMask().longValue());
		assertEquals(0x34, val.getUnsignedValue().longValue());
		assertEquals(0x34, val.getSignedValue().longValue());
		assertEquals(0x0ffL, val.getValueMask().longValue());

		val = new RegisterValue(regCF, new byte[] { (byte) 0xf0, (byte) 0xff, 0x12, 0x34 });

		assertEquals(0x34, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x34, val.getSignedValueIgnoreMask().longValue());
		assertEquals(0x34, val.getUnsignedValue().longValue());
		assertEquals(0x34, val.getSignedValue().longValue());
		assertEquals(0x0ffL, val.getValueMask().longValue());

		val = new RegisterValue(regCF, new byte[] { (byte) 0xff, (byte) 0xf0, 0x12, 0x34 });

		assertEquals(0x30, val.getUnsignedValueIgnoreMask().longValue());
		assertEquals(0x30, val.getSignedValueIgnoreMask().longValue());
		assertEquals(null, val.getUnsignedValue());
		assertEquals(null, val.getSignedValue());
		assertEquals(0x0f0, val.getValueMask().longValue());
	}

}
