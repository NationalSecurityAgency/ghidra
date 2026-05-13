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
package ghidra.pcode.emu.jit.gen;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.util.Map;

import org.junit.Test;

import ghidra.program.model.lang.LanguageID;

public class X86JitCodeGeneratorTest extends AbstractJitCodeGeneratorTest {

	protected static final LanguageID ID_X8664 = new LanguageID("x86:LE:64:default");

	@Override
	protected LanguageID getLanguageID() {
		return ID_X8664;
	}

	@Test
	public void testX86DIV() throws Exception {
		Translation tr = translateLang(getLanguageID(), 0x00400000, """
				MOV RAX, 0xdeadbeef
				MOV RDX, 0x1234
				MOV RBX, 0x4321
				DIV RBX
				""", Map.of());
		tr.runDecodeErr(0x0040001b);
		BigInteger dividend = new BigInteger("123400000000deadbeef", 16);
		BigInteger divisor = new BigInteger("4321", 16);
		long quotient = dividend.divide(divisor).longValue();
		long remainder = dividend.remainder(divisor).longValue();
		assertEquals(quotient, tr.getLongRegVal("RAX"));
		assertEquals(remainder, tr.getLongRegVal("RDX"));
	}

	@Test
	public void testX86OffcutJump() throws Exception {
		Translation tr = translateLang(getLanguageID(), 0x00400000, """
				.emit eb ff c0
				CALL 0x0dedbeef
				""".formatted(LONG_CONST), Map.of());
		tr.runDecodeErr(0x0dedbeef);
	}
}
