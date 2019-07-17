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
package ghidra.app.plugin.assembler.sleigh;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNumericTerminal;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseNumericToken;

public class TokensTest {
	@Test
	public void testNumeric() {
		AssemblyNumericTerminal t = new AssemblyNumericTerminal("test", 0);

		AssemblyParseNumericToken m;

		m = t.match("");
		assertNull(m);

		// Implicit positive
		m = t.match("0");
		assertEquals(0, m.getNumericValue());
		assertEquals("0", m.getString());

		m = t.match("12");
		assertEquals(12, m.getNumericValue());
		assertEquals("12", m.getString());

//		m = t.match("0d12");
//		assertEquals(12, m.getNumericValue());
//		assertEquals("0d12", m.getString());

		m = t.match("0x12");
		assertEquals(0x12, m.getNumericValue());
		assertEquals("0x12", m.getString());

		m = t.match("012");
		assertEquals(012, m.getNumericValue());
		assertEquals("012", m.getString());

		// Explicit positive
		m = t.match("+0");
		assertEquals(0, m.getNumericValue());
		assertEquals("+0", m.getString());

		m = t.match("+12");
		assertEquals(12, m.getNumericValue());
		assertEquals("+12", m.getString());

//		m = t.match("+0d12");
//		assertEquals(12, m.getNumericValue());
//		assertEquals("+0d12", m.getString());

		m = t.match("+0x12");
		assertEquals(0x12, m.getNumericValue());
		assertEquals("+0x12", m.getString());

		m = t.match("+012");
		assertEquals(012, m.getNumericValue());
		assertEquals("+012", m.getString());

		// Explicit negative
		m = t.match("-0");
		assertEquals(0, m.getNumericValue());
		assertEquals("-0", m.getString());

		m = t.match("-12");
		assertEquals(-12, m.getNumericValue());
		assertEquals("-12", m.getString());

//		m = t.match("-0d12");
//		assertEquals(-12, m.getNumericValue());
//		assertEquals("-0d12", m.getString());

		m = t.match("-0x12");
		assertEquals(-0x12, m.getNumericValue());
		assertEquals("-0x12", m.getString());

		m = t.match("-012");
		assertEquals(-012, m.getNumericValue());
		assertEquals("-012", m.getString());

		// Truncation
		m = t.match("-h");
		assertNull(m);

		m = t.match("12x");
		assertEquals(12, m.getNumericValue());
		assertEquals("12", m.getString());
	}
}
