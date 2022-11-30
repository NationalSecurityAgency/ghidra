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
package agent.gdb.manager.impl;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.nio.ByteOrder;

import org.junit.Test;

import agent.gdb.manager.impl.cmd.GdbReadRegistersCommand;

public class GdbReadRegistersCommandTest {
	@Test
	public void testParseAndFindInteger_Integer() throws Exception {
		String value = "0x1234";
		assertEquals(BigInteger.valueOf(0x1234),
			GdbReadRegistersCommand.parseAndFindInteger(value, 8, ByteOrder.LITTLE_ENDIAN));
	}

	@Test
	public void testParseAndFindInteger_CompositeWithInteger() throws Exception {
		String value = "{nope = {f = 0x0}, i = 0x1234}";
		assertEquals(BigInteger.valueOf(0x1234),
			GdbReadRegistersCommand.parseAndFindInteger(value, 8, ByteOrder.LITTLE_ENDIAN));
	}

	@Test
	public void testParseAndFindInteger_Array() throws Exception {
		String value = "{0x34, 0x12}";
		assertEquals(BigInteger.valueOf(0x1234),
			GdbReadRegistersCommand.parseAndFindInteger(value, 2, ByteOrder.LITTLE_ENDIAN));
	}

	@Test
	public void testParseAndFindInteger_PatternX64() throws Exception {
		String value = "{v64_int8 = {0x34, 0x12, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}";
		assertEquals(BigInteger.valueOf(0x1234),
			GdbReadRegistersCommand.parseAndFindInteger(value, 8, ByteOrder.LITTLE_ENDIAN));
	}

	@Test
	public void testParseAndFindInteger_PatternARMv7() throws Exception {
		String value = "{u8 = {0x34, 0x12, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}";
		assertEquals(BigInteger.valueOf(0x1234),
			GdbReadRegistersCommand.parseAndFindInteger(value, 8, ByteOrder.LITTLE_ENDIAN));
	}

	@Test
	public void testParseAndFindInteger_PatternAArch64() throws Exception {
		String value = "{b = {u = {0x34, 0x12, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}";
		assertEquals(BigInteger.valueOf(0x1234),
			GdbReadRegistersCommand.parseAndFindInteger(value, 8, ByteOrder.LITTLE_ENDIAN));
	}
}
