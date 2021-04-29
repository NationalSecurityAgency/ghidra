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
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import agent.gdb.manager.parsing.GdbCValueParser;
import agent.gdb.manager.parsing.GdbCValueParser.*;
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;

public class GdbCValueParserTest {
	@Test
	public void testIntegerZero() throws GdbParseError {
		assertEquals(GdbIntValue.valueOf(0), GdbCValueParser.parseValue("0"));
		assertEquals(GdbIntValue.valueOf(0), GdbCValueParser.parseValue("00"));
		assertEquals(GdbIntValue.valueOf(0), GdbCValueParser.parseValue("000"));
		assertEquals(GdbIntValue.valueOf(0), GdbCValueParser.parseValue("0x0"));
		assertEquals(GdbIntValue.valueOf(0), GdbCValueParser.parseValue("0x00"));
	}

	@Test
	public void testIntegerDec() throws GdbParseError {
		assertEquals(GdbIntValue.valueOf(1), GdbCValueParser.parseValue("1"));
		assertEquals(GdbIntValue.valueOf(10), GdbCValueParser.parseValue("10"));
		assertEquals(GdbIntValue.valueOf(1234567890), GdbCValueParser.parseValue("1234567890"));
	}

	@Test(expected = GdbParseError.class)
	public void testIntegerDecErr() throws GdbParseError {
		GdbCValueParser.parseValue("1f");
	}

	@Test
	public void testIntegerHex() throws GdbParseError {
		assertEquals(GdbIntValue.valueOf(1), GdbCValueParser.parseValue("0x1"));
		assertEquals(GdbIntValue.valueOf(0x10), GdbCValueParser.parseValue("0x10"));
		assertEquals(GdbIntValue.valueOf(0x123456789abcdef0L),
			GdbCValueParser.parseValue("0x123456789abcdef0"));
	}

	@Test(expected = GdbParseError.class)
	public void testIntegerHexErr() throws GdbParseError {
		GdbCValueParser.parseValue("0xfg");
	}

	@Test
	public void testIntegerOct() throws GdbParseError {
		assertEquals(GdbIntValue.valueOf(01), GdbCValueParser.parseValue("01"));
		assertEquals(GdbIntValue.valueOf(010), GdbCValueParser.parseValue("010"));
		assertEquals(GdbIntValue.valueOf(012345670), GdbCValueParser.parseValue("012345670"));
	}

	@Test(expected = GdbParseError.class)
	public void testIntegerOctErr() throws GdbParseError {
		GdbCValueParser.parseValue("018");
	}

	@Test
	public void testComposite() throws GdbParseError {
		assertEquals(GdbCompositeValue.builder()
				.put("a", GdbIntValue.valueOf(1))
				.put("b", GdbIntValue.valueOf(2))
				.put("c", GdbIntValue.valueOf(3))
				.build(),
			GdbCValueParser.parseValue("{a=1,b=0x2,c=03}"));
	}

	@Test
	public void testCompositeSpaces() throws GdbParseError {
		assertEquals(GdbCompositeValue.builder()
				.put("a", GdbIntValue.valueOf(1))
				.put("b", GdbIntValue.valueOf(2))
				.put("c", GdbIntValue.valueOf(3))
				.build(),
			GdbCValueParser.parseValue(" { a = 1 , b = 0x2 , c = 03 } "));
	}

	@Test(expected = GdbParseError.class)
	public void testCompositeErrMissingClose() throws GdbParseError {
		GdbCValueParser.parseValue("{a = 1, b = 0x2, c = 03");
	}

	@Test(expected = GdbParseError.class)
	public void testCompositeErrMissingComma() throws GdbParseError {
		GdbCValueParser.parseValue("{a = 1 b = 0x2, c = 03}");
	}

	@Test
	public void testArray() throws GdbParseError {
		assertEquals(GdbArrayValue.builder()
				.add(GdbIntValue.valueOf(1))
				.add(GdbIntValue.valueOf(2))
				.add(GdbIntValue.valueOf(3))
				.build(),
			GdbCValueParser.parseValue("{1,0x2,03}"));
	}

	@Test
	public void testArraySpaces() throws GdbParseError {
		assertEquals(GdbArrayValue.builder()
				.add(GdbIntValue.valueOf(1))
				.add(GdbIntValue.valueOf(2))
				.add(GdbIntValue.valueOf(3))
				.build(),
			GdbCValueParser.parseValue(" { 1 , 0x2 , 03 } "));
	}

	@Test(expected = GdbParseError.class)
	public void testArrayErrMissingClose() throws GdbParseError {
		GdbCValueParser.parseValue("{1, 0x2, 03");
	}

	@Test(expected = GdbParseError.class)
	public void testArrayErrMissingComma() throws GdbParseError {
		GdbCValueParser.parseValue("{1 0x2, 03}");
	}

	@Test
	public void testArrayWithRepeat() throws GdbParseError {
		assertEquals(GdbArrayValue.builder()
				.add(GdbIntValue.valueOf(1))
				.add(GdbIntValue.valueOf(2))
				.add(GdbIntValue.valueOf(2))
				.add(GdbIntValue.valueOf(2))
				.add(GdbIntValue.valueOf(2))
				.add(GdbIntValue.valueOf(2))
				.add(GdbIntValue.valueOf(3))
				.build(),
			GdbCValueParser.parseValue("{1, 0x2 <repeats 5 times>, 03}"));
	}

	@Test
	public void testNested() throws GdbParseError {
		assertEquals(GdbCompositeValue.builder()
				.put("a", GdbIntValue.valueOf(1))
				.put("b", GdbArrayValue.builder()
						.add(GdbIntValue.valueOf(2))
						.add(GdbIntValue.valueOf(3))
						.build())
				.put("c", GdbCompositeValue.builder()
						.put("d", GdbIntValue.valueOf(4))
						.put("e", GdbIntValue.valueOf(5))
						.build())
				.build(),
			GdbCValueParser.parseValue("{a=1,b={2,3},c={d=4,e=5}}"));
	}

	@Test(expected = GdbParseError.class)
	public void testEmptyStringErr() throws GdbParseError {
		GdbCValueParser.parseValue("");
	}

	@Test
	public void testEmptyValue() throws GdbParseError {
		assertTrue(GdbCValueParser.parseValue("{}").isEmpty());
	}

	@Test
	public void testRegisterValue() throws GdbParseError {
		String observed = "{" +
			"v4_float = {0x0, 0x0, 0x0, 0x0}, " +
			"v2_double = {0x0, 0x0}, " +
			"v16_int8 = {0x0 <repeats 16 times>}, " +
			"v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, " +
			"v4_int32 = {0x0, 0x0, 0x0, 0x0}, " +
			"v2_int64 = {0x0, 0x0}, " +
			"uint128 = 0x00000000000000000000000000000000" +
			"}";
		assertEquals(GdbCompositeValue.builder()
				.put("v4_float", GdbArrayValue.builder()
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.build())
				.put("v2_double", GdbArrayValue.builder()
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.build())
				.put("v16_int8", GdbArrayValue.builder()
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.build())
				.put("v8_int16", GdbArrayValue.builder()
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.build())
				.put("v4_int32", GdbArrayValue.builder()
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.build())
				.put("v2_int64", GdbArrayValue.builder()
						.add(GdbIntValue.valueOf(0))
						.add(GdbIntValue.valueOf(0))
						.build())
				.put("uint128", GdbIntValue.valueOf(0))
				.build(),
			GdbCValueParser.parseValue(observed));
	}
}
