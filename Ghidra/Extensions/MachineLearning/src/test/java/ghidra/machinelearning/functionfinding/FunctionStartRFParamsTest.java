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
package ghidra.machinelearning.functionfinding;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class FunctionStartRFParamsTest extends AbstractGenericTest {

	@Test(expected = IllegalArgumentException.class)
	public void testBadParse1() {
		FunctionStartRFParams.parseIntegerCSV("");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testBadParse2() {
		FunctionStartRFParams.parseIntegerCSV("   ");
	}

	@Test(expected = NumberFormatException.class)
	public void testBadParse3() {
		FunctionStartRFParams.parseIntegerCSV("1,,2");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testBadParse4() {
		FunctionStartRFParams.parseIntegerCSV("-1");
	}

	@Test(expected = NumberFormatException.class)
	public void testBadParse5() {
		FunctionStartRFParams.parseIntegerCSV("--1");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testBadParse6() {
		FunctionStartRFParams.parseIntegerCSV(",");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testBadParse7() {
		FunctionStartRFParams.parseIntegerCSV("1,");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testBadParse8() {
		FunctionStartRFParams.parseIntegerCSV("1,2,3,");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testBadParse9() {
		FunctionStartRFParams.parseIntegerCSV(",1,2,3,");
	}

	@Test(expected = NumberFormatException.class)
	public void testBadParse10() {
		FunctionStartRFParams.parseIntegerCSV("1,0xabcdv,3");
	}

	@Test
	public void testBasicValidParses() {
		List<Integer> results = FunctionStartRFParams.parseIntegerCSV("12345678");
		assertEquals(1, results.size());
		assertEquals(Integer.valueOf(12345678), results.get(0));
		results = FunctionStartRFParams.parseIntegerCSV("0x1,2 , 0x3, 4");
		assertEquals(4, results.size());
		assertEquals(Integer.valueOf(1), results.get(0));
		assertEquals(Integer.valueOf(2), results.get(1));
		assertEquals(Integer.valueOf(3), results.get(2));
		assertEquals(Integer.valueOf(4), results.get(3));
		results = FunctionStartRFParams.parseIntegerCSV("4,3,4,3");
		assertEquals(2, results.size());
		assertEquals(Integer.valueOf(3), results.get(0));
		assertEquals(Integer.valueOf(4), results.get(1));
	}

}
