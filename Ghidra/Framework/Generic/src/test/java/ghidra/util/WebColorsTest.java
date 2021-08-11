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
package ghidra.util;

import static org.junit.Assert.*;

import java.awt.Color;

import org.junit.Test;

public class WebColorsTest {

	@Test
	public void testColorToStringFromDefinedValue() {
		assertEquals("Navy", WebColors.toString(WebColors.NAVY));
	}

	@Test
	public void testColorToStringNewColor() {
		assertEquals("Navy", WebColors.toString(new Color(0, 0, 0x80)));
	}

	@Test
	public void testColorToStringFromColorWithNoDefinedEntry() {
		assertEquals("#0123EF", WebColors.toString(new Color(0x01, 0x23, 0xEF)));
	}

	@Test
	public void testGetColorFromName() {
		assertEquals(WebColors.NAVY, WebColors.getColor("Navy"));
	}

	@Test
	public void testGetColorFromHexString() {
		assertEquals(WebColors.NAVY, WebColors.getColor("0x000080"));
	}

	@Test
	public void testGetColorFromHexString2() {
		assertEquals(WebColors.NAVY, WebColors.getColor("#000080"));
	}

	@Test
	public void testGetColorWithNoDefinedValue() {
		assertEquals(new Color(0x12, 0x34, 0x56), WebColors.getColor("0x123456"));
	}

	@Test
	public void testGetColorByBadName() {
		assertNull(WebColors.getColor("ABCDEFG"));
	}
}
