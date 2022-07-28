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
		assertEquals("#0123ef", WebColors.toString(new Color(0x01, 0x23, 0xef)));
	}

	@Test
	public void testGetColor() {
		assertEquals(WebColors.NAVY, WebColors.getColor("Navy"));
		assertEquals(WebColors.NAVY, WebColors.getColor("0x000080"));
		assertEquals(WebColors.NAVY, WebColors.getColor("#000080"));
		assertEquals(WebColors.NAVY, WebColors.getColor("rgb(0,0,128)"));
		assertEquals(WebColors.NAVY, WebColors.getColor("rgba(0,0,128,1.0)"));
		assertEquals(WebColors.NAVY, WebColors.getColor("rgba(0,0,128, 255)"));

		assertEquals(new Color(0x123456), WebColors.getColor("0x123456"));
		assertEquals(new Color(0x80102030, true), WebColors.getColor("rgba(16, 32, 48, 0.5)"));

		assertNull(WebColors.getColor("asdfasdfas"));
	}

	@Test
	public void testColorWithAlphaRoundTrip() {
		Color c = new Color(0x44112233, true);
		assertEquals(0x44, c.getAlpha());
		String string = WebColors.toString(c, false);
		Color parsed = WebColors.getColor(string);
		assertEquals(c, parsed);
	}
}
