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
package docking.widgets.fieldpanel;

import static org.junit.Assert.assertEquals;

import java.awt.Color;

import org.junit.Test;

import docking.widgets.fieldpanel.internal.ColorRangeMap;
import generic.test.AbstractGenericTest;

public class ColorRangeMapTest extends AbstractGenericTest {
	public ColorRangeMapTest() {
		super();
	}

	@Test
	public void testPaint1() {
		ColorRangeMap map = new ColorRangeMap();
		map.color(10, 10, Color.BLUE);
		assertEquals(Color.WHITE, map.getColor(0, Color.WHITE));
		assertEquals(Color.WHITE, map.getColor(9, Color.WHITE));
		assertEquals(Color.BLUE, map.getColor(10, Color.WHITE));
		assertEquals(Color.WHITE, map.getColor(11, Color.WHITE));
		assertEquals(Color.WHITE, map.getColor(100, Color.WHITE));
	}

	@Test
	public void testCopy() {
		ColorRangeMap map = new ColorRangeMap();
		map.color(10, 10, Color.BLUE);
		assertEquals(Color.WHITE, map.getColor(0, Color.WHITE));
		assertEquals(Color.WHITE, map.getColor(9, Color.WHITE));
		assertEquals(Color.BLUE, map.getColor(10, Color.WHITE));
		assertEquals(Color.WHITE, map.getColor(11, Color.WHITE));
		assertEquals(Color.WHITE, map.getColor(100, Color.WHITE));

		map = map.copy();

		assertEquals(Color.WHITE, map.getColor(0, Color.WHITE));
		assertEquals(Color.WHITE, map.getColor(9, Color.WHITE));
		assertEquals(Color.BLUE, map.getColor(10, Color.WHITE));
		assertEquals(Color.WHITE, map.getColor(11, Color.WHITE));
		assertEquals(Color.WHITE, map.getColor(100, Color.WHITE));
	}

}
