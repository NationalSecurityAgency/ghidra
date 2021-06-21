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
package docking.widgets.shapes;

import static org.junit.Assert.*;

import java.awt.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.exception.AssertException;

public class PopupWindowPlacerTest extends AbstractGenericTest {

	private Rectangle screen = new Rectangle(0, 0, 2000, 1000);

	// This is overly large for testing with a common context
	private Rectangle center = new Rectangle(200, 200, 1600, 600);
	private Dimension popup = new Dimension(100, 100);
	private Dimension popupBig = new Dimension(250, 250);
	private Dimension popupHugeWidth = new Dimension(screen.width - 100, 100);
	private Dimension popupHugeHeight = new Dimension(100, screen.height - 100);

	@Test
	public void testLeftmostTop() {
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().topEdge(Location.LEFT).build();
		Rectangle placement = placer.getPlacement(popup, center, screen);
		Point expected = new Point(center.x - popup.width, center.y - popup.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popup), placement);
	}

	@Test
	public void testUpperLeft() {
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().leftEdge(Location.TOP).build();
		Rectangle placement = placer.getPlacement(popup, center, screen);
		Point expected = new Point(center.x - popup.width, center.y - popup.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popup), placement);
	}

	@Test
	public void testLeftmostBottom() {
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().bottomEdge(Location.LEFT).build();
		Rectangle placement = placer.getPlacement(popup, center, screen);
		Point expected = new Point(center.x - popup.width, center.y + center.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popup), placement);
	}

	@Test
	public void testLowerLeft() {
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().leftEdge(Location.BOTTOM).build();
		Rectangle placement = placer.getPlacement(popup, center, screen);
		Point expected = new Point(center.x - popup.width, center.y + center.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popup), placement);
	}

	@Test
	public void testRightmostTop() {
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().topEdge(Location.RIGHT).build();
		Rectangle placement = placer.getPlacement(popup, center, screen);
		Point expected = new Point(center.x + center.width, center.y - popup.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popup), placement);
	}

	@Test
	public void testUpperRight() {
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().rightEdge(Location.TOP).build();
		Rectangle placement = placer.getPlacement(popup, center, screen);
		Point expected = new Point(center.x + center.width, center.y - popup.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popup), placement);
	}

	@Test
	public void testRightmostBottom() {
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().bottomEdge(Location.RIGHT).build();
		Rectangle placement = placer.getPlacement(popup, center, screen);
		Point expected = new Point(center.x + center.width, center.y + center.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popup), placement);
	}

	@Test
	public void testLowerRight() {
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().rightEdge(Location.BOTTOM).build();
		Rectangle placement = placer.getPlacement(popup, center, screen);
		Point expected = new Point(center.x + center.width, center.y + center.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popup), placement);
	}

	@Test
	public void testLeftmostTopNeedsShift() {
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().topEdge(Location.LEFT).build();
		int delta = 200;
		Dimension widePopup = new Dimension(popup.width + delta, popup.height);
		Rectangle placement = placer.getPlacement(widePopup, center, screen);
		int x = Integer.max(center.x - widePopup.width, screen.x);
		Point expected = new Point(x, center.y - widePopup.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, widePopup), placement);
	}

	@Test
	public void testLeftmostTopNeedsShiftButCannot() {
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().topEdge(Location.LEFT, Location.LEFT).build();
		int delta = 200;
		Dimension widePopup = new Dimension(popup.width + delta, popup.height);
		Rectangle placement = placer.getPlacement(widePopup, center, screen);
		assertTrue(placement == null);
	}

	@Test
	public void testUpperLeftNeedsShift() {
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().leftEdge(Location.TOP).build();
		int delta = 200;
		Dimension tallPopup = new Dimension(popup.width, popup.height + delta);
		Rectangle placement = placer.getPlacement(tallPopup, center, screen);
		int y = Integer.max(center.y - tallPopup.height, screen.y);
		Point expected = new Point(center.x - tallPopup.width, y);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, tallPopup), placement);
	}

	@Test
	public void testUpperLeftNeedsShiftButCannot() {
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().leftEdge(Location.TOP, Location.TOP).build();
		int delta = 200;
		Dimension tallPopup = new Dimension(popup.width, popup.height + delta);
		Rectangle placement = placer.getPlacement(tallPopup, center, screen);
		assertTrue(placement == null);
	}

	@Test
	public void testLeftmostBottomNeedsShift() {
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().bottomEdge(Location.LEFT).build();
		int delta = 200;
		Dimension widePopup = new Dimension(popup.width + delta, popup.height);
		Rectangle placement = placer.getPlacement(widePopup, center, screen);
		int x = Integer.max(center.x - widePopup.width, screen.x);
		Point expected = new Point(x, center.y + center.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, widePopup), placement);
	}

	@Test
	public void testLeftmostBottomNeedsShiftButCannot() {
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().bottomEdge(Location.LEFT, Location.LEFT).build();
		int delta = 200;
		Dimension widePopup = new Dimension(popup.width + delta, popup.height);
		Rectangle placement = placer.getPlacement(widePopup, center, screen);
		assertTrue(placement == null);
	}

	@Test
	public void testLowerLeftNeedsShift() {
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().leftEdge(Location.BOTTOM).build();
		int delta = 200;
		Dimension tallPopup = new Dimension(popup.width, popup.height + delta);
		Rectangle placement = placer.getPlacement(tallPopup, center, screen);
		int y = Integer.min(center.y + center.height, screen.y + screen.height - tallPopup.height);
		Point expected = new Point(center.x - tallPopup.width, y);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, tallPopup), placement);
	}

	@Test
	public void testLowerLeftNeedsShiftButCannot() {
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().leftEdge(Location.BOTTOM, Location.BOTTOM).build();
		int delta = 200;
		Dimension tallPopup = new Dimension(popup.width, popup.height + delta);
		Rectangle placement = placer.getPlacement(tallPopup, center, screen);
		assertTrue(placement == null);
	}

	@Test
	public void testRightmostTopNeedsShift() {
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().topEdge(Location.RIGHT).build();
		int delta = 200;
		Dimension widePopup = new Dimension(popup.width + delta, popup.height);
		Rectangle placement = placer.getPlacement(widePopup, center, screen);
		int x = Integer.min(center.x + center.width, screen.x + screen.width - widePopup.width);
		Point expected = new Point(x, center.y - widePopup.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, widePopup), placement);
	}

	@Test
	public void testRightmostTopNeedsShiftButCannot() {
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().topEdge(Location.RIGHT, Location.RIGHT).build();
		int delta = 200;
		Dimension widePopup = new Dimension(popup.width + delta, popup.height);
		Rectangle placement = placer.getPlacement(widePopup, center, screen);
		assertTrue(placement == null);
	}

	@Test
	public void testUpperRightNeedsShift() {
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().rightEdge(Location.TOP).build();
		int delta = 200;
		Dimension tallPopup = new Dimension(popup.width, popup.height + delta);
		Rectangle placement = placer.getPlacement(tallPopup, center, screen);
		int y = Integer.max(center.y - tallPopup.height, screen.y);
		Point expected = new Point(center.x + center.width, y);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, tallPopup), placement);
	}

	@Test
	public void testUpperRightNeedsShiftButCannot() {
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().rightEdge(Location.TOP, Location.TOP).build();
		int delta = 200;
		Dimension tallPopup = new Dimension(popup.width, popup.height + delta);
		Rectangle placement = placer.getPlacement(tallPopup, center, screen);
		assertTrue(placement == null);
	}

	@Test
	public void testRightmostBottomNeedsShift() {
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().bottomEdge(Location.RIGHT).build();
		int delta = 200;
		Dimension widePopup = new Dimension(popup.width + delta, popup.height);
		Rectangle placement = placer.getPlacement(widePopup, center, screen);
		int x = Integer.min(center.x + center.width, screen.x + screen.width - widePopup.width);
		Point expected = new Point(x, center.y + center.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, widePopup), placement);
	}

	@Test
	public void testRightmostBottomNeedsShiftButCannot() {
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().bottomEdge(Location.RIGHT, Location.RIGHT).build();
		int delta = 200;
		Dimension widePopup = new Dimension(popup.width + delta, popup.height);
		Rectangle placement = placer.getPlacement(widePopup, center, screen);
		assertTrue(placement == null);
	}

	@Test
	public void testLowerRightNeedsShift() {
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().rightEdge(Location.BOTTOM).build();
		int delta = 200;
		Dimension tallPopup = new Dimension(popup.width, popup.height + delta);
		Rectangle placement = placer.getPlacement(tallPopup, center, screen);
		int y = Integer.min(center.y + center.height, screen.y + screen.height - tallPopup.height);
		Point expected = new Point(center.x + center.width, y);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, tallPopup), placement);
	}

	@Test
	public void testLowerRightNeedsShiftButCannot() {
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().rightEdge(Location.BOTTOM, Location.BOTTOM).build();
		int delta = 200;
		Dimension tallPopup = new Dimension(popup.width, popup.height + delta);
		Rectangle placement = placer.getPlacement(tallPopup, center, screen);
		assertTrue(placement == null);
	}

	@Test
	public void testCenterTopNeedsShiftLeft() {
		int deltaX = 100;
		int deltaY = 0;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().topEdge(Location.CENTER).build();
		Rectangle placement = placer.getPlacement(popupHugeWidth, skewed, screen);
		int x = Integer.min(skewed.x + (skewed.width - popupHugeWidth.width) / 2,
			screen.x + screen.width - popupHugeWidth.width);
		Point expected = new Point(x, skewed.y - popupHugeWidth.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popupHugeWidth), placement);
	}

	@Test
	public void testCenterTopNeedsShiftLeftButCannot() {
		int deltaX = 100;
		int deltaY = 0;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().topEdge(Location.CENTER, Location.CENTER).build();
		Rectangle placement = placer.getPlacement(popupHugeWidth, skewed, screen);
		assertTrue(placement == null);
	}

	@Test
	public void testCenterTopNeedsShiftRight() {
		int deltaX = -100;
		int deltaY = 0;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().topEdge(Location.CENTER).build();
		Rectangle placement = placer.getPlacement(popupHugeWidth, skewed, screen);
		int x = Integer.max(skewed.x + (skewed.width - popupHugeWidth.width) / 2, screen.x);
		Point expected = new Point(x, skewed.y - popupHugeWidth.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popupHugeWidth), placement);
	}

	@Test
	public void testCenterTopNeedsShiftRightButCannot() {
		int deltaX = -100;
		int deltaY = 0;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().topEdge(Location.CENTER, Location.CENTER).build();
		Rectangle placement = placer.getPlacement(popupHugeWidth, skewed, screen);
		assertTrue(placement == null);
	}

	@Test
	public void testCenterBottomNeedsShiftLeft() {
		int deltaX = 100;
		int deltaY = 0;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().bottomEdge(Location.CENTER).build();
		Rectangle placement = placer.getPlacement(popupHugeWidth, skewed, screen);
		int x = Integer.min(skewed.x + (skewed.width - popupHugeWidth.width) / 2,
			screen.x + screen.width - popupHugeWidth.width);
		Point expected = new Point(x, skewed.y + skewed.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popupHugeWidth), placement);
	}

	@Test
	public void testCenterBottomNeedsShiftLeftDownButCannot() {
		int deltaX = 100;
		int deltaY = 0;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().bottomEdge(Location.CENTER, Location.CENTER).build();
		Rectangle placement = placer.getPlacement(popupHugeWidth, skewed, screen);
		assertTrue(placement == null);
	}

	@Test
	public void testCenterBottomNeedsShiftRight() {
		int deltaX = -100;
		int deltaY = 0;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().bottomEdge(Location.CENTER).build();
		Rectangle placement = placer.getPlacement(popupHugeWidth, skewed, screen);
		int x = Integer.max(skewed.x + (skewed.width - popupHugeWidth.width) / 2, screen.x);
		Point expected = new Point(x, center.y + center.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popupHugeWidth), placement);
	}

	@Test
	public void testCenterBottomNeedsShiftRightDownButCannot() {
		int deltaX = -100;
		int deltaY = 0;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().bottomEdge(Location.CENTER, Location.CENTER).build();
		Rectangle placement = placer.getPlacement(popupHugeWidth, skewed, screen);
		assertTrue(placement == null);
	}

	@Test
	public void testCenterLeftNeedsShiftUp() {
		int deltaX = 0;
		int deltaY = 100;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().leftEdge(Location.CENTER).build();
		Rectangle placement = placer.getPlacement(popupHugeHeight, skewed, screen);
		int y = Integer.min(skewed.y + (skewed.height - popupHugeHeight.height) / 2,
			screen.y + screen.height - popupHugeHeight.height);
		Point expected = new Point(center.x - popupHugeHeight.width, y);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popupHugeHeight), placement);
	}

	@Test
	public void testCenterLeftNeedsShiftUpDownButCannot() {
		int deltaX = 0;
		int deltaY = 100;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().leftEdge(Location.CENTER, Location.CENTER).build();
		Rectangle placement = placer.getPlacement(popupHugeHeight, skewed, screen);
		assertTrue(placement == null);
	}

	@Test
	public void testCenterLeftNeedsShiftDown() {
		int deltaX = 0;
		int deltaY = -100;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().leftEdge(Location.CENTER).build();
		Rectangle placement = placer.getPlacement(popupHugeHeight, skewed, screen);
		int y = Integer.max(skewed.y + (skewed.height - popupHugeHeight.height) / 2, screen.y);
		Point expected = new Point(center.x - popupHugeHeight.width, y);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popupHugeHeight), placement);
	}

	@Test
	public void testCenterLeftNeedsShiftDownDownButCannot() {
		int deltaX = 0;
		int deltaY = -100;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().leftEdge(Location.CENTER, Location.CENTER).build();
		Rectangle placement = placer.getPlacement(popupHugeHeight, skewed, screen);
		assertTrue(placement == null);
	}

	@Test
	public void testCenterRightNeedsShiftUp() {
		int deltaX = 0;
		int deltaY = 100;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().rightEdge(Location.CENTER).build();
		Rectangle placement = placer.getPlacement(popupHugeHeight, skewed, screen);
		int y = Integer.min(skewed.y + (skewed.height - popupHugeHeight.height) / 2,
			screen.y + screen.height - popupHugeHeight.height);
		Point expected = new Point(center.x + center.width, y);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popupHugeHeight), placement);
	}

	@Test
	public void testCenterRightNeedsShiftUpDownButCannot() {
		int deltaX = 0;
		int deltaY = 100;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().rightEdge(Location.CENTER, Location.CENTER).build();
		Rectangle placement = placer.getPlacement(popupHugeHeight, skewed, screen);
		assertTrue(placement == null);
	}

	@Test
	public void testCenterRightNeedsShiftDown() {
		int deltaX = 0;
		int deltaY = -100;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().rightEdge(Location.CENTER).build();
		Rectangle placement = placer.getPlacement(popupHugeHeight, skewed, screen);
		int y = Integer.max(skewed.y + (skewed.height - popupHugeHeight.height) / 2, screen.y);
		Point expected = new Point(center.x + center.width, y);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popupHugeHeight), placement);
	}

	@Test
	public void testCenterRightNeedsShiftDownButCannot() {
		int deltaX = 0;
		int deltaY = -100;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().rightEdge(Location.CENTER, Location.CENTER).build();
		Rectangle placement = placer.getPlacement(popupHugeHeight, skewed, screen);
		assertTrue(placement == null);
	}

	@Test
	public void testLeastOverlapCornerTopLeft() {
		int deltaX = 1;
		int deltaY = 1;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().leastOverlapCorner().build();
		Rectangle placement = placer.getPlacement(popupBig, skewed, screen);
		int x = Integer.max(skewed.x - popupBig.width, screen.x);
		int y = Integer.max(skewed.y - popupBig.height, screen.y);
		Point expected = new Point(x, y);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popupBig), placement);
	}

	// Overlapping corner tests
	@Test
	public void testLeastOverlapCornerBottomLeft() {
		int deltaX = 1;
		int deltaY = -1;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().leastOverlapCorner().build();
		Rectangle placement = placer.getPlacement(popupBig, skewed, screen);
		int x = Integer.max(skewed.x - popupBig.width, screen.x);
		int y = Integer.min(skewed.y + skewed.height, screen.y + screen.height - popupBig.height);
		Point expected = new Point(x, y);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popupBig), placement);
	}

	@Test
	public void testLeastOverlapCornerTopRight() {
		int deltaX = -1;
		int deltaY = 1;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().leastOverlapCorner().build();
		Rectangle placement = placer.getPlacement(popupBig, skewed, screen);
		int x = Integer.min(skewed.x + skewed.width, screen.x + screen.width - popupBig.width);
		int y = Integer.max(skewed.y - popupBig.height, screen.y);
		Point expected = new Point(x, y);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popupBig), placement);
	}

	@Test
	public void testLeastOverlapCornerBottomRight() {
		int deltaX = -1;
		int deltaY = -1;
		Rectangle skewed =
			new Rectangle(center.x + deltaX, center.y + deltaY, center.width, center.height);
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().leastOverlapCorner().build();
		Rectangle placement = placer.getPlacement(popupBig, skewed, screen);
		int x = Integer.min(skewed.x + skewed.width, screen.x + screen.width - popupBig.width);
		int y = Integer.min(skewed.y + skewed.height, screen.y + screen.height - popupBig.height);
		Point expected = new Point(x, y);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, popupBig), placement);
	}

	@Test
	public void testThrowsAssertException() {
		PopupWindowPlacer placer = new PopupWindowPlacerBuilder().throwsAssertException().build();
		try {
			// Choice of context area and other parameters does not matter for this test
			placer.getPlacement(popup, center, screen);
			fail("Should not get here");
		}
		catch (AssertException e) {
			assertTrue("Unexpected popup placement error.".equals(e.getMessage()));
		}
	}

	// Some Combination tests
	@Test
	public void testLeftmostTopFixedRightmostTopShift() {
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().topEdge(Location.LEFT, Location.LEFT)
					.topEdge(Location.RIGHT)
					.build();
		int delta = 200;
		Dimension widePopup = new Dimension(popup.width + delta, popup.height);
		Rectangle placement = placer.getPlacement(widePopup, center, screen);
		int x = Integer.min(center.x + center.width, screen.x + screen.width - widePopup.width);
		Point expected = new Point(x, center.y - widePopup.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, widePopup), placement);
	}

	@Test
	public void testRightmostTopFixedLeftmostTopShift() {
		PopupWindowPlacer placer =
			new PopupWindowPlacerBuilder().topEdge(Location.RIGHT, Location.RIGHT)
					.topEdge(Location.LEFT)
					.build();
		int delta = 200;
		Dimension widePopup = new Dimension(popup.width + delta, popup.height);
		Rectangle placement = placer.getPlacement(widePopup, center, screen);
		int x = Integer.max(center.x - widePopup.width, screen.x);
		Point expected = new Point(x, center.y - widePopup.height);
		assertTrue(screen.contains(placement));
		assertEquals(new Rectangle(expected, widePopup), placement);
	}
}
