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
package docking.util;

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.List;

import javax.swing.JLabel;
import javax.swing.JPanel;

import org.junit.Test;

import docking.DockingFrame;
import docking.test.AbstractDockingTest;
import docking.util.TextShaper.TextShaperLine;
import generic.theme.Gui;
import ghidra.util.bean.GGlassPane;

public class TextShaperTest extends AbstractDockingTest {

	// @Test 
	// for debugging
	public void testShowMessage() {

		JLabel label = new JLabel("<html>This is<br>some text that<br>spans multiple lines.");

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(label);

		DockingFrame frame = new DockingFrame("Test Frame");
		frame.getContentPane().add(panel);
		GGlassPane glassPane = new GGlassPane();
		frame.setGlassPane(glassPane);
		frame.setSize(400, 400);
		frame.setVisible(true);

		GGlassPaneMessage glassPaneMessage = new GGlassPaneMessage(label);
		glassPaneMessage
				.showCenteredMessage(
					"This is a test and (newline\n\nhere) some more text to reach the width limit.  " +
						"More text to (tab here\t\t) to come as we type.");
		fail();
	}

	@Test
	public void testShaper() {

		BufferedImage tempImage = new BufferedImage(10, 10, BufferedImage.TYPE_INT_ARGB);
		Graphics2D scratchG2d = (Graphics2D) tempImage.getGraphics();
		Font font = Gui.getFont("font.monospaced").deriveFont(24);
		scratchG2d.setFont(font);

		Dimension size = new Dimension(1000, 100);
		String message = "This is a message";
		TextShaper shaper = new TextShaper(message, size, scratchG2d);

		List<TextShaperLine> lines = shaper.getLines();
		assertEquals(1, lines.size());
		assertFalse(shaper.isClipped());
	}

	@Test
	public void testShaper_LineWrap() {

		BufferedImage tempImage = new BufferedImage(10, 10, BufferedImage.TYPE_INT_ARGB);
		Graphics2D scratchG2d = (Graphics2D) tempImage.getGraphics();
		Font font = Gui.getFont("font.monospaced").deriveFont(24);
		scratchG2d.setFont(font);

		Dimension size = new Dimension(100, 100);
		String message = "This is a long message";
		TextShaper shaper = new TextShaper(message, size, scratchG2d);

		List<TextShaperLine> lines = shaper.getLines();
		assertEquals(2, lines.size());
		assertFalse(shaper.isClipped());
	}

	@Test
	public void testShaper_NewLine() {

		BufferedImage tempImage = new BufferedImage(10, 10, BufferedImage.TYPE_INT_ARGB);
		Graphics2D scratchG2d = (Graphics2D) tempImage.getGraphics();
		Font font = Gui.getFont("font.monospaced").deriveFont(24);
		scratchG2d.setFont(font);

		Dimension size = new Dimension(1000, 100);
		String message = "This is a long\nmessage";
		TextShaper shaper = new TextShaper(message, size, scratchG2d);

		List<TextShaperLine> lines = shaper.getLines();
		assertEquals(2, lines.size());
		assertEquals("This is a long", lines.get(0).getText());
		assertEquals("message", lines.get(1).getText());
		assertFalse(shaper.isClipped());
	}

	@Test
	public void testShaper_NewLines_Consecutive() {

		BufferedImage tempImage = new BufferedImage(10, 10, BufferedImage.TYPE_INT_ARGB);
		Graphics2D scratchG2d = (Graphics2D) tempImage.getGraphics();
		Font font = Gui.getFont("font.monospaced").deriveFont(24);
		scratchG2d.setFont(font);

		Dimension size = new Dimension(1000, 100);
		String message = "This is a long\n\nmessage";
		TextShaper shaper = new TextShaper(message, size, scratchG2d);

		List<TextShaperLine> lines = shaper.getLines();
		assertEquals(3, lines.size());
		assertEquals("This is a long", lines.get(0).getText());
		assertEquals("\n", lines.get(1).getText());
		assertEquals("message", lines.get(2).getText());
		assertFalse(shaper.isClipped());
	}

	@Test
	public void testShaper_NewLines_AroundText() {

		BufferedImage tempImage = new BufferedImage(10, 10, BufferedImage.TYPE_INT_ARGB);
		Graphics2D scratchG2d = (Graphics2D) tempImage.getGraphics();
		Font font = Gui.getFont("font.monospaced").deriveFont(24);
		scratchG2d.setFont(font);

		Dimension size = new Dimension(1000, 100);
		String message = "\n\nThis is a long message\n\n";
		TextShaper shaper = new TextShaper(message, size, scratchG2d);

		List<TextShaperLine> lines = shaper.getLines();
		assertEquals(1, lines.size());
		assertFalse(shaper.isClipped());
	}

	@Test
	public void testShaper_Tabs() {

		BufferedImage tempImage = new BufferedImage(10, 10, BufferedImage.TYPE_INT_ARGB);
		Graphics2D scratchG2d = (Graphics2D) tempImage.getGraphics();
		Font font = Gui.getFont("font.monospaced").deriveFont(24);
		scratchG2d.setFont(font);

		Dimension size = new Dimension(1000, 100);
		String message = "This is a\t\tmessage";
		TextShaper shaper = new TextShaper(message, size, scratchG2d);

		List<TextShaperLine> lines = shaper.getLines();
		assertEquals(1, lines.size());
		assertEquals("This is a        message", lines.get(0).getText());
		assertFalse(shaper.isClipped());
	}
}
