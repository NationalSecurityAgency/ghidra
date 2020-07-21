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
package resources.icons;

import java.awt.*;
import java.awt.image.BufferedImage;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.junit.Test;

import resources.MultiIconBuilder;
import resources.QUADRANT;

/**
 * Minimal tests for MultiIconBuilder.  Doesn't test the produced images, just that it didn't cause an exception.
 * <p>
 * The showXYZ() methods are present so a human can run them as a test and see the output  
 */
public class MultiIconBuilderTest {

	private ImageIcon makeEmptyIcon(int w, int h, Color color) {
		BufferedImage bi = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
		if (color != null) {
			Graphics g = bi.getGraphics();
			g.setColor(color);
			g.fillRect(0, 0, w, h);
			g.dispose();
		}
		return new ImageIcon(bi);
	}

	private ImageIcon makeQuandrantIcon(int w, int h, Color bgColor, Color lineColor) {
		BufferedImage bi = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
		Graphics g = bi.getGraphics();
		g.setColor(bgColor);
		g.fillRect(0, 0, w, h);
		g.setColor(lineColor);
		g.drawLine(w / 2, 0, w / 2, h);
		g.drawLine(0, h / 2, w, h / 2);
		g.dispose();
		return new ImageIcon(bi);
	}

	private Font font = new Font("Monospaced", Font.PLAIN, 12);

	//@Test
	public void showIconText() {
		for (QUADRANT quad : QUADRANT.values()) {
			ImageIcon icon =
				new MultiIconBuilder(makeQuandrantIcon(32, 32, Color.gray, Color.white))
						.addText("Abcfg", font, Color.red, quad)
						.build();
			JOptionPane.showMessageDialog(null, "" + quad + " aligned", "Icon text overlay test",
				JOptionPane.OK_OPTION, icon);
		}
	}

	//@Test
	public void showIconOverlay() {
		for (QUADRANT quad : QUADRANT.values()) {
			ImageIcon icon = new MultiIconBuilder(makeEmptyIcon(32, 32, Color.gray))
					.addIcon(makeEmptyIcon(8, 8, Color.red), 8, 8, quad)
					.build();
			JOptionPane.showMessageDialog(null, "" + quad + " aligned", "Icon_icon overlay test",
				JOptionPane.OK_OPTION, icon);
		}
	}

	//@Test
	public void showScaledIconOverlay() {
		for (QUADRANT quad : QUADRANT.values()) {
			ImageIcon icon = new MultiIconBuilder(makeEmptyIcon(32, 32, Color.gray))
					.addIcon(makeQuandrantIcon(32, 32, Color.red, Color.black), 14, 14, quad)
					.build();
			JOptionPane.showMessageDialog(null, "" + quad + " aligned",
				"Scaled icon_icon overlay test",
				JOptionPane.OK_OPTION, icon);
		}
	}

	@Test
	public void testIconOverlay() {
		// doesn't verify anything other than it doesn't fall down go boom
		for (QUADRANT quad : QUADRANT.values()) {
			ImageIcon icon = new MultiIconBuilder(makeEmptyIcon(32, 32, Color.gray))
					.addIcon(makeQuandrantIcon(32, 32, Color.red, Color.black), 14, 14, quad)
					.build();
			icon.getDescription();
		}
	}

	@Test
	public void testIconText() {
		// doesn't verify anything other than it doesn't fall down go boom
		for (QUADRANT quad : QUADRANT.values()) {
			ImageIcon icon =
				new MultiIconBuilder(makeQuandrantIcon(32, 32, Color.gray, Color.white))
						.addText("Abcfg", font, Color.red, quad)
						.build();
			icon.getDescription();
		}
	}
}
