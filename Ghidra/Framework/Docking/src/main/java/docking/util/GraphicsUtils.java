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

import java.awt.*;

import javax.swing.JComponent;
import javax.swing.plaf.basic.BasicGraphicsUtils;

import ghidra.util.exception.AssertException;

public class GraphicsUtils {
	public static void drawString(JComponent c, Graphics g, String text, int x, int y) {
		BasicGraphicsUtils.drawString(c, getGraphics2D(g), text, x, y);
	}

	public static void drawString(JComponent c, Graphics2D g2d, String text, int x, int y) {
		BasicGraphicsUtils.drawString(c, g2d, text, x, y);
	}

	public static Graphics2D getGraphics2D(Graphics g) {
		if (g instanceof Graphics2D) {
			return (Graphics2D) g;
		}
		throw new AssertException("Expected Graphics2D but got: " + g.getClass().getName());
	}

	public static int stringWidth(JComponent c, FontMetrics fm, String string) {
		return (int) BasicGraphicsUtils.getStringWidth(c, fm, string);
	}
}
