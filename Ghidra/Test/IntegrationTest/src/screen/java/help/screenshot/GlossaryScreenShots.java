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
package help.screenshot;

import java.awt.*;
import java.awt.image.BufferedImage;

import org.junit.Test;

public class GlossaryScreenShots extends GhidraScreenShotGenerator {

	public GlossaryScreenShots() {
		super();
	}

@Test
    public void testBigEndian() {

		//Draw empty white rectangle		
		image = new BufferedImage(450, 100, BufferedImage.TYPE_INT_ARGB);
		Graphics g = image.getGraphics();
		g.setColor(Color.WHITE);
		g.fillRect(0, 0, 450, 125);

		//Draw box with line in the middle
		Point p1 = new Point(30, 10);
		Point p2 = new Point(430, 10);
		Point p3 = new Point(430, 50);
		Point p4 = new Point(30, 50);

		Point p5 = new Point(225, 10);
		Point p6 = new Point(225, 50);

		drawLine(Color.BLACK, 1, p1, p2);
		drawLine(Color.BLACK, 1, p2, p3);
		drawLine(Color.BLACK, 1, p3, p4);
		drawLine(Color.BLACK, 1, p4, p1);

		drawLine(Color.BLACK, 1, p5, p6);

		//Draw Text in boxes
		drawText("high-order byte", Color.BLACK, new Point(80, 35), 12);
		drawText("low-order byte", Color.BLACK, new Point(285, 35), 12);

		//Draw arrows
		Point p7 = new Point(30, 50);
		Point p8 = new Point(30, 80);
		Point p9 = new Point(225, 50);
		Point p10 = new Point(225, 80);

		drawArrow(Color.BLACK, 1, p8, p7, 6);
		drawArrow(Color.BLACK, 1, p10, p9, 6);

		//Draw arrow text
		drawText("addr A", Color.BLACK, new Point(15, 93), 12);
		drawText("addr A+1", Color.BLACK, new Point(200, 93), 12);

	}

@Test
    public void testLittleEndian() {

		//Draw empty white rectangle		
		image = new BufferedImage(450, 100, BufferedImage.TYPE_INT_ARGB);
		Graphics g = image.getGraphics();
		g.setColor(Color.WHITE);
		g.fillRect(0, 0, 450, 125);

		//Draw box with line in the middle
		Point p1 = new Point(30, 10);
		Point p2 = new Point(430, 10);
		Point p3 = new Point(430, 50);
		Point p4 = new Point(30, 50);

		Point p5 = new Point(225, 10);
		Point p6 = new Point(225, 50);

		drawLine(Color.BLACK, 1, p1, p2);
		drawLine(Color.BLACK, 1, p2, p3);
		drawLine(Color.BLACK, 1, p3, p4);
		drawLine(Color.BLACK, 1, p4, p1);

		drawLine(Color.BLACK, 1, p5, p6);

		//Draw Text in boxes
		drawText("high-order byte", Color.BLACK, new Point(80, 35), 12);
		drawText("low-order byte", Color.BLACK, new Point(285, 35), 12);

		//Draw arrows
		Point p7 = new Point(430, 50);
		Point p8 = new Point(430, 80);
		Point p9 = new Point(225, 50);
		Point p10 = new Point(225, 80);

		drawArrow(Color.BLACK, 1, p8, p7, 6);
		drawArrow(Color.BLACK, 1, p10, p9, 6);

		//Draw arrow text		
		drawText("addr A+1", Color.BLACK, new Point(200, 93), 12);
		drawText("addr A", Color.BLACK, new Point(413, 93), 12);

	}
}
