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
package docking.util.image;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.image.*;

import javax.swing.*;

import generic.theme.GThemeDefaults.Colors.Palette;

public class DropShadow {

	private Color shadowColor = Palette.BLACK;
	private float shadowOpacity = 0.85f;

	private void applyShadow(BufferedImage image, int shadowSize) {
		int imgWidth = image.getWidth();
		int imgHeight = image.getHeight();

		int left = (shadowSize - 1) >> 1;
		int right = shadowSize - left;
		int xStart = left;
		int xStop = imgWidth - right;
		int yStart = left;
		int yStop = imgHeight - right;

		int shadowRgb = shadowColor.getRGB() & 0x00ffffff;
		int[] aHistory = new int[shadowSize];

		int[] data = ((DataBufferInt) image.getRaster().getDataBuffer()).getData();
		int lastPixelOffset = right * imgWidth;
		float sumDivider = shadowOpacity / shadowSize;

		// horizontal pass
		for (int y = 0, pixel = 0; y < imgHeight; y++, pixel = y * imgWidth) {
			int aSum = 0;
			int history = 0;
			for (int x = 0; x < shadowSize; x++, pixel++) {
				int a = data[pixel] >>> 24;
				aHistory[x] = a;
				aSum += a;
			}

			pixel -= right;

			for (int x = xStart; x < xStop; x++, pixel++) {
				int a = (int) (aSum * sumDivider);
				data[pixel] = a << 24 | shadowRgb;

				// subtract the oldest pixel from the sum
				aSum -= aHistory[history];

				// get the latest pixel
				a = data[pixel + right] >>> 24;
				aHistory[history] = a;
				aSum += a;

				if (++history >= shadowSize) {
					history -= shadowSize;
				}
			}
		}

		// vertical pass
		for (int x = 0, bufferOffset = 0; x < imgWidth; x++, bufferOffset = x) {
			int aSum = 0;
			int history = 0;
			for (int y = 0; y < shadowSize; y++, bufferOffset += imgWidth) {
				int a = data[bufferOffset] >>> 24;
				aHistory[y] = a;
				aSum += a;
			}

			bufferOffset -= lastPixelOffset;

			for (int y = yStart; y < yStop; y++, bufferOffset += imgWidth) {
				int a = (int) (aSum * sumDivider);
				data[bufferOffset] = a << 24 | shadowRgb;

				// subtract the oldest pixel from the sum
				aSum -= aHistory[history];

				// get the latest pixel
				a = data[bufferOffset + lastPixelOffset] >>> 24;
				aHistory[history] = a;
				aSum += a;

				if (++history >= shadowSize) {
					history -= shadowSize;
				}
			}
		}
	}

	private BufferedImage prepareImage(BufferedImage image, int shadowSize) {
		int width = image.getWidth() + (shadowSize * 2);
		int height = image.getHeight() + (shadowSize * 2);
		BufferedImage subject = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);

		Graphics2D g2 = subject.createGraphics();
		g2.drawImage(image, null, shadowSize, shadowSize);
		g2.dispose();

		return subject;
	}

	public Image createDropShadow(BufferedImage image, int shadowSize) {
		BufferedImage subject = prepareImage(image, shadowSize);
		applyShadow(subject, shadowSize);
		return subject;
	}

	public static void main(String[] args) {

		final DropShadow ds = new DropShadow();

		final JPanel canvas = new JPanel() {

			BufferedImage image = null;
			Image shadow = null;

			@Override
			protected void paintComponent(Graphics g) {
				Graphics2D g2d = (Graphics2D) g;
				Color background = Palette.WHITE;
				g.setColor(background);
				Dimension size = getSize();
				g.fillRect(0, 0, size.width, size.height);

//				if (image == null) {
				GraphicsConfiguration gc = g2d.getDeviceConfiguration();
				VolatileImage newImage = gc.createCompatibleVolatileImage(size.width, size.height,
					Transparency.TRANSLUCENT);
				g2d = (Graphics2D) newImage.getGraphics();

				// update all pixels to have 0 alpha
				g2d.setComposite(AlphaComposite.Clear);
				g2d.fillRect(0, 0, size.width, size.height);

				// render the clip shape into the image
				g2d.setComposite(AlphaComposite.Src);
				g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
					RenderingHints.VALUE_ANTIALIAS_ON);
				g2d.setColor(Palette.WHITE);
				g2d.fillOval(size.width / 4, size.height / 4, size.width / 2, size.height / 2);

				// Using ScrAtop uses the alpha value as a coverage for each pixel stored in
				// the destination.  For the areas outside the clip shape, the destination alpha will
				// be zero, so nothing is rendered in those areas.
				g2d.setComposite(AlphaComposite.SrcAtop);
				g2d.setPaint(new GradientPaint(0, 0, Palette.RED, 0, size.height, Palette.YELLOW));
				g2d.fillRect(0, 0, size.width, size.height);
				g2d.dispose();

				BufferedImage bufferedImage =
					new BufferedImage(size.width, size.height, BufferedImage.TYPE_INT_ARGB);
				Graphics graphics = bufferedImage.getGraphics();
				graphics.drawImage(newImage, 0, 0, null);
				graphics.dispose();
				image = bufferedImage;

				shadow = ds.createDropShadow(bufferedImage, 5);

//				}

				g.drawImage(shadow, 10, 10, null);
				g.drawImage(image, 0, 0, null);
			}
		};

		canvas.setPreferredSize(new Dimension(600, 600));

		JFrame frame = new JFrame("Test");
		Container contentPane = frame.getContentPane();
		contentPane.setLayout(new BorderLayout());
		contentPane.add(canvas);
		canvas.addMouseMotionListener(new MouseAdapter() {
			@Override
			public void mouseDragged(MouseEvent e) {
//				lastPoint.x = e.getX();
//				lastPoint.y = e.getY();
				canvas.repaint();
			}
		});
		frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

		frame.setVisible(true);
		frame.pack();
	}
}
