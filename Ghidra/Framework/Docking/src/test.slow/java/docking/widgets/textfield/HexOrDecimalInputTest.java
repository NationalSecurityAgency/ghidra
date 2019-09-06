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
package docking.widgets.textfield;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

import java.awt.*;
import java.awt.RenderingHints.Key;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.font.FontRenderContext;
import java.awt.font.GlyphVector;
import java.awt.geom.AffineTransform;
import java.awt.image.*;
import java.awt.image.renderable.RenderableImage;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.text.AttributedCharacterIterator;
import java.util.Map;

import javax.swing.DebugGraphics;
import javax.swing.RepaintManager;

import org.hamcrest.CoreMatchers;
import org.junit.Test;

public class HexOrDecimalInputTest {

	@Test
	public void testSetAllowNegative() {
		HexOrDecimalInput input = new HexOrDecimalInput();

		Long newValue = -1L;
		input.setValue(newValue);

		assertThat(input.getValue(), is(newValue));

		input.setAllowNegative(false);
		assertThat(input.getValue(), nullValue());

		newValue = 20L;
		input.setValue(newValue);
		assertThat(input.getValue(), is(newValue));

		newValue = -100L;
		input.setValue(newValue);
		assertThat(input.getValue(), nullValue());

		input.setAllowNegative(true);
		newValue = -100L;
		input.setValue(newValue);
		assertThat(input.getValue(), is(newValue));
	}

	@Test
	public void testCustomPaint() {

		HexOrDecimalInput input = new HexOrDecimalInput();
		RepaintManager repaintManager = RepaintManager.currentManager(input);
		repaintManager.setDoubleBufferingEnabled(false);

		SpyPrintStream spy = new SpyPrintStream();
		DebugGraphics.setLogStream(spy);

		DebugGraphics debugGraphics = new DebugGraphics(scratchGraphics());
		debugGraphics.setDebugOptions(DebugGraphics.LOG_OPTION);

		Graphics2D g2d = new Graphics2DAdapter(debugGraphics);
		input.paintComponent(g2d);
		assertThat(spy.toString(), CoreMatchers.containsString("Dec"));

		spy.reset();
		input.setHexMode();
		input.paintComponent(g2d);
		assertThat(spy.toString(), CoreMatchers.containsString("Hex"));

		spy.reset();
		input.setDecimalMode();
		input.paintComponent(g2d);
		assertThat(spy.toString(), CoreMatchers.containsString("Dec"));
	}

	@Test
	public void testToggleHexModeFromKeybinding() {
		HexOrDecimalInput input = new HexOrDecimalInput();
		Long value = 10L;
		input.setValue(value);

		assertThat(input.getValue(), is(value));

		toggleMode(input);

		assertThat(input.getValue(), is(0xAL));

		toggleMode(input);

		assertThat(input.getValue(), is(value));
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private void toggleMode(final HexOrDecimalInput input) {
		KeyEvent event = new KeyEvent(input, 0, System.currentTimeMillis(), 0, KeyEvent.VK_M, 'm');
		KeyListener[] keyListeners = input.getKeyListeners();
		for (KeyListener listener : keyListeners) {
			listener.keyPressed(event);
		}
	}

	private Graphics scratchGraphics() {
		BufferedImage image = new BufferedImage(100, 20, BufferedImage.TYPE_INT_BGR);
		return image.getGraphics();
	}

	private static class SpyPrintStream extends PrintStream {
		private static ByteArrayOutputStream baos = new ByteArrayOutputStream();

		SpyPrintStream() {
			super(baos);
		}

		void reset() {
			baos.reset();
		}

		@Override
		public String toString() {
			return baos.toString();
		}
	}

	/**
	 * An adapter to turn a Graphics into a Graphics2D.  This implementation satisfies the base 
	 * methods needed for the test.  So, many operations are stubbed or are exceptional. 
	 */
	private static class Graphics2DAdapter extends Graphics2D {

		private Graphics delegate;

		Graphics2DAdapter(Graphics g) {
			this.delegate = g;
		}

		@Override
		public void draw(Shape s) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean drawImage(Image img, AffineTransform xform, ImageObserver obs) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void drawImage(BufferedImage img, BufferedImageOp op, int x, int y) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void drawRenderedImage(RenderedImage img, AffineTransform xform) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void drawRenderableImage(RenderableImage img, AffineTransform xform) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void drawString(String str, int x, int y) {
			delegate.drawString(str, x, y);
		}

		@Override
		public void drawString(String str, float x, float y) {
			delegate.drawString(str, (int) x, (int) y);
		}

		@Override
		public void drawString(AttributedCharacterIterator iterator, int x, int y) {
			delegate.drawString(iterator, x, y);
		}

		@Override
		public void drawString(AttributedCharacterIterator iterator, float x, float y) {
			delegate.drawString(iterator, (int) x, (int) y);
		}

		@Override
		public void drawGlyphVector(GlyphVector g, float x, float y) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void fill(Shape s) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean hit(Rectangle rect, Shape s, boolean onStroke) {
			throw new UnsupportedOperationException();
		}

		@Override
		public GraphicsConfiguration getDeviceConfiguration() {
			throw new UnsupportedOperationException();
		}

		@Override
		public void setComposite(Composite comp) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void setPaint(Paint paint) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void setStroke(Stroke s) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void setRenderingHint(Key hintKey, Object hintValue) {
			// no-op
		}

		@Override
		public Object getRenderingHint(Key hintKey) {
			return null;
		}

		@Override
		public void setRenderingHints(Map<?, ?> hints) {
			// no-op
		}

		@Override
		public void addRenderingHints(Map<?, ?> hints) {
			throw new UnsupportedOperationException();
		}

		@Override
		public RenderingHints getRenderingHints() {
			throw new UnsupportedOperationException();
		}

		@Override
		public void translate(int x, int y) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void translate(double tx, double ty) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void rotate(double theta) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void rotate(double theta, double x, double y) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void scale(double sx, double sy) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void shear(double shx, double shy) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void transform(AffineTransform Tx) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void setTransform(AffineTransform Tx) {
			throw new UnsupportedOperationException();
		}

		@Override
		public AffineTransform getTransform() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Paint getPaint() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Composite getComposite() {
			throw new UnsupportedOperationException();
		}

		@Override
		public void setBackground(Color color) {
			throw new UnsupportedOperationException();
		}

		@Override
		public Color getBackground() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Stroke getStroke() {
			throw new UnsupportedOperationException();
		}

		@Override
		public void clip(Shape s) {
			throw new UnsupportedOperationException();
		}

		@Override
		public FontRenderContext getFontRenderContext() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Graphics create() {
			return delegate.create();
		}

		@Override
		public Color getColor() {
			return delegate.getColor();
		}

		@Override
		public void setColor(Color c) {
			delegate.setColor(c);
		}

		@Override
		public void setPaintMode() {
			throw new UnsupportedOperationException();
		}

		@Override
		public void setXORMode(Color c1) {
			delegate.setXORMode(c1);
		}

		@Override
		public Font getFont() {
			return delegate.getFont();
		}

		@Override
		public void setFont(Font font) {
			delegate.setFont(font);
		}

		@Override
		public FontMetrics getFontMetrics(Font f) {
			return delegate.getFontMetrics();
		}

		@Override
		public Rectangle getClipBounds() {
			return delegate.getClipBounds();
		}

		@Override
		public void clipRect(int x, int y, int width, int height) {
			delegate.clipRect(x, y, width, height);
		}

		@Override
		public void setClip(int x, int y, int width, int height) {
			delegate.setClip(x, y, width, height);
		}

		@Override
		public Shape getClip() {
			return delegate.getClip();
		}

		@Override
		public void setClip(Shape clip) {
			delegate.setClip(clip);
		}

		@Override
		public void copyArea(int x, int y, int width, int height, int dx, int dy) {
			delegate.copyArea(x, y, width, height, dx, dy);
		}

		@Override
		public void drawLine(int x1, int y1, int x2, int y2) {
			delegate.drawLine(x1, y1, x2, y2);
		}

		@Override
		public void fillRect(int x, int y, int width, int height) {
			delegate.fillRect(x, y, width, height);
		}

		@Override
		public void clearRect(int x, int y, int width, int height) {
			delegate.clearRect(x, y, width, height);
		}

		@Override
		public void drawRoundRect(int x, int y, int width, int height, int arcWidth,
				int arcHeight) {
			delegate.drawRoundRect(x, y, width, height, arcWidth, arcHeight);
		}

		@Override
		public void fillRoundRect(int x, int y, int width, int height, int arcWidth,
				int arcHeight) {
			delegate.fillRoundRect(x, y, width, height, arcWidth, arcHeight);
		}

		@Override
		public void drawOval(int x, int y, int width, int height) {
			delegate.drawOval(x, y, width, height);
		}

		@Override
		public void fillOval(int x, int y, int width, int height) {
			delegate.fillOval(x, y, width, height);
		}

		@Override
		public void drawArc(int x, int y, int width, int height, int startAngle, int arcAngle) {
			delegate.drawArc(x, y, width, height, startAngle, arcAngle);
		}

		@Override
		public void fillArc(int x, int y, int width, int height, int startAngle, int arcAngle) {
			delegate.fillArc(x, y, width, height, startAngle, arcAngle);
		}

		@Override
		public void drawPolyline(int[] xPoints, int[] yPoints, int nPoints) {
			delegate.drawPolyline(xPoints, yPoints, nPoints);
		}

		@Override
		public void drawPolygon(int[] xPoints, int[] yPoints, int nPoints) {
			delegate.drawPolygon(xPoints, yPoints, nPoints);
		}

		@Override
		public void fillPolygon(int[] xPoints, int[] yPoints, int nPoints) {
			delegate.fillPolygon(null);
		}

		@Override
		public boolean drawImage(Image img, int x, int y, ImageObserver observer) {
			return delegate.drawImage(img, x, y, observer);
		}

		@Override
		public boolean drawImage(Image img, int x, int y, int width, int height,
				ImageObserver observer) {
			return delegate.drawImage(img, x, y, width, height, observer);
		}

		@Override
		public boolean drawImage(Image img, int x, int y, Color bgcolor, ImageObserver observer) {
			return delegate.drawImage(img, x, y, bgcolor, observer);
		}

		@Override
		public boolean drawImage(Image img, int x, int y, int width, int height, Color bgcolor,
				ImageObserver observer) {
			return delegate.drawImage(img, x, y, width, height, bgcolor, observer);
		}

		@Override
		public boolean drawImage(Image img, int dx1, int dy1, int dx2, int dy2, int sx1, int sy1,
				int sx2, int sy2, ImageObserver observer) {
			return delegate.drawImage(img, dx1, dy1, dx2, dy2, sx1, sy1, sx2, sy2, observer);
		}

		@Override
		public boolean drawImage(Image img, int dx1, int dy1, int dx2, int dy2, int sx1, int sy1,
				int sx2, int sy2, Color bgcolor, ImageObserver observer) {
			return delegate.drawImage(img, dx1, dy1, dx2, dy2, sx1, sy1, sx2, sy2, bgcolor,
				observer);
		}

		@Override
		public void dispose() {
			delegate.dispose();
		}

	}
}
