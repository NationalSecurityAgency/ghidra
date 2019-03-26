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
package ghidra.docking.util.painting;

import java.awt.*;
import java.awt.MultipleGradientPaint.CycleMethod;
import java.awt.RenderingHints.Key;
import java.awt.font.FontRenderContext;
import java.awt.font.GlyphVector;
import java.awt.geom.AffineTransform;
import java.awt.geom.Point2D;
import java.awt.image.*;
import java.awt.image.renderable.RenderableImage;
import java.text.AttributedCharacterIterator;
import java.util.Map;

/**
 * A simple wrapper object that changes colors passed to {@link Graphics2D}.
 */
public class Graphics2DWrapper extends Graphics2D {

	private Graphics2D delegate;

	public Graphics2DWrapper() {
		// delegate set later
	}

	private Graphics2DWrapper(Graphics2D delegate) {
		setDelegate(delegate);
	}

	public void setDelegate(Graphics2D delegate) {
		this.delegate = delegate;

		setColor(delegate.getColor());
		setBackground(delegate.getBackground());
		setPaint(delegate.getPaint());
	}

	@Override
	public int hashCode() {
		return delegate.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		return delegate.equals(obj);
	}

	@Override
	public Graphics create() {
		return new Graphics2DWrapper((Graphics2D) delegate.create());
	}

	@Override
	public Graphics create(int x, int y, int width, int height) {
		return new Graphics2DWrapper((Graphics2D) delegate.create(x, y, width, height));
	}

	@Override
	public Color getColor() {
		// 
		// Clients will call this method to later restore this Graphic's color.  So, we must
		// revert the color or it will get restored incorrectly.
		//
		Color alt = delegate.getColor();
		Color orig = getComplementaryColor(alt);
		return orig;
	}

	private static Color getComplementaryColor(Color c) {

		if (c == null) {
			return null;
		}

		Color alt = new Color(255 - c.getRed(), 255 - c.getGreen(), 255 - c.getBlue());
		return alt;
	}

	@Override
	public void setBackground(Color c) {
		Color alt = getComplementaryColor(c);
		delegate.setBackground(alt);
	}

	@Override
	public Color getBackground() {
		// 
		// Clients will call this method to later restore this Graphic's color.  So, we must
		// revert the color or it will get restored incorrectly.
		//
		Color alt = delegate.getBackground();
		Color orig = getComplementaryColor(alt);
		return orig;
	}

	@Override
	public void setColor(Color c) {
		Color alt = getComplementaryColor(c);
		delegate.setColor(alt);
	}

	@Override
	public Paint getPaint() {
		Paint alt = delegate.getPaint();

		if (alt instanceof Color) {
			Color c = (Color) alt;
			Color orig = getComplementaryColor(c);
			return orig;
		}
		else if (alt instanceof GradientPaint) {
			GradientPaint gp = (GradientPaint) alt;
			Color alt1 = getComplementaryColor(gp.getColor1());
			Color alt2 = getComplementaryColor(gp.getColor2());
			GradientPaint orig =
				new GradientPaint(gp.getPoint1(), alt1, gp.getPoint2(), alt2, gp.isCyclic());
			return orig;
		}
		else if (alt instanceof LinearGradientPaint) {

			LinearGradientPaint gp = (LinearGradientPaint) alt;
			Color[] colors = gp.getColors();
			float[] fractions = gp.getFractions();
			Point2D start = gp.getStartPoint();
			Point2D end = gp.getEndPoint();
			CycleMethod cycleMethod = gp.getCycleMethod();
			LinearGradientPaint orig =
				new LinearGradientPaint(start, end, fractions, colors, cycleMethod);
			return orig;
		}
		else {
			// Else case from  setPaint()
		}

		return alt;
	}

	@Override
	public void setPaint(Paint paint) {

		if (paint instanceof Color) {
			Color c = (Color) paint;
			Color alt = getComplementaryColor(c);
			delegate.setPaint(alt);
		}
		else if (paint instanceof GradientPaint) {
			GradientPaint gp = (GradientPaint) paint;
			Color alt1 = getComplementaryColor(gp.getColor1());
			Color alt2 = getComplementaryColor(gp.getColor2());
			GradientPaint alt =
				new GradientPaint(gp.getPoint1(), alt1, gp.getPoint2(), alt2, gp.isCyclic());
			delegate.setPaint(alt);
		}
		else if (paint instanceof LinearGradientPaint) {

			LinearGradientPaint gp = (LinearGradientPaint) paint;
			Color[] colors = gp.getColors();
			float[] fractions = gp.getFractions();
			Point2D start = gp.getStartPoint();
			Point2D end = gp.getEndPoint();
			CycleMethod cycleMethod = gp.getCycleMethod();
			LinearGradientPaint alt =
				new LinearGradientPaint(start, end, fractions, colors, cycleMethod);
			delegate.setPaint(alt);
		}
		else {

			System.err.println("G2DWrapper - non-Color Paint: " + paint.getClass().getSimpleName());
			delegate.setPaint(paint);
		}
	}

	@Override
	public void setPaintMode() {
		delegate.setPaintMode();
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
	public FontMetrics getFontMetrics() {
		return delegate.getFontMetrics();
	}

	@Override
	public FontMetrics getFontMetrics(Font f) {
		return delegate.getFontMetrics(f);
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
	public void drawRect(int x, int y, int width, int height) {
		delegate.drawRect(x, y, width, height);
	}

	@Override
	public void draw3DRect(int x, int y, int width, int height, boolean raised) {
		delegate.draw3DRect(x, y, width, height, raised);
	}

	@Override
	public void clearRect(int x, int y, int width, int height) {
		delegate.clearRect(x, y, width, height);
	}

	@Override
	public void drawRoundRect(int x, int y, int width, int height, int arcWidth, int arcHeight) {
		delegate.drawRoundRect(x, y, width, height, arcWidth, arcHeight);
	}

	@Override
	public void fill3DRect(int x, int y, int width, int height, boolean raised) {
		delegate.fill3DRect(x, y, width, height, raised);
	}

	@Override
	public void fillRoundRect(int x, int y, int width, int height, int arcWidth, int arcHeight) {
		delegate.fillRoundRect(x, y, width, height, arcWidth, arcHeight);
	}

	@Override
	public void draw(Shape s) {
		delegate.draw(s);
	}

	@Override
	public boolean drawImage(Image img, AffineTransform xform, ImageObserver obs) {
		return delegate.drawImage(img, xform, obs);
	}

	@Override
	public void drawImage(BufferedImage img, BufferedImageOp op, int x, int y) {
		delegate.drawImage(img, op, x, y);
	}

	@Override
	public void drawOval(int x, int y, int width, int height) {
		delegate.drawOval(x, y, width, height);
	}

	@Override
	public void drawRenderedImage(RenderedImage img, AffineTransform xform) {
		delegate.drawRenderedImage(img, xform);
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
	public void drawRenderableImage(RenderableImage img, AffineTransform xform) {
		delegate.drawRenderableImage(img, xform);
	}

	@Override
	public void drawString(String str, int x, int y) {
		delegate.drawString(str, x, y);
	}

	@Override
	public void fillArc(int x, int y, int width, int height, int startAngle, int arcAngle) {
		delegate.fillArc(x, y, width, height, startAngle, arcAngle);
	}

	@Override
	public void drawString(String str, float x, float y) {
		delegate.drawString(str, x, y);
	}

	@Override
	public void drawPolyline(int[] xPoints, int[] yPoints, int nPoints) {
		delegate.drawPolyline(xPoints, yPoints, nPoints);
	}

	@Override
	public void drawString(AttributedCharacterIterator iterator, int x, int y) {
		delegate.drawString(iterator, x, y);
	}

	@Override
	public void drawPolygon(int[] xPoints, int[] yPoints, int nPoints) {
		delegate.drawPolygon(xPoints, yPoints, nPoints);
	}

	@Override
	public void drawString(AttributedCharacterIterator iterator, float x, float y) {
		delegate.drawString(iterator, x, y);
	}

	@Override
	public void drawPolygon(Polygon p) {
		delegate.drawPolygon(p);
	}

	@Override
	public void fillPolygon(int[] xPoints, int[] yPoints, int nPoints) {
		delegate.fillPolygon(xPoints, yPoints, nPoints);
	}

	@Override
	public void drawGlyphVector(GlyphVector g, float x, float y) {
		delegate.drawGlyphVector(g, x, y);
	}

	@Override
	public void fillPolygon(Polygon p) {
		delegate.fillPolygon(p);
	}

	@Override
	public void fill(Shape s) {
		delegate.fill(s);
	}

	@Override
	public boolean hit(Rectangle rect, Shape s, boolean onStroke) {
		return delegate.hit(rect, s, onStroke);
	}

	@Override
	public void drawChars(char[] data, int offset, int length, int x, int y) {
		delegate.drawChars(data, offset, length, x, y);
	}

	@Override
	public GraphicsConfiguration getDeviceConfiguration() {
		return delegate.getDeviceConfiguration();
	}

	@Override
	public void setComposite(Composite comp) {
		delegate.setComposite(comp);
	}

	@Override
	public void drawBytes(byte[] data, int offset, int length, int x, int y) {
		delegate.drawBytes(data, offset, length, x, y);
	}

	@Override
	public boolean drawImage(Image img, int x, int y, ImageObserver observer) {

		return delegate.drawImage(img, x, y, observer);
	}

	@Override
	public void setStroke(Stroke s) {
		delegate.setStroke(s);
	}

	@Override
	public void setRenderingHint(Key hintKey, Object hintValue) {
		delegate.setRenderingHint(hintKey, hintValue);
	}

	@Override
	public Object getRenderingHint(Key hintKey) {
		return delegate.getRenderingHint(hintKey);
	}

	@Override
	public boolean drawImage(Image img, int x, int y, int width, int height,
			ImageObserver observer) {
		return delegate.drawImage(img, x, y, width, height, observer);
	}

	@Override
	public void setRenderingHints(Map<?, ?> hints) {
		delegate.setRenderingHints(hints);
	}

	@Override
	public void addRenderingHints(Map<?, ?> hints) {
		delegate.addRenderingHints(hints);
	}

	@Override
	public RenderingHints getRenderingHints() {
		return delegate.getRenderingHints();
	}

	@Override
	public boolean drawImage(Image img, int x, int y, Color bgcolor, ImageObserver observer) {
		return delegate.drawImage(img, x, y, bgcolor, observer);
	}

	@Override
	public void translate(int x, int y) {
		delegate.translate(x, y);
	}

	@Override
	public void translate(double tx, double ty) {
		delegate.translate(tx, ty);
	}

	@Override
	public void rotate(double theta) {
		delegate.rotate(theta);
	}

	@Override
	public boolean drawImage(Image img, int x, int y, int width, int height, Color bgcolor,
			ImageObserver observer) {
		return delegate.drawImage(img, x, y, width, height, bgcolor, observer);
	}

	@Override
	public void rotate(double theta, double x, double y) {
		delegate.rotate(theta, x, y);
	}

	@Override
	public void scale(double sx, double sy) {
		delegate.scale(sx, sy);
	}

	@Override
	public void shear(double shx, double shy) {
		delegate.shear(shx, shy);
	}

	@Override
	public boolean drawImage(Image img, int dx1, int dy1, int dx2, int dy2, int sx1, int sy1,
			int sx2, int sy2, ImageObserver observer) {
		return delegate.drawImage(img, dx1, dy1, dx2, dy2, sx1, sy1, sx2, sy2, observer);
	}

	@Override
	public void transform(AffineTransform Tx) {
		delegate.transform(Tx);
	}

	@Override
	public void setTransform(AffineTransform Tx) {
		delegate.setTransform(Tx);
	}

	@Override
	public AffineTransform getTransform() {
		return delegate.getTransform();
	}

	@Override
	public boolean drawImage(Image img, int dx1, int dy1, int dx2, int dy2, int sx1, int sy1,
			int sx2, int sy2, Color bgcolor, ImageObserver observer) {
		return delegate.drawImage(img, dx1, dy1, dx2, dy2, sx1, sy1, sx2, sy2, bgcolor, observer);
	}

	@Override
	public Composite getComposite() {
		return delegate.getComposite();
	}

	@Override
	public Stroke getStroke() {
		return delegate.getStroke();
	}

	@Override
	public void clip(Shape s) {
		delegate.clip(s);
	}

	@Override
	public FontRenderContext getFontRenderContext() {
		return delegate.getFontRenderContext();
	}

	@Override
	public void dispose() {
		delegate.dispose();
	}

	@Override
	public void finalize() {
		delegate.finalize();
	}

	@Override
	public String toString() {
		return delegate.toString();
	}

	@Override
	public Rectangle getClipRect() {
		return delegate.getClipBounds();
	}

	@Override
	public boolean hitClip(int x, int y, int width, int height) {
		return delegate.hitClip(x, y, width, height);
	}

	@Override
	public Rectangle getClipBounds(Rectangle r) {
		return delegate.getClipBounds(r);
	}

}
