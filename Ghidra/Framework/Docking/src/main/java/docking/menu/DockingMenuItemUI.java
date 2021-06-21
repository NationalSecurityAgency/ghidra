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
package docking.menu;

import java.awt.*;
import java.awt.RenderingHints.Key;
import java.awt.font.FontRenderContext;
import java.awt.font.GlyphVector;
import java.awt.geom.AffineTransform;
import java.awt.image.*;
import java.awt.image.renderable.RenderableImage;
import java.text.AttributedCharacterIterator;
import java.util.ArrayList;
import java.util.Map;

import javax.accessibility.Accessible;
import javax.swing.*;
import javax.swing.plaf.ComponentUI;
import javax.swing.plaf.MenuItemUI;

import docking.util.GraphicsUtils;

/**
 * This class exists to make menu items display content with proper alignment whether or not
 * they are displaying an icon.  That is, this class will introduce padding for absent icons 
 * within menu items so that the item lines up with those items that do contain icons.
 * <p>
 * This class has an additional feature that allows clients to display menu item content in a
 * tabular fashion.  A menu item using this UI can contain some combination of the of the following
 * items, in the given order: 
 * <pre>
 * [Checkbox][Icon][Menu Item Content][Menu Pull-right/Accelerator Text]
 * </pre>
 * To display the <b>Menu Item Content</b> in a tabular fashion, use the <code>'\t'</code> character 
 * to delimit the data into columns.  This class will align all menu items in the given menu  
 * based upon the largest number of columns in the group and the largest width for each column.
 */
public class DockingMenuItemUI extends MenuItemUI {

	private static final String TABULATOR_PROPERTIES = "menuItemTabulator";

	// make this big enough to differentiate columns
	private static final int COLUMN_PADDING = 20;

	protected MenuItemUI ui;

	public static ComponentUI createUI(JComponent c) {
		DockingMenuItemUI result = new DockingMenuItemUI();
		result.ui = (MenuItemUI) UIManager.getDefaults().getUI(c);
		return result;
	}

	@Override
	public void installUI(JComponent c) {
		ui.installUI(c);
	}

	@Override
	public void uninstallUI(JComponent c) {
		ui.uninstallUI(c);
	}

	@Override
	public void paint(Graphics g, JComponent c) {
		if (((JMenuItem) c).getText().indexOf('\t') != -1) {
			MenuTabulator tabulator = MenuTabulator.get((JMenuItem) c);
			SwitchGraphics2D sg = new SwitchGraphics2D((Graphics2D) g);
			sg.setDoText(false);
			// Draw without text...
			ui.paint(sg, c);

			// Now draw tabulated text
			paintText(sg, (JMenuItem) c, tabulator);
			// TODO: I think underlines must be in the first column unless I want to putz with line drawing
		}
		else {
			ui.paint(g, c);
		}
	}

	@Override
	public void update(Graphics g, JComponent c) {
		if (((JMenuItem) c).getText().indexOf('\t') != -1) {
			MenuTabulator tabulator = MenuTabulator.get((JMenuItem) c);
			SwitchGraphics2D sg = new SwitchGraphics2D((Graphics2D) g);
			sg.setDoText(false);
			// Draw without text...
			ui.update(sg, c);

			// Now draw tabulated text
			paintText(sg, (JMenuItem) c, tabulator);
			// TODO: I think underlines must be in the first column unless I want to putz with line drawing
		}
		else {
			ui.update(g, c);
		}
	}

	public void paintText(SwitchGraphics2D sg, JMenuItem c, MenuTabulator t) {
		SwitchGraphics2D sg2 = (SwitchGraphics2D) sg.create();
		sg2.setDoDraw(false);
		sg2.setDoFill(false);
		sg2.setDoText(true);
		sg2.setDoImage(false);

		Icon origIcon = c.getIcon();
		int iconWidth = 0;
		if (origIcon != null) {
			iconWidth = origIcon.getIconWidth();
		}
		String origText = c.getText();
		KeyStroke origAcc = c.getAccelerator();
		String[] parts = origText.split("\t");
		for (int i = 0; i < parts.length; i++) {

			c.setText(parts[i]);
			ui.paint(sg2, c);

			sg2.translate(iconWidth + t.columns.get(i) + COLUMN_PADDING, 0);

			// this is only needed for the first pass
			iconWidth = 0;
			c.setIcon(null);
			c.setAccelerator(null);
		}

		c.setIcon(origIcon);
		c.setText(origText);
		c.setAccelerator(origAcc);
	}

	@Override
	public Dimension getPreferredSize(JComponent c) {
		Dimension uiPref = ui.getPreferredSize(c);
		String text = ((JMenuItem) c).getText();
		if (text.indexOf('\t') == -1) {
			return uiPref;
		}

		int extra = uiPref.width - textWidth(c, text);
		MenuTabulator tabulator = MenuTabulator.tabulate((JMenuItem) c);
		return new Dimension(tabulator.getWidth() + extra, uiPref.height);
	}

	@Override
	public Dimension getMinimumSize(JComponent c) {
		return ui.getMinimumSize(c);
	}

	@Override
	public Dimension getMaximumSize(JComponent c) {
		return ui.getMaximumSize(c);
	}

	private static int textWidth(JComponent c, String text) {
		return GraphicsUtils.stringWidth(c, c.getFontMetrics(c.getFont()), text);
	}

	public static class MenuTabulator {
		private ArrayList<Integer> columns = new ArrayList<Integer>();

		public static MenuTabulator tabulate(JMenuItem c) {
			MenuTabulator tabulator = get(c);
			if (tabulator == null) {
				tabulator = new MenuTabulator();
				JComponent p = (JComponent) c.getParent();
				p.putClientProperty(TABULATOR_PROPERTIES, tabulator);
			}
			tabulator.tabulate(c, c.getText());
			return tabulator;
		}

		public static MenuTabulator get(JMenuItem c) {
			JComponent p = (JComponent) c.getParent();
			return (MenuTabulator) p.getClientProperty(TABULATOR_PROPERTIES);
		}

		public void tabulate(JComponent c, String tabularText) {
			String[] parts = tabularText.split("\t");
			for (int i = 0; i < parts.length; i++) {
				int candWidth = textWidth(c, parts[i]);
				if (i < columns.size()) {
					int width = columns.get(i);
					columns.set(i, Math.max(width, candWidth));
				}
				else {
					columns.add(candWidth);
				}
			}
		}

		public int getWidth() {
			int total = 0;
			for (Integer i : columns) {
				total += i;
			}
			total += (columns.size() - 1) * COLUMN_PADDING;
			return total;
		}
	}

	@Override
	public boolean contains(JComponent c, int x, int y) {
		return ui.contains(c, x, y);
	}

	@Override
	public int getBaseline(JComponent c, int width, int height) {
		return ui.getBaseline(c, width, height);
	}

	@Override
	public Component.BaselineResizeBehavior getBaselineResizeBehavior(JComponent c) {
		return ui.getBaselineResizeBehavior(c);
	}

	@Override
	public int getAccessibleChildrenCount(JComponent c) {
		return ui.getAccessibleChildrenCount(c);
	}

	@Override
	public Accessible getAccessibleChild(JComponent c, int i) {
		return ui.getAccessibleChild(c, i);
	}

	public static class SwitchGraphics2D extends Graphics2D {
		protected boolean doDraw = true;
		protected boolean doFill = true;
		protected boolean doText = true;
		protected boolean doImage = true;

		protected Graphics2D g;

		public SwitchGraphics2D(Graphics2D g) {
			this.g = g;
		}

		public void setDoDraw(boolean doDraw) {
			this.doDraw = doDraw;
		}

		public void setDoFill(boolean doFill) {
			this.doFill = doFill;
		}

		public void setDoText(boolean doText) {
			this.doText = doText;
		}

		public void setDoImage(boolean doImage) {
			this.doImage = doImage;
		}

		@Override
		public Graphics create() {
			return new SwitchGraphics2D((Graphics2D) g.create());
		}

		@Override
		public Graphics create(int x, int y, int width, int height) {
			return new SwitchGraphics2D((Graphics2D) g.create(x, y, width, height));
		}

		@Override
		public void drawLine(int x1, int y1, int x2, int y2) {
			if (doDraw) {
				g.drawLine(x1, y1, x2, y2);
			}
		}

		@Override
		public void fillRect(int x, int y, int width, int height) {
			if (doFill) {
				g.fillRect(x, y, width, height);
			}
		}

		@Override
		public void clearRect(int x, int y, int width, int height) {
			if (doFill) {
				g.clearRect(x, y, width, height);
			}
		}

		@Override
		public void drawRoundRect(int x, int y, int width, int height, int arcWidth,
				int arcHeight) {
			if (doDraw) {
				g.drawRoundRect(x, y, width, height, arcWidth, arcHeight);
			}
		}

		@Override
		public void fillRoundRect(int x, int y, int width, int height, int arcWidth,
				int arcHeight) {
			if (doFill) {
				g.fillRoundRect(x, y, width, height, arcWidth, arcHeight);
			}
		}

		@Override
		public void drawOval(int x, int y, int width, int height) {
			if (doDraw) {
				g.drawOval(x, y, width, height);
			}
		}

		@Override
		public void fillOval(int x, int y, int width, int height) {
			if (doFill) {
				g.fillOval(x, y, width, height);
			}
		}

		@Override
		public void drawArc(int x, int y, int width, int height, int startAngle, int arcAngle) {
			if (doDraw) {
				g.drawArc(x, y, width, height, startAngle, arcAngle);
			}
		}

		@Override
		public void fillArc(int x, int y, int width, int height, int startAngle, int arcAngle) {
			if (doFill) {
				g.fillArc(x, y, width, height, startAngle, arcAngle);
			}
		}

		@Override
		public void drawPolyline(int[] xPoints, int[] yPoints, int nPoints) {
			if (doDraw) {
				g.drawPolyline(xPoints, yPoints, nPoints);
			}
		}

		@Override
		public void drawPolygon(int[] xPoints, int[] yPoints, int nPoints) {
			if (doDraw) {
				g.drawPolygon(xPoints, yPoints, nPoints);
			}
		}

		@Override
		public void fillPolygon(int[] xPoints, int[] yPoints, int nPoints) {
			if (doFill) {
				g.fillPolygon(xPoints, yPoints, nPoints);
			}
		}

		@Override
		public void drawString(String str, int x, int y) {
			if (doText) {
				g.drawString(str, x, y);
			}
		}

		@Override
		public void drawString(AttributedCharacterIterator iterator, int x, int y) {
			if (doText) {
				g.drawString(iterator, x, y);
			}
		}

		@Override
		public boolean drawImage(Image img, int x, int y, ImageObserver observer) {
			if (doImage) {
				return g.drawImage(img, x, y, observer);
			}
			return true; // Just say pixels are not still changing
		}

		@Override
		public boolean drawImage(Image img, int x, int y, int width, int height,
				ImageObserver observer) {
			if (doImage) {
				return g.drawImage(img, x, y, width, height, observer);
			}
			return true; // Just say pixels are not still changing
		}

		@Override
		public boolean drawImage(Image img, int x, int y, Color bgcolor, ImageObserver observer) {
			if (doImage) {
				return g.drawImage(img, x, y, bgcolor, observer);
			}
			return true; // Just say pixels are not still changing
		}

		@Override
		public boolean drawImage(Image img, int x, int y, int width, int height, Color bgcolor,
				ImageObserver observer) {
			if (doImage) {
				return g.drawImage(img, x, y, width, height, bgcolor, observer);
			}
			return true; // Just say pixels are not still changing
		}

		@Override
		public boolean drawImage(Image img, int dx1, int dy1, int dx2, int dy2, int sx1, int sy1,
				int sx2, int sy2, ImageObserver observer) {
			if (doImage) {
				return g.drawImage(img, dx1, dy1, dx2, dy2, sx1, sy1, sx2, sy2, observer);
			}
			return true; // Just say pixels are not still changing
		}

		@Override
		public boolean drawImage(Image img, int dx1, int dy1, int dx2, int dy2, int sx1, int sy1,
				int sx2, int sy2, Color bgcolor, ImageObserver observer) {
			if (doImage) {
				return g.drawImage(img, dx1, dy1, dx2, dy2, sx1, sy1, sx2, sy2, bgcolor, observer);
			}
			return true; // Just say pixels are not still changing
		}

		@Override
		public void translate(int x, int y) {
			g.translate(x, y);
		}

		@Override
		public Color getColor() {
			return g.getColor();
		}

		@Override
		public void setColor(Color c) {
			g.setColor(c);
		}

		@Override
		public void setPaintMode() {
			g.setPaintMode();
		}

		@Override
		public void setXORMode(Color c1) {
			g.setXORMode(c1);
		}

		@Override
		public Font getFont() {
			return g.getFont();
		}

		@Override
		public void setFont(Font font) {
			g.setFont(font);
		}

		@Override
		public FontMetrics getFontMetrics(Font f) {
			return g.getFontMetrics(f);
		}

		@Override
		public Rectangle getClipBounds() {
			return g.getClipBounds();
		}

		@Override
		public void clipRect(int x, int y, int width, int height) {
			g.clipRect(x, y, width, height);
		}

		@Override
		public void setClip(int x, int y, int width, int height) {
			g.setClip(x, y, width, height);
		}

		@Override
		public Shape getClip() {
			return g.getClip();
		}

		@Override
		public void setClip(Shape clip) {
			g.setClip(clip);
		}

		@Override
		public void copyArea(int x, int y, int width, int height, int dx, int dy) {
			g.copyArea(x, y, width, height, dx, dy);
		}

		@Override
		public void dispose() {
			// Do nothing.
		}

		@Override
		public void draw(Shape s) {
			if (doDraw) {
				g.draw(s);
			}
		}

		@Override
		public boolean drawImage(Image img, AffineTransform xform, ImageObserver obs) {
			if (doImage) {
				return g.drawImage(img, xform, obs);
			}
			return true; // Just say fully loaded and rendered
		}

		@Override
		public void drawImage(BufferedImage img, BufferedImageOp op, int x, int y) {
			if (doImage) {
				g.drawImage(img, op, x, y);
			}
		}

		@Override
		public void drawRenderedImage(RenderedImage img, AffineTransform xform) {
			if (doImage) {
				g.drawRenderedImage(img, xform);
			}
		}

		@Override
		public void drawRenderableImage(RenderableImage img, AffineTransform xform) {
			if (doImage) {
				g.drawRenderableImage(img, xform);
			}
		}

		@Override
		public void drawString(String str, float x, float y) {
			if (doText) {
				g.drawString(str, x, y);
			}
		}

		@Override
		public void drawString(AttributedCharacterIterator iterator, float x, float y) {
			if (doText) {
				g.drawString(iterator, x, y);
			}
		}

		@Override
		public void drawGlyphVector(GlyphVector gv, float x, float y) {
			if (doText) {
				g.drawGlyphVector(gv, x, y);
			}
		}

		@Override
		public void fill(Shape s) {
			if (doFill) {
				g.fill(s);
			}
		}

		@Override
		public boolean hit(Rectangle rect, Shape s, boolean onStroke) {
			return g.hit(rect, s, onStroke);
		}

		@Override
		public GraphicsConfiguration getDeviceConfiguration() {
			return g.getDeviceConfiguration();
		}

		@Override
		public void setComposite(Composite comp) {
			g.setComposite(comp);
		}

		@Override
		public void setPaint(Paint paint) {
			g.setPaint(paint);
		}

		@Override
		public void setStroke(Stroke s) {
			g.setStroke(s);
		}

		@Override
		public void setRenderingHint(Key hintKey, Object hintValue) {
			g.setRenderingHint(hintKey, hintValue);
		}

		@Override
		public Object getRenderingHint(Key hintKey) {
			return g.getRenderingHint(hintKey);
		}

		@Override
		public void setRenderingHints(Map<?, ?> hints) {
			g.setRenderingHints(hints);
		}

		@Override
		public void addRenderingHints(Map<?, ?> hints) {
			g.addRenderingHints(hints);
		}

		@Override
		public RenderingHints getRenderingHints() {
			return g.getRenderingHints();
		}

		@Override
		public void translate(double tx, double ty) {
			g.translate(tx, ty);
		}

		@Override
		public void rotate(double theta) {
			g.rotate(theta);
		}

		@Override
		public void rotate(double theta, double x, double y) {
			g.rotate(theta, x, y);
		}

		@Override
		public void scale(double sx, double sy) {
			g.scale(sx, sy);
		}

		@Override
		public void shear(double shx, double shy) {
			g.shear(shx, shy);
		}

		@Override
		public void transform(AffineTransform Tx) {
			g.transform(Tx);
		}

		@Override
		public void setTransform(AffineTransform Tx) {
			g.setTransform(Tx);
		}

		@Override
		public AffineTransform getTransform() {
			return g.getTransform();
		}

		@Override
		public Paint getPaint() {
			return g.getPaint();
		}

		@Override
		public Composite getComposite() {
			return g.getComposite();
		}

		@Override
		public void setBackground(Color color) {
			g.setBackground(color);
		}

		@Override
		public Color getBackground() {
			return g.getBackground();
		}

		@Override
		public Stroke getStroke() {
			return g.getStroke();
		}

		@Override
		public void clip(Shape s) {
			g.clip(s);
		}

		@Override
		public FontRenderContext getFontRenderContext() {
			return g.getFontRenderContext();
		}
	}
}
