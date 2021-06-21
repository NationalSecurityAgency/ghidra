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
package ghidra.app.plugin.gui;

import java.awt.*;
import java.awt.event.*;
import java.awt.geom.*;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.*;

import docking.ComponentProvider;
import docking.Tool;
import generic.util.WindowUtilities;
import generic.util.image.ImageUtils;
import ghidra.app.DeveloperPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.util.Swing;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = WindowLocationPlugin.NAME,
	description = "Shows all known window and screen geometry"
)
//@formatter:on
public class WindowLocationPlugin extends Plugin {

	static final String NAME = "Window Locations";

	private WindowLocationProvider provider;
	private Map<Window, WindowInfo> visibleWindows = new HashMap<>();

	public WindowLocationPlugin(PluginTool tool) {
		super(tool);

		provider = new WindowLocationProvider(tool);
		tool.addComponentProvider(provider, false);
	}

	private class WindowLocationProvider extends ComponentProvider {

		private WindowLocationPanel windowPanel;

		public WindowLocationProvider(Tool tool) {
			super(tool, "Window Locations", WindowLocationPlugin.this.getName());

			build();
		}

		private void build() {

			windowPanel = new WindowLocationPanel();
			windowPanel.setPreferredSize(new Dimension(1000, 600));
			windowPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

			Toolkit toolkit = Toolkit.getDefaultToolkit();
			AWTEventListener listener = new AWTEventListener() {
				@Override
				public void eventDispatched(AWTEvent event) {
					windowPanel.repaint();
				}
			};
			toolkit.addAWTEventListener(listener, AWTEvent.MOUSE_MOTION_EVENT_MASK);
			toolkit.addAWTEventListener(listener, AWTEvent.MOUSE_EVENT_MASK);
		}

		void repaint() {
			windowPanel.repaint();
		}

		@Override
		public void componentHidden() {
			windowPanel.clear();
		}

		@Override
		public JComponent getComponent() {
			return windowPanel;
		}
	}

	private class WindowLocationPanel extends JPanel {

		private MouseListener mousy = new MouseListener();

		WindowLocationPanel() {

			// at least one focusable component is required to reside in a window
			setFocusable(true);

			addMouseMotionListener(mousy);
			addMouseListener(mousy);
		}

		void clear() {
			visibleWindows.clear();
			mousy.clear();
		}

		@Override
		protected void paintComponent(Graphics g) {

			Dimension size = getSize();
			double panelWidth = size.getWidth();
			double panelHeight = size.getHeight();
			setBackground(Color.BLACK);
			g.fillRect(0, 0, (int) panelWidth, (int) panelHeight);

			Graphics2D g2d = (Graphics2D) g;
			AffineTransform orig = g2d.getTransform();
			AffineTransform clone = (AffineTransform) orig.clone();
			try {
				AffineTransform newxform = createScreenTransform();
				clone.concatenate(newxform);
				g2d.setTransform(clone);

				paintVirtualBounds(g2d, Color.RED);
				paintVisibleBounds(g2d, Color.GREEN);
				paintScreens(g2d, Color.ORANGE);
				paintWindows(g2d, newxform);
			}
			finally {
				g2d.setTransform(orig);
			}
		}

		private AffineTransform createScreenTransform() {

			Area area = getFullScreenArea();

			Rectangle ab = area.getBounds();
			double fullWidth = ab.getWidth();
			double fullHeight = ab.getHeight();

			Dimension size = getSize();
			double panelWidth = size.getWidth();
			double panelHeight = size.getHeight();
			double dw = panelWidth / fullWidth;
			double dh = panelHeight / fullHeight;
			double scale = Math.min(dw, dh);

			double tx = ab.x;
			double ty = ab.y;

			// padding around the edges of all shapes
			tx -= 100;
			ty -= 100;

			double stx = tx * scale;
			double sty = ty * scale;

			// transform
			AffineTransform xtranslate = AffineTransform.getTranslateInstance(-stx, -sty);
			AffineTransform xscale = AffineTransform.getScaleInstance(scale, scale);
			AffineTransform newxform = new AffineTransform();
			newxform.concatenate(xtranslate);
			newxform.concatenate(xscale);
			return newxform;
		}

		private void paintWindows(Graphics2D g2d, AffineTransform xform) {
			Font f = g2d.getFont();
			Font biggerFont = f.deriveFont(40f);
			g2d.setFont(biggerFont);
			g2d.setColor(Color.GRAY);

			Window[] windows = Window.getWindows();

			int z = 0;
			Collection<WindowInfo> infos = visibleWindows.values();
			for (WindowInfo info : infos) {
				int infoz = info.getZ();
				z = Math.max(infoz, z);
			}

			for (Window w : windows) {
				if (!w.isShowing()) {
					visibleWindows.remove(w);
					continue;
				}

				WindowInfo info = visibleWindows.get(w);
				if (info == null) {
					info = new WindowInfo(w, g2d.getTransform(), ++z);
					visibleWindows.put(w, info);
				}
				else {
					// update the transform, in case it has changed since we create the info
					info.xform = xform;
				}

				info.paint(g2d);
			}
		}

		private void paintScreens(Graphics2D g2d, Color color) {

			g2d.setColor(color);
			Collection<Rectangle> screens = getScreens();
			for (Rectangle screen : screens) {
				g2d.draw(screen);
			}
		}

		private void paintVirtualBounds(Graphics2D g2d, Color color) {
			g2d.setColor(color);
			Rectangle virtualBounds = WindowUtilities.getVirtualScreenBounds();
			g2d.draw(virtualBounds);
		}

		private void paintVisibleBounds(Graphics2D g2d, Color color) {
			g2d.setColor(color);
			Shape visibleShape = WindowUtilities.getVisibleScreenBounds();
			g2d.draw(visibleShape.getBounds());
		}

		private Area getFullScreenArea() {

			Rectangle virtualBounds = WindowUtilities.getVirtualScreenBounds();
			Shape visibleShape = WindowUtilities.getVisibleScreenBounds();

			Rectangle visibleBounds = visibleShape.getBounds();

			double tx = virtualBounds.x;
			double ty = virtualBounds.y;
			tx = Math.min(tx, visibleBounds.x);
			ty = Math.min(ty, visibleBounds.y);

			Area area = new Area();
			area.add(new Area(virtualBounds));
			area.add(new Area(visibleShape));

			Window[] windows = Window.getWindows();
			for (Window w : windows) {
				if (!w.isVisible()) {
					continue;
				}
				Rectangle bounds = w.getBounds();
				area.add(new Area(bounds));

				tx = Math.min(tx, bounds.x);
				ty = Math.min(ty, bounds.y);
			}

			// padding around the edges of all shapes
			tx -= 100;
			ty -= 100;

			// account for items offscreen in the negative direction
			Rectangle fullBounds = area.getBounds();
			int width = fullBounds.width + (int) ((-tx) * 2);
			int height = fullBounds.height + (int) ((-ty) * 2);
			area.add(new Area(new Rectangle(0, 0, width, height)));

			return area;
		}

		private Collection<Rectangle> getScreens() {
			List<Rectangle> screens = new ArrayList<>();
			GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
			GraphicsDevice[] gs = ge.getScreenDevices();
			for (GraphicsDevice gd : gs) {
				GraphicsConfiguration gc = gd.getDefaultConfiguration();
				Rectangle gcBounds = gc.getBounds();
				screens.add(gcBounds);
			}
			return screens;
		}

	}

	private class WindowInfo {

		private Window window;
		private Rectangle startBounds;
		private int zOrder;
		private boolean isSelected;
		private AffineTransform xform;
		private String infoName;
		private Image windowImage;

		WindowInfo(Window w, AffineTransform xform, int zOrder) {
			this.window = w;
			this.xform = xform;
			this.zOrder = zOrder;
			this.startBounds = window.getBounds();

			this.infoName = WindowUtilities.getTitle(w);
			if (infoName == null) {
				infoName = "no title";
			}
		}

		int getZ() {
			return zOrder;
		}

		void resetLocation() {
			window.setBounds(startBounds);
		}

		void setZOrder(int zOrder) {
			this.zOrder = zOrder;
		}

		void setSelected(boolean isSelected) {
			this.isSelected = isSelected;
			if (!isSelected) {
				// clear the image so that it gets rebuilt the next time this info is selected so
				// that the user has the most up-to-date image while still allowing us to buffer
				windowImage = null;
			}
		}

		boolean isSelected() {
			return isSelected;
		}

		void move(double dx, double dy) {

			double sx = (1 / xform.getScaleX()) * dx;
			double sy = (1 / xform.getScaleY()) * dy;

			Point oldLocation = window.getLocation();
			double newx = oldLocation.getX() + sx;
			double newy = oldLocation.getY() + sy;

			oldLocation.setLocation(newx, newy);
			window.setLocation(oldLocation);
		}

		boolean contains(Point location) {

			Rectangle bounds = window.getBounds();
			Point xlocation = new Point();

			try {
				xform.inverseTransform(location, xlocation);
			}
			catch (NoninvertibleTransformException e) {
				Msg.debug(this, "Unexpected exception transforming point", e);
			}

			return bounds.contains(xlocation);
		}

		void paint(Graphics2D g2d) {
			Rectangle b = window.getBounds();
			g2d.drawString(infoName, (float) b.getX(), (float) (b.getY() - 10));
			g2d.draw(b);

			FontMetrics fm = g2d.getFontMetrics();
			String coords = b.getX() + ", " + b.getY();
			Rectangle2D sb = fm.getStringBounds(infoName, g2d);
			g2d.drawString(coords, (float) b.getX(),
				(float) (b.getY() + b.getHeight() + 10 + sb.getHeight()));

			if (isSelected) {

				Color bg = g2d.getColor();
				try {
					Color withAlpha = new Color(0, 255, 0, 200);
					g2d.setColor(withAlpha);
					g2d.fill(b);
				}
				finally {
					g2d.setColor(bg);
				}

				Image image = getImage();
				if (image != null) {
					g2d.drawImage(image, (int) b.getX(), (int) b.getY(), null);
				}
			}
		}

		private Image getImage() {

			if (windowImage != null) {
				return windowImage;
			}

			// note: must do this on the swing thread later due to timing between paint requests
			//       and how the image gets created
			Swing.runLater(() -> {
				windowImage = createImage();
				provider.repaint();
			});
			return null;
		}

		private Image createImage() {
			return ImageUtils.createImage(window);
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((window == null) ? 0 : window.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}

			WindowInfo other = (WindowInfo) obj;
			if (!Objects.equals(window, other.window)) {
				return false;
			}
			return true;
		}

		@Override
		public String toString() {
			return infoName + " - selected? " + isSelected;
		}
	}

	private class MouseListener extends MouseAdapter {

		private WindowInfo draggedInfo;
		private Point lastPoint;

		@Override
		public void mouseDragged(MouseEvent e) {

			Point newLocation = e.getPoint();
			WindowInfo info = getDraggedInfo(e);
			draggedInfo = info;

			if (info == null) {
				return;
			}

			if (lastPoint == null) {
				lastPoint = newLocation;
			}

			double dx = newLocation.getX() - lastPoint.getX();
			double dy = newLocation.getY() - lastPoint.getY();
			lastPoint = newLocation;
			info.move(dx, dy);
		}

		void clear() {
			draggedInfo = null;
			lastPoint = null;
		}

		private WindowInfo getDraggedInfo(MouseEvent e) {

			if (draggedInfo != null) {
				return draggedInfo;
			}

			List<WindowInfo> intersection = visibleWindows.values()
					.stream()
					.filter(w -> w.contains(e.getPoint()))
					.sorted((w1, w2) -> w1.zOrder - w2.zOrder)
					.collect(Collectors.toList());

			if (intersection.isEmpty()) {
				return null;
			}

			WindowInfo info = intersection.get(0);
			if (!info.isSelected()) {
				return null;
			}

			return info;
		}

		@Override
		public void mouseClicked(MouseEvent e) {

			draggedInfo = null;
			lastPoint = e.getPoint();
			boolean isRightClick = e.getButton() == MouseEvent.BUTTON3;

			List<WindowInfo> intersection = visibleWindows.values()
					.stream()
					.filter(w -> w.contains(e.getPoint()))
					.sorted((w1, w2) -> w1.zOrder - w2.zOrder)
					.collect(Collectors.toList());

			clearSelection();

			if (intersection.isEmpty()) {

				if (isRightClick) {
					lastPoint = null;
					resetAllLocations();
				}

				provider.repaint();
				return;
			}
			else if (intersection.size() == 1) {

				if (isRightClick) {
					lastPoint = null;
					intersection.get(0).resetLocation();
					return;
				}

				intersection.get(0).setSelected(true);
				provider.repaint();
				return;
			}

			if (e.isShiftDown()) {
				cycleZOrder(intersection);
			}
			else {
				// normal click; multiple overlapping windows; select the new top window
				intersection.get(0).setSelected(true);
			}

			provider.repaint();
		}

		private void resetAllLocations() {
			visibleWindows.values().forEach(info -> info.resetLocation());

		}

		private void clearSelection() {
			visibleWindows.values().forEach(info -> info.setSelected(false));
		}

		private void cycleZOrder(List<WindowInfo> topWindows) {

			List<WindowInfo> reSorted = new ArrayList<>(visibleWindows.values());

			// put the top windows to the front, in order, rotating the last to the
			// top, to cycle the order
			for (int i = topWindows.size() - 2; i >= 0; i--) {
				WindowInfo info = topWindows.get(i);
				reSorted.remove(info);
				reSorted.add(0, info);
			}

			// ...now put the last one we missed above to the top
			WindowInfo lastInfo = topWindows.get(topWindows.size() - 1);
			reSorted.remove(lastInfo);
			reSorted.add(0, lastInfo);

			// reset the stored z-order
			int zOrder = 0;
			for (WindowInfo info : reSorted) {
				info.setZOrder(zOrder++);
			}

			// select the new top window
			reSorted.get(0).setSelected(true);
		}

		@Override
		public void mouseReleased(MouseEvent e) {
			draggedInfo = null;
			lastPoint = null;
		}

		@Override
		public void mouseExited(MouseEvent e) {
			draggedInfo = null;
			lastPoint = null;
		}

		@Override
		public void mouseEntered(MouseEvent e) {
			draggedInfo = null;
			lastPoint = null;
		}
	}
}
