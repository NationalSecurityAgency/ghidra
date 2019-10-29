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
package docking.widgets.imagepanel;

import java.awt.*;
import java.awt.event.*;
import java.awt.geom.AffineTransform;
import java.util.Arrays;

import javax.swing.*;

import docking.widgets.label.GIconLabel;
import resources.icons.EmptyIcon;

/**
 * Creates a panel that displays an {@link Image}. Users may pan the image as desired and zoom the
 * image according to specific zoom levels. 
 */
public class ImagePanel extends JPanel {

	// If this array is changed, ensure compatibility with ImagePanelTest
	public static final float[] ZOOM_LEVELS = new float[] {
		// @formatter:off
		
		// shrinking scales
		.05f, .1f, .25f, .5f, .75f,
		// neutral
		1.0f,
		// expanding scales
		1.5f, 2f, 2.5f, 3f, 4f, 5f, 6f, 7f, 8f, 9f, 10f 
		
		// @formatter:on
	};

	private static final int ZERO_MAGNIFICATION_INDEX = findZeroMagnificationIndex();

	protected static final int ZOOM_FACTOR_INDEX_DEFAULT = findZeroMagnificationIndex();

	private static int findZeroMagnificationIndex() {

		for (int i = 0; i < ZOOM_LEVELS.length; i++) {
			if (Float.compare(ZOOM_LEVELS[i], 1.0f) == 0) {
				return i;
			}
		}
		throw new IllegalStateException(
			"Magnification factor list must contain an entry for no magnification (1.0x)");
	}

	protected int zoomLevelIndex = ZOOM_FACTOR_INDEX_DEFAULT;

	private Image image;
	private PanAndZoomComponent label;
	private JScrollPane imageScroller;

	private boolean zoomEnabled = true;
	private boolean translateEnabled = true;

	public static final float DEFAULT_ZOOM_FACTOR = 1.0f;

	private float defaultZoomFactor = DEFAULT_ZOOM_FACTOR;

	/** Property name that indicates the image displayed by this panel has changed **/
	public static final String IMAGE_PROPERTY = "image";

	/** Property name that indicates the zoom level of the image has changed **/
	public static final String ZOOM_PROPERTY = "zoom";
	/** Property name that indicates the default zoom level of the image has changed **/
	public static final String DEFAULT_ZOOM_PROPERTY = "default_zoom";
	/** Property name that indicates the image has been translated **/
	public static final String TRANSLATION_PROPERTY = "translation";

	private MouseAdapter zoomAndPanMouseAdapter = new MouseAdapter() {

		private int lastX;
		private int lastY;

		@Override
		public void mouseWheelMoved(MouseWheelEvent e) {
			int steps = e.getWheelRotation();
			if (steps > 0) {
				zoomOut(e.getPoint());
			}
			else {
				zoomIn(e.getPoint());
			}
		}

		@Override
		public void mouseDragged(MouseEvent e) {
			super.mouseDragged(e);

			if (e.getButton() == MouseEvent.BUTTON1) {

				int newDx = e.getX() - lastX;
				int newDy = e.getY() - lastY;

				lastX += newDx;
				lastY += newDy;

				translateImage(newDx, newDy);
			}
		}
	};

	private JPanel imagePanel;

	/**
	 * Create an empty NavigableImagePanel
	 */
	public ImagePanel() {
		this(null);
	}

	/**
	 * Create an NavigableImagePanel with the specified image
	 */
	public ImagePanel(Image image) {
		initUI();

		label.addMouseWheelListener(zoomAndPanMouseAdapter);
		label.addMouseListener(zoomAndPanMouseAdapter);
		label.addMouseMotionListener(zoomAndPanMouseAdapter);

		label.addPropertyChangeListener(PanAndZoomComponent.TRANSLATION_RESET_PROPERTY,
			evt -> SwingUtilities.invokeLater(() -> {
				firePropertyChange(TRANSLATION_PROPERTY, evt.getOldValue(), evt.getNewValue());
			}));

		setImage(image);
	}

	private void initUI() {

		label = new PanAndZoomComponent(new EmptyIcon(16, 16), SwingConstants.CENTER);
		imagePanel = new JPanel(new BorderLayout());

		imagePanel.add(label, BorderLayout.CENTER);

		imageScroller =
			new JScrollPane(imagePanel, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

		setLayout(new BorderLayout());
		add(imageScroller, BorderLayout.CENTER);
	}

	/**
	 * Set the image this panel should display
	 * @param image the new image to display
	 */
	public void setImage(Image image) {

		Image oldImage = getImage();

		this.image = image;

		resetZoom();
		resetImageTranslation();

		firePropertyChange(IMAGE_PROPERTY, oldImage, this.image);
	}

	/** 
	 * Get the currently-displayed image
	 * @return the current image
	 */
	public Image getImage() {
		return image;
	}

	/**
	 * Set the background color of the panel. If the specified color is null, the 
	 * default color for panel backgrounds is used.
	 * @param color the new background color
	 */
	public void setImageBackgroundColor(Color color) {
		if (color == null) {
			color = UIManager.getColor("Panel.background");
		}
		imagePanel.setBackground(color);
	}

	/**
	 * Get the current background color of this panel
	 * @return the background color
	 */
	public Color getImageBackgroundColor() {
		return imagePanel.getBackground();
	}

	public void setText(String text) {
		label.setText(text);
	}

	public String getText() {
		return label.getText();
	}

	/**
	 * Get the current zoom factor the image is being drawn to
	 * @return the image magnification factor
	 */
	public float getZoomFactor() {
		return ZOOM_LEVELS[zoomLevelIndex];
	}

	/**
	 * Set the magnification factor of the image. The zoom parameter is aligned to the 
	 * nearest pre-configured magnification factor, rounding down for zoom factors less than 
	 * 1.0, and up for factors greater than 1.0. Zoom factors outside the pre-configured range
	 * are limited to the nearest range extent.  
	 * @param zoom
	 */
	public void setZoomFactor(float zoom) {

		float currentZoom = getZoomFactor();

		zoomLevelIndex = getIndexForLevel(ZOOM_LEVELS, zoom);
		zoom = ZOOM_LEVELS[zoomLevelIndex];
		doZoom(getImageComponentCenter(), zoom);

		firePropertyChange(ZOOM_PROPERTY, currentZoom, zoom);
	}

	private static int getIndexForLevel(float[] levels, float zoom) {

		int idx = Arrays.binarySearch(levels, zoom);

		if (idx >= 0) {
			// The requested zoom level was found at levels[idx]
			return idx;
		}

		// The requested zoom level was not found in levels...
		idx = -(idx + 1);
		// idx is now the index for where zoom should be inserted into levels...

		if (idx == 0) {
			// Smaller zoom factor than our minimum-supported; just provide 
			// our minimum-supported
			return 0;
		}

		if (idx == levels.length) {
			// Greater zoom factor than our maximum-supported; return our maximum-supported
			// zoom level
			return levels.length - 1;
		}

		if (idx < ZERO_MAGNIFICATION_INDEX) {
			// Round down for shrinking factors
			return idx - 1;
		}

		return idx;
	}

	/** 
	 * Get the default zoom level
	 * @return
	 */
	public float getDefaultZoomFactor() {
		return defaultZoomFactor;
	}

	/**
	 * Set the default zoom level, adhering to the same set of constrains as {@link #setZoomFactor(float)} 
	 * @param zoom
	 * @see #setZoomFactor(float)
	 * @see #resetZoom()
	 */
	public void setDefaultZoomFactor(float zoom) {
		float oldDefaultZoom = getDefaultZoomFactor();
		if (zoom == oldDefaultZoom) {
			return;
		}

		int idx = getIndexForLevel(ZOOM_LEVELS, zoom);
		defaultZoomFactor = ZOOM_LEVELS[idx];

		firePropertyChange(DEFAULT_ZOOM_PROPERTY, oldDefaultZoom, zoom);
	}

	public void resetZoom() {
		setZoomFactor(getDefaultZoomFactor());
	}

	private Point getImageComponentCenter() {
		Rectangle bounds = imageScroller.getBounds();
		double cx = bounds.getCenterX();
		double cy = bounds.getCenterY();

		Point p = new Point(bounds.x + (int) cx, bounds.y + (int) cy);
		return p;
	}

	/**
	 * Determine if the image can zoom in further based on current magnification levels 
	 * @return True if magnification steps are available, false otherwise
	 */
	public boolean canZoomIn() {
		return image != null && zoomLevelIndex < ZOOM_LEVELS.length - 1;
	}

	/** 
	 * Enlarge the image about the image center
	 */
	public void zoomIn() {
		zoomIn(getImageComponentCenter());
	}

	/**
	 * Enlarge the image about the given point
	 * @param center location to enlarge the image around
	 */
	public void zoomIn(Point center) {

		if (!isImageZoomEnabled()) {
			return;
		}

		if (!canZoomIn()) {
			return;
		}

		float currentZoom = getZoomFactor();

		int idx = Math.min(ZOOM_LEVELS.length - 1, zoomLevelIndex + 1);

		if (zoomLevelIndex == idx) {
			return;
		}

		zoomLevelIndex = idx;

		float zoomFactor = ZOOM_LEVELS[idx];
		doZoom(center, zoomFactor);

		firePropertyChange(ZOOM_PROPERTY, currentZoom, getZoomFactor());
	}

	/**
	 * Determine if the image can zoom out further based on current magnification levels 
	 * @return True if (de-)magnification steps are available, false otherwise
	 */

	public boolean canZoomOut() {
		int realHeight = label.getIcon().getIconHeight();

		return image != null && zoomLevelIndex > 0 && realHeight > 1;
	}

	/**
	 * Shrink the image about the image center
	 */
	public void zoomOut() {
		zoomOut(getImageComponentCenter());
	}

	/**
	 * Shrink the image about the given point
	 * @param center location to shrink the image around
	 */
	public void zoomOut(Point center) {

		if (!isImageZoomEnabled()) {
			return;
		}

		if (!canZoomOut()) {
			return;
		}

		float currentZoom = getZoomFactor();

		int idx = Math.max(0, zoomLevelIndex - 1);
		if (zoomLevelIndex == idx) {
			return;
		}

		int oldIndex = zoomLevelIndex;

		try {
			zoomLevelIndex = idx;

			float zoomFactor = ZOOM_LEVELS[idx];
			doZoom(center, zoomFactor);

		}
		catch (IllegalArgumentException iae) {
			zoomLevelIndex = oldIndex;
			idx = zoomLevelIndex;

			float zoomFactor = ZOOM_LEVELS[idx];
			doZoom(center, zoomFactor);

		}

		firePropertyChange(ZOOM_PROPERTY, currentZoom, getZoomFactor());
	}

	private void doZoom(Point center, float zoomFactor) {
		if (image == null) {
			label.setIcon(null);
			imageScroller.getViewport().setViewPosition(new Point(0, 0));
		}
		else {

			ImageIcon icon = new ImageIcon(image);

			int width = icon.getIconWidth();
			int height = icon.getIconHeight();

			Image scaled = image.getScaledInstance((int) (width * zoomFactor),
				(int) (height * zoomFactor), Image.SCALE_FAST);

			label.setIcon(new ImageIcon(scaled));

			Point pos = imageScroller.getViewport().getViewPosition();

			int newX = (int) (center.x * (zoomFactor - 1.0f) + zoomFactor * pos.x);
			int newY = (int) (center.y * (zoomFactor - 1.0f) + zoomFactor * pos.y);

			imageScroller.getViewport().setViewPosition(new Point(newX, newY));
		}

		imageScroller.revalidate();
		imageScroller.repaint();

	}

	public boolean isImageZoomEnabled() {
		return zoomEnabled;
	}

	public void setImageZoomEnabled(boolean enabled) {
		zoomEnabled = enabled;
	}

	/**
	 *	Move the image back to the center. Zoom factor is unmodified. 
	 */
	public void resetImageTranslation() {
		label.resetTranslation();
	}

	/**
	 * Determine if the image has been moved from its original location
	 * @return True if the image has moved, false otherwise
	 */
	public boolean isTranslated() {
		return label.isTranslated();
	}

	/**
	 * Get the X-Y distance the image has moved
	 * @return the X-Y distances the image has moved
	 */
	public Point getTranslation() {
		return label.getTranslation();
	}

	private void translateImage(int dX, int dY) {

		if (!isImageTranslationEnabled()) {
			return;
		}

		if (dX == 0 && dY == 0) {
			return;
		}

		Point oldTranslation = label.getTranslation();

		label.translate(dX, dY);

		Point newTranslation = label.getTranslation();

		firePropertyChange(TRANSLATION_PROPERTY, oldTranslation, newTranslation);

	}

	public boolean isImageTranslationEnabled() {
		return translateEnabled;
	}

	public void setImageTranslationEnabled(boolean enabled) {
		translateEnabled = enabled;
	}

	private class PanAndZoomComponent extends GIconLabel {

		public static final String TRANSLATION_RESET_PROPERTY = "translation-reset";

		private int translateX = 0;
		private int translateY = 0;
		private boolean resetTranslation = false;

		public PanAndZoomComponent(Icon image, int horizontalAlignment) {
			super(image, horizontalAlignment);

			addComponentListener(new ComponentAdapter() {

				@Override
				public void componentResized(ComponentEvent e) {
					repaint();
				}
			});
		}

		public void translate(int dX, int dY) {
			translateX += dX;
			translateY += dY;
			repaint();
		}

		public Point getTranslation() {
			return new Point(translateX, translateY);
		}

		public boolean isTranslated() {
			return translateX != 0 || translateY != 0 || resetTranslation;
		}

		public void resetTranslation() {
			translateX *= -1;
			translateY *= -1;
			resetTranslation = true;
			repaint();

		}

		@Override
		public void paint(Graphics g) {
			AffineTransform tx = new AffineTransform();

			Point oldTranslation = getTranslation();

			tx.translate(translateX, translateY);
			Graphics2D g2 = (Graphics2D) g;
			g2.setTransform(tx);
			super.paint(g);

			if (resetTranslation) {
				translateX = translateY = 0;
				resetTranslation = false;

				firePropertyChange(TRANSLATION_RESET_PROPERTY, oldTranslation, getTranslation());
			}
		}
	}
}
