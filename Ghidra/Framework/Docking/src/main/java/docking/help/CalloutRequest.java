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
package docking.help;

import java.awt.*;
import java.awt.geom.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.net.URL;

import javax.help.WindowPresentation;
import javax.swing.*;
import javax.swing.event.ChangeListener;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.html.HTML;
import javax.swing.text.html.HTMLDocument;

import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.TimingTargetAdapter;

import docking.util.AnimationPainter;
import docking.util.AnimationUtils;
import generic.theme.GColor;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidra.util.bean.GGlassPane;
import ghidra.util.task.SwingUpdateManager;

/**
 * A class that will trigger a UI aid to show users to where in the given html page the view has 
 * been navigated.   As users follow links, the new page is loaded, but it is not always easy to see
 * where on the page the original link is pointing.   This will paint a UI marker where at the 
 * destination of the clicked link.  Perhaps the most important job of this class is to reposition
 * the view once the html loading has finished.
 * <p>
 * This class is complicated due to the asynchronous nature of html document loading and rendering.
 * The document is loaded in a background thread. After the page is loaded, some elements on the 
 * page, such as images, may also be loaded asynchronously.  As these elements get loaded, the 
 * geometry of the page may change.  This means that the destination bounds of a link may change as 
 * the page is being loaded and rendered.  To compensate for these changes, we need a way to delay
 * showing the UI marker until the page is fully rendered.  Here we use a {@link SwingUpdateManager}
 * to delay the UI marker until no new changes are being made.  At that point, the bounds of the
 * anchor should be finalized.
 */
class CalloutRequest {

	private DockingHelpBroker helpBroker;
	private Animator animator;
	private JEditorPane editorPane;
	private URL requestUrl;

	private String pageInfo;

	private PropertyChangeListener pageLoadListener = new PageLoadingListener();

	private SwingUpdateManager calloutUpdater = new SwingUpdateManager(this::doUpdate);
	private ChangeListener changeListener = e -> {
		Object source = e.getSource();
		if (source instanceof JViewport) {

			// push back the callout so it can get the up-to-date dimensions
			calloutUpdater.updateLater();
		}
	};

	CalloutRequest(DockingHelpBroker helpBroker, JEditorPane editorPane, URL requestUrl) {
		this.helpBroker = helpBroker;
		this.editorPane = editorPane;
		this.requestUrl = requestUrl;

		savePageInfo();
	}

	private void savePageInfo() {
		pageInfo = requestUrl.toString();

		int lastSlash = pageInfo.lastIndexOf('/');
		if (lastSlash < 0) {
			return;
		}

		pageInfo = pageInfo.substring(lastSlash + 1, pageInfo.length());
	}

	public void runLater() {

		String ref = requestUrl.getRef();
		if (ref == null) {
			dispose();
			return; // no ref to callout for this url
		}

		if (isCurrentPage(requestUrl)) {
			start(); // page already loaded; just start
		}
		else {
			// start when loaded
			editorPane.addPropertyChangeListener("page", pageLoadListener);
		}
	}

	private void start() {
		JScrollPane scrollPane = getScrollPane();
		JViewport viewport = scrollPane.getViewport();
		viewport.addChangeListener(changeListener);

		calloutUpdater.updateLater();
	}

	public void dispose() {
		calloutUpdater.dispose();

		if (animator != null) {
			animator.stop();
			animator = null;
		}
	}

	private void doUpdate() {

		// stop listening for document changes now that we are going to do our work
		JScrollPane scrollPane = getScrollPane();
		JViewport viewport = scrollPane.getViewport();
		viewport.removeChangeListener(changeListener);

		// Always place the area at the top of the screen.
		String ref = requestUrl.getRef();
		Rectangle currentRefArea = getReferenceArea(ref);
		currentRefArea.y += (viewport.getHeight() - currentRefArea.getHeight());
		editorPane.scrollRectToVisible(currentRefArea);

		Rectangle updatedRefArea = getReferenceArea(ref);
		doCalloutReference(updatedRefArea);
	}

	private JScrollPane getScrollPane() {
		Container parent = editorPane.getParent();
		while (parent != null) {
			if (parent instanceof JScrollPane) {
				return (JScrollPane) parent;
			}
			parent = parent.getParent();
		}
		return null;
	}

	private Rectangle getReferenceArea(String ref) {

		int pos = getAnchorPosition(ref);
		if (pos == -1) {
			return null;
		}

		Rectangle2D startArea = null;
		try {
			startArea = editorPane.modelToView2D(pos);
		}
		catch (BadLocationException ble) {
			Msg.trace(this, "Unexpected exception searching for help reference", ble);
			return null;
		}

		Rectangle bounds = startArea.getBounds();

		// Ensure the bounds has a non-zero width.  This makes rectangle intersection work
		// correctly in the client code.
		bounds.width = Math.max(bounds.width, 10);
		return bounds;
	}

	private int getAnchorPosition(String ref) {
		HTMLDocument document = (HTMLDocument) editorPane.getDocument();
		HTMLDocument.Iterator it = document.getIterator(HTML.Tag.A);
		for (; it.isValid(); it.next()) {
			AttributeSet attrs = it.getAttributes();
			String name = (String) attrs.getAttribute(HTML.Attribute.NAME);
			if (ref.equals(name)) {
				return it.getStartOffset();
			}
		}
		return -1;
	}

	private boolean isCalloutEnabled() {
		String showAidString = Preferences.getProperty(HelpManager.SHOW_AID_KEY);
		if (showAidString == null) {
			return false;
		}

		return Boolean.parseBoolean(showAidString);
	}

	private void doCalloutReference(final Rectangle area) {

		if (!isCalloutEnabled()) {
			return; // the user has disabled the animation
		}

		WindowPresentation windowPresentation = helpBroker.getWindowPresentation();
		Window helpWindow = windowPresentation.getHelpWindow();
		Container contentPane = null;
		if (helpWindow instanceof JDialog) {
			contentPane = ((JDialog) helpWindow).getContentPane();
		}
		else {
			contentPane = ((JFrame) helpWindow).getContentPane();
		}

		JScrollPane scrollPane = getScrollPane();
		JViewport viewport = scrollPane.getViewport();
		Point viewPosition = viewport.getViewPosition();

		//
		// The area of the HTML content is absolute inside of the entire document.
		// However, the user is viewing the document inside of a scroll pane.  So, we
		// want the offset of the element within the viewer, not the absolute position.
		//
		Rectangle offsetArea = new Rectangle(area);
		offsetArea.y -= viewPosition.y;

		//
		// Update the coordinates to be relative to the content pane, which is where we
		// are doing the painting.
		//
		Rectangle relativeArea =
			SwingUtilities.convertRectangle(scrollPane, offsetArea, contentPane);
		Shape star = new StarShape(relativeArea.getLocation());

		animator = AnimationUtils.createPaintingAnimator(helpWindow, new LocationHintPainter(star));
		if (animator == null) {
			return; // animations are disabled
		}

		animator.addTarget(new TimingTargetAdapter() {
			@Override
			public void end() {
				animator = null;
				dispose();
			}
		});
	}

	private boolean isCurrentPage(URL newURL) {
		if (newURL == null) {
			return false;// not sure if this can happen
		}

		String newFile = newURL.getFile();
		URL currentURL = editorPane.getPage();
		if (currentURL == null) {
			return false;
		}

		String currentFile = currentURL.getFile();
		return newFile.equals(currentFile);
	}

	@Override
	public String toString() {
		return pageInfo;
	}

//=================================================================================================
// Inner Classes
//=================================================================================================	

	private class PageLoadingListener implements PropertyChangeListener {
		@Override
		public void propertyChange(PropertyChangeEvent evt) {
			editorPane.removePropertyChangeListener("page", pageLoadListener);
			start();
		}
	}

	private class StarShape extends Path2D.Float {

		StarShape(Point location) {
			this(5, location, 1, .3);// reasonable star qualities
		}

		StarShape(int points, Point location, double outerRadius, double innerRadius) {
			// note: location is the origin of the shape

			double angle = Math.PI / points;
			GeneralPath path = new GeneralPath();

			int scale = 20;
			double lr = Math.max(outerRadius, innerRadius);
			int width = (int) (scale * (2 * lr));
			int height = width;// square bounds
			double cx = location.x + width / 2;
			double cy = location.y + height / 2;
			Point2D.Double center = new Point2D.Double(cx, cy);

			// start the first point...
			double r = outerRadius;
			double x = center.x + Math.cos(0 * angle) * r;
			double y = center.y + Math.sin(0 * angle) * r;
			path.moveTo(x, y);

			// ...the remaining points
			for (int i = 1; i < 2 * points; i++) {
				r = (i % 2) == 0 ? outerRadius : innerRadius;
				x = center.x + Math.cos(i * angle) * r;
				y = center.y + Math.sin(i * angle) * r;
				path.lineTo(x, y);
			}

			path.closePath();

			// scaled center x/y
			double scx = scale * cx;
			double scy = scale * cy;

			// note: An offset of (width / 2) moves from center to 0.  This didn't look quite
			//       right, so, through trial and error, we updated the offset so that the
			//       shape's location is just over the beginning of the text that follows the
			//       anchor, in most cases.
			double offsetx = width / 4;
			double offsety = height / 4;

			// scaled offset x/y
			double sox = scx - offsetx;// move the x from center to 0
			double soy = scy - offsety;// ...

			// delta x/y
			double dx = sox - location.x;
			double dy = soy - location.y;

			// move the origin so that after we scale, it goes back to 0,0
			AffineTransform xform = AffineTransform.getTranslateInstance(-dx, -dy);
			xform.scale(scale, scale);

			Shape shape = xform.createTransformedShape(path);
			super.append(shape, true);
		}
	}

	private class LocationHintPainter implements AnimationPainter {

		private Color color = new GColor("color.bg.help.hint");
		private Shape paintShape;

		LocationHintPainter(Shape paintShape) {
			this.paintShape = paintShape;
		}

		@Override
		public void paint(GGlassPane glassPane, Graphics graphics, double percentComplete) {

			Graphics2D g2d = (Graphics2D) graphics;
			g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
				RenderingHints.VALUE_INTERPOLATION_BILINEAR);

			//
			// At 0%,  with 100% opacity; at the end, paint with 0% opacity
			//
			Composite originalComposite = g2d.getComposite();
			AlphaComposite alphaComposite = AlphaComposite
					.getInstance(AlphaComposite.SrcOver.getRule(), (float) (1 - percentComplete));
			g2d.setComposite(alphaComposite);

			double transition = 1 - percentComplete;
			Color originalColor = g2d.getColor();

			AffineTransform originalTransform = g2d.getTransform();

			double scale = 4 * transition;

			int degrees = (int) (480 * transition);
			double rad = Math.toRadians(transition * degrees);

			Rectangle b = paintShape.getBounds();
			double cx = b.getCenterX();
			double cy = b.getCenterY();
			double scx = cx * scale;
			double scy = cy * scale;
			double dcx = scx - cx;
			double dcy = scy - cy;

			AffineTransform scaler = new AffineTransform();
			scaler.translate(-dcx, -dcy);
			scaler.scale(scale, scale);
			Shape scaled = scaler.createTransformedShape(paintShape);

			AffineTransform rotater = new AffineTransform();
			rotater.rotate(rad, cx, cy);
			Shape finalShape = rotater.createTransformedShape(scaled);

			/*
			 	// Debug
			Shape box = scaler.createTransformedShape(b);
			g2d.setColor(Palette.GREEN);
			g2d.fill(box);
			
			box = transform.createTransformedShape(box);
			g2d.setColor(Palette.YELLOW);
			g2d.fill(box);
			*/

			g2d.setColor(color);
			g2d.fill(finalShape);

			g2d.setColor(originalColor);
			g2d.setTransform(originalTransform);
			g2d.setComposite(originalComposite);
		}

	}

}
