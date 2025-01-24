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
import java.awt.event.ActionEvent;
import java.awt.geom.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.net.URL;
import java.util.List;

import javax.help.*;
import javax.help.event.HelpModelEvent;
import javax.help.event.HelpModelListener;
import javax.swing.*;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.html.HTML;
import javax.swing.text.html.HTMLDocument;

import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.TimingTargetAdapter;

import docking.framework.ApplicationInformationDisplayFactory;
import docking.util.AnimationPainter;
import docking.util.AnimationUtils;
import generic.theme.GColor;
import ghidra.framework.preferences.Preferences;
import ghidra.util.*;
import ghidra.util.bean.GGlassPane;
import help.CustomTOCView;
import help.GHelpBroker;
import resources.Icons;

/**
 * An extension of the {@link GHelpBroker} that allows {@code Docking} classes to be installed.
 * <p>
 * Additions include a search feature a navigation aid.
 */
public class DockingHelpBroker extends GHelpBroker {

	private static final List<Image> ICONS = ApplicationInformationDisplayFactory.getWindowIcons();

	private static final int MAX_CALLOUT_RETRIES = 3;

	private PropertyChangeListener pageLoadListener = new PageLoadingListener();
	private HelpModelListener helpModelListener = new HelpIDChangedListener();
	private Animator lastAnimator;
	private URL loadingURL;

	public DockingHelpBroker(HelpSet hs) {
		super(hs);
	}

	@Override
	protected List<Image> getApplicationIcons() {
		return ICONS;
	}

	@Override
	protected HelpModel getCustomHelpModel() {
		//
		// Unusual Code Alert!: We have opened up access to the help system's HelpModel by way
		//                      of our CustomTOCView object that we install elsewhere.  We need
		//                      access to the model because of a bug in the help system
		//                      (SCR 7639).  Unfortunately, the Java Help system does not give us
		//                      access to the model directly, but we have opened up the access from
		//                      one of our overriding components.  The following code is
		//                      digging-out our custom component to get at the model.  An
		//                      alternative approach would be to just use reflection and violate
		//                      security restrictions, but that seemed worse than this solution.
		//

		WindowPresentation windowPresentation = getWindowPresentation();
		HelpSet helpSet = windowPresentation.getHelpSet();
		NavigatorView tocView = helpSet.getNavigatorView("TOC");
		if (!(tocView instanceof CustomTOCView)) {
			// not sure how this could happen
			Msg.debug(this, "The help system is not using the CustomTOCView class!");
			return null;
		}

		CustomTOCView customTOCView = (CustomTOCView) tocView;
		return customTOCView.getHelpModel();
	}

	@Override
	protected void installHelpSearcher(JHelp jHelp, HelpModel helpModel) {
		helpModel.addHelpModelListener(helpModelListener);
		new HelpViewSearcher(jHelp);
	}

	@Override
	protected void showNavigationAid(URL url) {
		prepareToCallout(url);
	}

	@Override
	protected void installActions(JHelp help) {
		JToolBar toolbar = null;
		Component[] components = help.getComponents();
		for (Component c : components) {
			if (c instanceof JToolBar) {
				toolbar = (JToolBar) c;
				break;
			}
		}

		if (toolbar == null) {
			// shouldn't happen
			return;
		}

		// separate the Java help stuff from our actions
		toolbar.addSeparator();

		ToggleNavigationAid action = new ToggleNavigationAid();
		toolbar.add(new JButton(action));

		if (SystemUtilities.isInDevelopmentMode()) {

			Action refreshAction = new AbstractAction() {

				{
					putValue(Action.SMALL_ICON, Icons.REFRESH_ICON);
					putValue(Action.SHORT_DESCRIPTION, "Reload the current page");
				}

				@Override
				public void actionPerformed(ActionEvent e) {
					reloadHelpPage(getCurrentURL());
				}
			};
			toolbar.add(new JButton(refreshAction));
		}
	}

	@Override // opened access
	protected void reloadHelpPage(URL url) {
		super.reloadHelpPage(url);
	}

//=================================================================================================
// Navigation Aid Section
//=================================================================================================

	private JScrollPane getScrollPane(JEditorPane editorPane) {
		Container parent = editorPane.getParent();
		while (parent != null) {
			if (parent instanceof JScrollPane) {
				return (JScrollPane) parent;
			}
			parent = parent.getParent();
		}
		return null;
	}

	private void showNavigationAid() {
		String showAidString = Preferences.getProperty(HelpManager.SHOW_AID_KEY);
		if (showAidString == null) {
			return;
		}

		boolean showAid = Boolean.parseBoolean(showAidString);
		if (!showAid) {
			return;
		}

		calloutReferenceLater();
	}

	private void calloutReferenceLater() {
		Swing.runLater(() -> calloutReference(loadingURL));
	}

	private void calloutReference(final URL url) {
		String ref = url.getRef();
		if (ref == null) {
			return;
		}

		final Rectangle area = getReferenceArea(ref);
		if (area == null) {
			return;
		}

		doCalloutReference(area, 0);
	}

	private Rectangle getReferenceArea(String ref) {
		HTMLDocument document = (HTMLDocument) htmlEditorPane.getDocument();
		HTMLDocument.Iterator iter = document.getIterator(HTML.Tag.A);
		for (; iter.isValid(); iter.next()) {
			AttributeSet attributes = iter.getAttributes();
			String name = (String) attributes.getAttribute(HTML.Attribute.NAME);
			if (name == null || !name.equals(ref)) {
				continue;
			}

			try {
				int start = iter.getStartOffset();
				Rectangle2D startArea = htmlEditorPane.modelToView2D(start);
				return startArea.getBounds();
			}
			catch (BadLocationException ble) {
				Msg.trace(this, "Unexpected exception searching for help reference", ble);
			}
		}
		return null;
	}

	/**
	 * This method exists to address the threaded timing nature of how the help system loads
	 * help pages and when the UI is adjusted in response to those changes.
	 * <p>
	 * Note: this method will call itself if the view is not yet updated for the requested
	 *       model change.  In that case, this method will call itself again later.  This may
	 *       need to happen more than once.  However, we will only try a few times and
	 *       then just give up.
	 *
	 * @param area the area to call out
	 * @param callCount the number number of times this method has already been called
	 */
	private void doCalloutReference(final Rectangle area, int callCount) {

		if (callCount > MAX_CALLOUT_RETRIES) {
			// this probably can't happen, but we don't want to keep calling this method
			// forever.
			return;
		}

		WindowPresentation windowPresentation = getWindowPresentation();
		Window helpWindow = windowPresentation.getHelpWindow();
		Container contentPane = null;
		if (helpWindow instanceof JDialog) {
			contentPane = ((JDialog) helpWindow).getContentPane();
		}
		else {
			contentPane = ((JFrame) helpWindow).getContentPane();
		}

		JScrollPane scrollPane = getScrollPane(htmlEditorPane);
		JViewport viewport = scrollPane.getViewport();
		Point viewPosition = viewport.getViewPosition();

		final int numberOfCalls = callCount + 1;
		if (viewPosition.x == 0 && viewPosition.y == 0) {

			//
			// Unusual Code: Not yet rendered!  Try again.
			//
			Swing.runLater(() -> doCalloutReference(area, numberOfCalls));

			return;
		}

		//
		// The area of the HTML content is absolute inside of the entire document.
		// However, the user is viewing the document inside of a scroll pane.  So, we
		// want the offset of the element within the viewer, not the absolute position.
		//
		area.y -= viewPosition.y;

		//
		// Update the coordinates to be relative to the content pane, which is where we
		// are doing the painting.
		//
		Rectangle relativeArea = SwingUtilities.convertRectangle(scrollPane, area, contentPane);
		Shape star = new StarShape(relativeArea.getLocation());

		Animator animator =
			AnimationUtils.createPaintingAnimator(helpWindow, new LocationHintPainter(star));
		if (animator == null) {
			return;
		}

		lastAnimator = animator;
		lastAnimator.addTarget(new TimingTargetAdapter() {
			@Override
			public void end() {
				lastAnimator = null;
			}
		});
	}

	private void prepareToCallout(URL url) {
		if (lastAnimator != null) {
			// prevent animations from lingering when moving to new pages
			lastAnimator.stop();
		}

		loadingURL = url;

		// updateTitle();

		if (isCurrentPage(loadingURL)) {
			showNavigationAid();
			return;// page already loaded; no need to use the listener
		}

		// listen for the page to be loaded, as it is asynchronous
		htmlEditorPane.removePropertyChangeListener("page", pageLoadListener);
		htmlEditorPane.addPropertyChangeListener("page", pageLoadListener);
	}

	private boolean isCurrentPage(URL newURL) {
		if (newURL == null) {
			return false;// not sure if this can happen
		}

		String newFile = newURL.getFile();
		URL currentURL = htmlEditorPane.getPage();
		if (currentURL == null) {
			return false;
		}

		String currentFile = currentURL.getFile();
		return newFile.equals(currentFile);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

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

	private class PageLoadingListener implements PropertyChangeListener {
		@Override
		public void propertyChange(PropertyChangeEvent evt) {
			showNavigationAid();
			htmlEditorPane.removePropertyChangeListener("page", pageLoadListener);
		}
	}

	private class HelpIDChangedListener implements HelpModelListener {
		@Override
		public void idChanged(HelpModelEvent e) {
			prepareToCallout(e.getURL());
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
