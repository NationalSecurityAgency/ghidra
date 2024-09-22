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
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.time.Duration;
import java.util.Objects;

import javax.swing.*;

import generic.json.Json;
import generic.theme.Gui;
import generic.util.WindowUtilities;
import generic.util.image.ImageUtils;
import ghidra.util.Swing;
import ghidra.util.bean.GGlassPane;
import ghidra.util.timer.GTimer;
import ghidra.util.timer.GTimerMonitor;

/**
 * A class that allows clients to paint a message over top of a given component.
 * <P>
 * This class will honor newline characters and will word wrap as needed.  If the message being 
 * displayed will not fit within the bounds of the given component, then the text will be clipped.
 */
public class GGlassPaneMessage {

	private static final int HIDE_DELAY_MILLIS = 2000;

	private AnimationRunner animationRunner;
	private GTimerMonitor timerMonitor;
	private Duration hideDelay = Duration.ofMillis(HIDE_DELAY_MILLIS);

	private JComponent component;
	private String message;

	public GGlassPaneMessage(JComponent component) {
		this.component = component;

		component.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
					if (animationRunner != null) {
						hide();
						e.consume();
					}
				}
			}
		});

	}

	/**
	 * Sets the amount of time the message will remain on screen after the animation has completed.
	 * To hide the message sooner, call {@link #hide()}.
	 * @param duration the duration
	 */
	public void setHideDelay(Duration duration) {
		hideDelay = Objects.requireNonNull(duration);
	}

	/**
	 * Shows the given message centered over the component used by this class.
	 * @param newMessage the message
	 */
	public void showCenteredMessage(String newMessage) {
		AnimationPainter painter = new CenterTextPainter();
		showMessage(newMessage, painter);
	}

	/**
	 * Shows a message at the bottom of the component used by this class.
	 * @param newMessage the message
	 */
	public void showBottomMessage(String newMessage) {
		AnimationPainter painter = new BottomTextPainter();
		showMessage(newMessage, painter);
	}

	public void showMessage(String newMessage, AnimationPainter painter) {

		hide();

		this.message = Objects.requireNonNull(newMessage);

		AnimationRunner runner = new AnimationRunner(component);

		double full = 1D;
		double emphasized = 1.2D;
		Double[] stages = new Double[] { full, emphasized, emphasized, emphasized, full };
		runner.setValues(stages);
		runner.setDuration(Duration.ofMillis(500));
		runner.setRemovePainterWhenFinished(false); // we will remove it ourselves
		runner.setPainter(painter);
		runner.start();

		animationRunner = runner;

		// remove the text later so users have a chance to read it
		timerMonitor = GTimer.scheduleRunnable(hideDelay.toMillis(), () -> {
			Swing.runNow(() -> hide());
		});
	}

	/**
	 * Hides any message being displayed.  This can be called even if the message has been hidden.
	 */
	public void hide() {

		if (animationRunner != null) {
			animationRunner.stop();
			animationRunner = null;
		}

		if (timerMonitor != null) {
			timerMonitor.cancel();
			timerMonitor = null;
		}
	}

	@Override
	public String toString() {
		return Json.toString(message);
	}

//=================================================================================================
// Inner Classes
//=================================================================================================

	private abstract class AbstractTextPainer implements AnimationPainter {

		private static String FONT_ID = "font.glasspane.message";
		private static final String MESSAGE_FG_COLOR_ID = "color.fg.glasspane.message";

		// use an image of the painted text to make scaling smoother; cache the image for speed
		protected Image baseTextImage;

		private ComponentListener resizeListener = new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				baseTextImage = null;
				Window w = WindowUtilities.windowForComponent(component);
				w.repaint();
			}
		};

		AbstractTextPainer() {
			component.addComponentListener(resizeListener);
		}

		private void createImage() {

			if (baseTextImage != null) {
				return;
			}

			Font font = Gui.getFont(FONT_ID);
			BufferedImage tempImage = new BufferedImage(10, 10, BufferedImage.TYPE_INT_ARGB);
			Graphics2D scratchG2d = (Graphics2D) tempImage.getGraphics();

			scratchG2d.setFont(font);
			Dimension size = getComponentSize();
			int padding = 20;
			size.width -= padding;
			TextShaper textShaper = new TextShaper(message, size, scratchG2d);

			Dimension textSize = textShaper.getTextSize();
			if (textSize.width == 0 || textSize.height == 0) {
				return; // not enough room to paint text
			}

			// Add some space to handle float to int rounding in the text calculation. This prevents
			// the edge of characters from getting clipped when painting.
			int roundingPadding = 5;
			int w = textSize.width + roundingPadding;
			int h = textSize.height;

			BufferedImage bi = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
			Graphics2D g2d = (Graphics2D) bi.getGraphics();
			g2d.setFont(font);
			g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
				RenderingHints.VALUE_ANTIALIAS_ON);

			g2d.setColor(Gui.getColor(MESSAGE_FG_COLOR_ID));

			textShaper.drawText(g2d);

			g2d.dispose();

			baseTextImage = bi;
		}

		protected Dimension getComponentSize() {
			Rectangle r = component.getVisibleRect();
			Dimension size = r.getSize();
			Container parent = component.getParent();
			if (parent instanceof JScrollPane || parent instanceof JViewport) {
				// this handles covering the component when it is inside of a scroll pane
				size = parent.getSize();
			}
			return size;
		}

		protected Rectangle getComponentBounds(GGlassPane glassPane) {

			Rectangle r = component.getVisibleRect();
			Point point = r.getLocation();
			Dimension size = r.getSize();

			Container parent = component.getParent();
			Component coordinateSource = parent;
			if (parent instanceof JScrollPane || parent instanceof JViewport) {
				// this handles covering the component when it is inside of a scroll pane
				point = parent.getLocation();
				size = parent.getSize();
				coordinateSource = parent.getParent();
			}

			point = SwingUtilities.convertPoint(coordinateSource, point, glassPane);
			return new Rectangle(point, size);
		}

		protected Image updateImage(Graphics2D g2d, double scale) {

			baseTextImage = null;

			createImage();

			if (baseTextImage == null) {
				return null; // this implies an exception happened
			}

			int w = baseTextImage.getWidth(null);
			int h = baseTextImage.getHeight(null);

			int sw = ((int) (w * scale));
			int sh = ((int) (h * scale));

			int iw = baseTextImage.getWidth(null);
			int ih = baseTextImage.getHeight(null);

			if (iw == sw && ih == sh) {
				return baseTextImage; // nothing to change
			}

			return ImageUtils.createScaledImage(baseTextImage, sw, sh, 0);
		}

		protected void paintOverComponent(Graphics2D g2d, GGlassPane glassPane) {

			Rectangle bounds = getComponentBounds(glassPane);

			float alpha = .7F; // arbitrary; allow some of the background to be visible
			AlphaComposite alphaComposite = AlphaComposite
					.getInstance(AlphaComposite.SrcOver.getRule(), alpha);
			Composite originalComposite = g2d.getComposite();
			Color originalColor = g2d.getColor();
			g2d.setComposite(alphaComposite);
			g2d.setColor(component.getBackground());

			g2d.fillRect(bounds.x, bounds.y, bounds.width, bounds.height);

			g2d.setComposite(originalComposite);
			g2d.setColor(originalColor);
		}
	}

	private class CenterTextPainter extends AbstractTextPainer {

		@Override
		public void paint(GGlassPane glassPane, Graphics graphics, double intensity) {

			Graphics2D g2d = (Graphics2D) graphics;

			Image image = updateImage(g2d, intensity);
			if (image == null) {
				return; // this implies an exception happened
			}

			// use visible rectangle to get the correct size when in a scroll pane
			Rectangle componentBounds = getComponentBounds(glassPane);

			// without room to draw the message, skip so we don't draw over other components
			int imageHeight = image.getHeight(null);
			if (imageHeight > componentBounds.height) {
				return;
			}

			paintOverComponent(g2d, glassPane);

			// note: textHeight and textWidth will vary depending on the intensity
			int textHeight = image.getHeight(null);
			int textWidth = image.getWidth(null);
			int padding = 5;
			int middleY = componentBounds.y + (componentBounds.height / 2);
			int middleX = componentBounds.x + (componentBounds.width / 2);
			int requiredHeight = textHeight + padding;
			int requiredWidth = textWidth + padding;
			int y = middleY - (requiredHeight / 2);
			int x = middleX - (requiredWidth / 2);

			g2d.drawImage(image, x, y, null);

			// debug
			// g2d.setColor(Palette.BLUE);
			// g2d.drawRect(x, y, textWidth, textHeight);
		}

	}

	private class BottomTextPainter extends AbstractTextPainer {

		@Override
		public void paint(GGlassPane glassPane, Graphics graphics, double intensity) {

			Graphics2D g2d = (Graphics2D) graphics;

			Image image = updateImage(g2d, intensity);
			if (image == null) {
				return; // this implies an exception happened
			}

			// use visible rectangle to get the correct size when in a scroll pane
			Rectangle componentBounds = getComponentBounds(glassPane);

			// without room to draw the message, skip so we don't draw over other components
			int imageHeight = image.getHeight(null);
			if (imageHeight > componentBounds.height) {
				return;
			}

			paintOverComponent(g2d, glassPane);

			int textHeight = image.getHeight(null);
			int padding = 5;
			int bottom = componentBounds.y + componentBounds.height;
			int requiredHeight = textHeight + padding;
			int y = bottom - requiredHeight;
			int x = componentBounds.x + padding;

			g2d.drawImage(image, x, y, null);

		}

	}
}
