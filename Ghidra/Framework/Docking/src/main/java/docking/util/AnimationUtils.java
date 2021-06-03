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
import java.awt.image.BufferedImage;

import javax.swing.*;

import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.Animator.RepeatBehavior;
import org.jdesktop.animation.timing.TimingTargetAdapter;
import org.jdesktop.animation.timing.interpolation.PropertySetter;

import generic.util.WindowUtilities;
import generic.util.image.ImageUtils;
import ghidra.util.Msg;
import ghidra.util.bean.GGlassPane;
import ghidra.util.bean.GGlassPanePainter;
import ghidra.util.exception.AssertException;
import resources.ResourceManager;

public class AnimationUtils {

	private static boolean animationEnabled = true;

	private AnimationUtils() {
		// utils class--cannot instantiate
	}

	/**
	 * Returns true if animation is enabled; false if animation has been disable, such as by
	 * a user option
	 * 
	 * @return true if enabled
	 */
	public static boolean isAnimationEnabled() {
		return animationEnabled;
	}

	/**
	 * Enables animation <b>for all tools in the Ghidra universe</b>.
	 * @param enabled true if animations should be used
	 */
	public static void setAnimationEnabled(boolean enabled) {
		animationEnabled = enabled;
	}

	/**
	 * Focuses the current component by graying out all other components but the given one and
	 * bringing that component to the middle of the screen.
	 * 
	 * @param component The component to focus
	 * @return the new animator
	 */
	public static Animator focusComponent(Component component) {
		if (!animationEnabled) {
			return null;
		}

		GGlassPane glassPane = getGlassPane(component);
		if (glassPane == null) {
			// could happen if the given component has not yet been realized
			return null;
		}

		FocusDriver driver = new FocusDriver(glassPane, component);
		return driver.animator;
	}

	public static Animator transitionUserFocusToComponent(Component activeComponent,
			Component toFocusComponent) {
		if (!animationEnabled) {
			return null;
		}

		if (activeComponent == null) {
			// this can happen in the testing environment
			Msg.error(AnimationUtils.class, "No active component for animation!");
			return null;
		}

		if (!componentsAreInTheSameWindow(activeComponent, toFocusComponent)) {
			throw new IllegalArgumentException(
				"The active component and the component to focus must be in the same window");
		}

		GGlassPane glassPane = getGlassPane(activeComponent);
		if (glassPane == null) {
			// could happen if the given component has not yet been realized
			return null;
		}

		PointToComponentDriver driver =
			new PointToComponentDriver(glassPane, activeComponent, toFocusComponent);
		return driver.animator;
	}

	public static Animator transitionFromComponentToComponent(Component fromComponent,
			Component toComponent) {
		if (!animationEnabled) {
			return null;
		}

		if (!componentsAreInTheSameWindow(fromComponent, toComponent)) {
			throw new IllegalArgumentException(
				"The fromComponent and the component to focus " + "must be in the same window");
		}

		GGlassPane glassPane = getGlassPane(fromComponent);
		if (glassPane == null) {
			// could happen if the given component has not yet been realized
			return null;
		}

		ComponentToComponentDriver driver =
			new ComponentToComponentDriver(glassPane, fromComponent, toComponent);
		return driver.animator;
	}

	public static Animator createPaintingAnimator(Component window, AnimationPainter painter) {
		if (!animationEnabled) {
			return null;
		}

		Component paneComponent = getGlassPane(window);
		if (paneComponent == null) {
			// could happen if the given component has not yet been realized
			return null;
		}

		if (!(paneComponent instanceof GGlassPane)) {
			Msg.debug(AnimationUtils.class,
				"Cannot animate without a " + GGlassPane.class.getName() + " installed");
			return null; // shouldn't happen
		}

		GGlassPane glassPane = (GGlassPane) paneComponent;
		BasicAnimationDriver driver =
			new BasicAnimationDriver(glassPane, new UserDefinedPainter(painter));
		return driver.animator;
	}

	public static Animator shakeComponent(Component component) {
		if (!animationEnabled) {
			return null;
		}

		GGlassPane glassPane = getGlassPane(component);
		if (glassPane == null) {
			// could happen if the given component has not yet been realized
			return null;
		}

		ShakeDriver shaker = new ShakeDriver(glassPane, component);
		return shaker.animator;
	}

	public static Animator rotateComponent(Component component) {
		if (!animationEnabled) {
			return null;
		}

		GGlassPane glassPane = getGlassPane(component);
		if (glassPane == null) {
			// could happen if the given component has not yet been realized
			return null;
		}

		RotateDriver rotator = new RotateDriver(glassPane, component);
		return rotator.animator;
	}

	public static Animator pulseComponent(Component component) {
		return pulseComponent(component, 2);
	}

	public static Animator pulseComponent(Component component, int pulseCount) {
		if (!animationEnabled) {
			return null;
		}

		GGlassPane glassPane = getGlassPane(component);
		if (glassPane == null) {
			// could happen if the given component has not yet been realized
			return null;
		}

		PulseDriver pulser = new PulseDriver(glassPane, component, false, pulseCount);
		return pulser.animator;
	}

	public static Animator pulseAndShakeComponent(Component component) {
		if (!animationEnabled) {
			return null;
		}

		GGlassPane glassPane = getGlassPane(component);
		if (glassPane == null) {
			// could happen if the given component has not yet been realized
			return null;
		}

		PulseDriver pulser = new PulseDriver(glassPane, component, true, 2);
		return pulser.animator;
	}

	public static Animator showTheDragonOverComponent(Component component) {
		if (!animationEnabled) {
			return null;
		}

		GGlassPane glassPane = getGlassPane(component);
		if (glassPane == null) {
			// could happen if the given component has not yet been realized
			return null;
		}

		DragonImageDriver pulser = new DragonImageDriver(component);
		return pulser.animator;
	}

	public static Animator executeSwingAnimationCallback(SwingAnimationCallback callback) {
		// note: instead of checking for 'animationEnabled' here, it will happen in the driver
		//       so that the we can call SwingAnimationCallback.done(), which will let the client 
		//       perform its final action.
		int duration = callback.getDuration();
		SwingAnimationCallbackDriver driver = new SwingAnimationCallbackDriver(callback, duration);
		return driver.animator;
	}

	/**
	 * Returns the {@link GGlassPane} for the given component
	 * 
	 * @param c the component
	 * @return the glass pane
	 */
	public static GGlassPane getGlassPane(Component c) {

		// TODO: validate component has been realized? ...check for window, but that would
		//       then put the onus on the client

		Window window = WindowUtilities.windowForComponent(c);
		if (window instanceof JFrame) {
			JFrame frame = (JFrame) window;
			Component glass = frame.getGlassPane();

			if (!(glass instanceof GGlassPane)) {
				Msg.error(AnimationUtils.class, "GGlassPane not installed on window: " + window,
					new AssertException());
				return null;
			}

			return ((GGlassPane) glass);
		}
		else if (window instanceof JDialog) {
			JDialog frame = (JDialog) window;
			Component glass = frame.getGlassPane();

			if (!(glass instanceof GGlassPane)) {
				Msg.error(AnimationUtils.class, "GGlassPane not installed on window: " + window,
					new AssertException());
				return null;
			}

			return ((GGlassPane) glass);
		}
		return null;
	}

	private static boolean componentsAreInTheSameWindow(Component activeComponent,
			Component toFocusComponent) {
		Window startWindow = WindowUtilities.windowForComponent(activeComponent);
		Window toWindow = WindowUtilities.windowForComponent(toFocusComponent);
		return startWindow == toWindow;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	public static class SwingAnimationCallbackDriver {
		private Animator animator;
		private SwingAnimationCallback callback;

		SwingAnimationCallbackDriver(SwingAnimationCallback swingCallback, int duration) {
			this.callback = swingCallback;
			double start = 0;
			double max = 1.0;

			if (!animationEnabled) {
				// no animation; signal to just do the work
				callback.done();
				return;
			}

			animator = PropertySetter.createAnimator(duration, this, "percentComplete", start, max);

			animator.setAcceleration(0.2f);
			animator.setDeceleration(0.8f);
			animator.addTarget(new TimingTargetAdapter() {
				@Override
				public void end() {
					callback.done();
				}
			});

			animator.start();
		}

		// note: must be public--it is a callback from the animator (also, its name must 
		//       match the value passed to the animator)
		public void setPercentComplete(double percent) {
			callback.progress(percent);
		}
	}

	public static class FocusDriver {
		private Animator animator;
		private FocusPainter painter;
		private GGlassPane glassPane;

		FocusDriver(GGlassPane glassPane, Component component) {
			this.glassPane = glassPane;

			double start = 0;
			double max = .5;
			this.painter = new FocusPainter(component, max);

			animator = PropertySetter.createAnimator(1000, this, "percentComplete", start, max, max,
				max, max, max, start);

			animator.setAcceleration(0.2f);
			animator.setDeceleration(0.8f);
			animator.addTarget(new TimingTargetAdapter() {
				@Override
				public void end() {
					done();
				}
			});

			glassPane.addPainter(painter);

			animator.start();
		}

		// note: must be public--it is a callback from the animator (also, its name must 
		//       match the value passed to the animator)
		public void setPercentComplete(double percent) {
			painter.setPercentComplete(percent);
			glassPane.repaint();
		}

		void done() {
			painter.setPercentComplete(0.0);
			glassPane.repaint();
			glassPane.removePainter(painter);
		}
	}

	private static class FocusPainter implements GGlassPanePainter {

		private Image image;
		private Component component;

		private double magnification = .0;
		private double percentComplete = 0.0;
		private double max;

		FocusPainter(Component component, double max) {
			this.component = component;
			this.max = max;
			image = ImageUtils.createImage(component);
		}

		void setPercentComplete(double percent) {
			percentComplete = percent;
		}

		@Override
		public void paint(GGlassPane glassPane, Graphics g) {
			Color gray = Color.GRAY;
//			double darknessFudge = .95;
//			double progress = percentComplete * darknessFudge; // emphasis starts at 1			
//			int alpha = Math.min(255, (int) (255 * progress));
//			gray = new Color(gray.getRed(), gray.getGreen(), gray.getBlue(), alpha);
			gray = new Color(gray.getRed(), gray.getGreen(), gray.getBlue());

			Graphics2D g2d = (Graphics2D) g;
			Composite originaComposite = g2d.getComposite();
			AlphaComposite alphaComposite = AlphaComposite.getInstance(
				AlphaComposite.SrcOver.getRule(), (float) percentComplete);
			g2d.setComposite(alphaComposite);

			g.setColor(gray);
			Rectangle displayBounds = glassPane.getBounds();
			g.fillRect(displayBounds.x, displayBounds.y, displayBounds.width, displayBounds.height);

			g2d.setComposite(originaComposite);

			Rectangle defaultBounds = component.getBounds();

			double emphasis = 1 + (magnification * percentComplete);
			// emphasis = (magnification * percentComplete); // thumbnail 
			int width = (int) (defaultBounds.width * emphasis);
			int height = (int) (defaultBounds.height * emphasis);

			Rectangle emphasizedBounds =
				new Rectangle(defaultBounds.x, defaultBounds.y, width, height);

			emphasizedBounds =
				SwingUtilities.convertRectangle(component.getParent(), emphasizedBounds, glassPane);

			// 
			// Calculate the position of the image.   At 100% we want to be in the center of
			// the display; at 0% we want to be at our default location
			// 

			double asPercent = percentComplete * (1 / max);

			double displayCenterX = displayBounds.getCenterX();
			double displayCenterY = displayBounds.getCenterY();
			double currentCenterX = emphasizedBounds.getCenterX();
			double currentCenterY = emphasizedBounds.getCenterY();

			double deltaCenterX = displayCenterX - currentCenterX;
			double deltaCenterY = displayCenterY - currentCenterY;

			double progressX = deltaCenterX * asPercent;
			double progressY = deltaCenterY * asPercent;

			double newCenterX = currentCenterX + progressX;
			double newCenterY = currentCenterY + progressY;

			int x = (int) (newCenterX - (width >> 1));
			int y = (int) (newCenterY - (height >> 1));

			g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
				RenderingHints.VALUE_INTERPOLATION_BILINEAR);

			g.drawImage(image, x, y, width, height, null);
		}
	}

	public static class PointToComponentDriver {
		private Animator animator;
		private PointToComponentPainter painter;
		private GGlassPane glassPane;

		PointToComponentDriver(GGlassPane glassPane, Component fromComponent,
				Component toComponent) {
			this.glassPane = glassPane;

			painter =
				new PointToComponentPainter(getStartPointFromComponent(fromComponent), toComponent);

			double start = 0;
			double max = 1.0;
			animator = PropertySetter.createAnimator(500, this, "percentComplete", start, max);

			animator.setAcceleration(0.2f);
			animator.setDeceleration(0.8f);
			animator.addTarget(new TimingTargetAdapter() {
				@Override
				public void end() {
					done();
				}
			});

			glassPane.addPainter(painter);

			animator.start();
		}

		private Point getStartPointFromComponent(Component component) {

			if (SwingUtilities.isDescendingFrom(component, glassPane)) {
				Rectangle startBounds = component.getBounds();
				Point relativeStartCenter =
					new Point((int) startBounds.getCenterX(), (int) startBounds.getCenterY());
				return SwingUtilities.convertPoint(component.getParent(), relativeStartCenter,
					glassPane);
			}

			Rectangle startBounds = component.getBounds();
			Container parent = component.getParent();
			if (parent == null) {
				// the given component is a Window; make it be the root
				startBounds.x = 0;
				startBounds.y = 0;
			}

			Point relativeStartCenter =
				new Point((int) startBounds.getCenterX(), (int) startBounds.getCenterY());
			return SwingUtilities.convertPoint(component.getParent(), relativeStartCenter,
				glassPane);
		}

		// note: must be public--it is a callback from the animator (also, its name must 
		//       match the value passed to the animator)
		public void setPercentComplete(double percent) {
			painter.setPercentComplete(percent);
			glassPane.repaint();
		}

		void done() {
			painter.setPercentComplete(0.0);
			glassPane.repaint();
			glassPane.removePainter(painter);
		}

	}

	private static class PointToComponentPainter implements GGlassPanePainter {

		private Image image;
		private Component component;
		private double percentComplete = 0.0;
		private Point startPoint;

		PointToComponentPainter(Point startPoint, Component component) {
			this.startPoint = startPoint;
			this.component = component;
			image = ImageUtils.createImage(component);
		}

		void setPercentComplete(double percent) {
			percentComplete = percent;
		}

		@Override
		public void paint(GGlassPane glassPane, Graphics graphics) {
			//
			// Update the size of the component, based upon the percent of completion
			//
			Graphics2D g2d = (Graphics2D) graphics;

			// 
			// Move the component to the update location, based upon the percent of completion
			//	
			Rectangle defaultBounds = component.getBounds();
			defaultBounds =
				SwingUtilities.convertRectangle(component.getParent(), defaultBounds, glassPane);
			Point endPoint = defaultBounds.getLocation();
			int distanceX = endPoint.x - startPoint.x;
			int distanceY = endPoint.y - startPoint.y;
			double currentX = endPoint.x - (distanceX * (1 - percentComplete));
			double currentY = endPoint.y - (distanceY * (1 - percentComplete));

			int scaledWidth = (int) (defaultBounds.width * percentComplete);
			int scaledHeight = (int) (defaultBounds.height * percentComplete);

			// gains opacity as it gets closer to the end; capped at the given percentage
			float opacity = (float) Math.min(.65, percentComplete);
			Composite originalComposite = g2d.getComposite();
			AlphaComposite alphaComposite = AlphaComposite.getInstance(
				AlphaComposite.SrcOver.getRule(), opacity);
			g2d.setComposite(alphaComposite);

			// 
			// Calculate the position of the image.   At 100% we want to be in the center of
			// the display; at 0% we want to be at our default location
			// 
			g2d.drawImage(image, (int) currentX, (int) currentY, scaledWidth, scaledHeight, null);

			g2d.setComposite(originalComposite);
		}
	}

	// note: must be public due to reflection used by the timing framework
	public static class BasicAnimationDriver {
		protected Animator animator;
		protected BasicAnimationPainter painter;
		protected GGlassPane glassPane;

		protected BasicAnimationDriver(GGlassPane glassPane, BasicAnimationPainter painter) {
			this.glassPane = glassPane;
			this.painter = painter;

			double start = 0;
			double max = 1.0;

			animator = PropertySetter.createAnimator(2000, this, "percentComplete", start, max);

			animator.setAcceleration(0.2f);
			animator.setDeceleration(0.8f);
			animator.addTarget(new TimingTargetAdapter() {
				@Override
				public void end() {
					done();
				}
			});

			glassPane.addPainter(painter);

			animator.start();
		}

		// note: must be public--it is a callback from the animator (also, its name must 
		//       match the value passed to the animator)
		public void setPercentComplete(double percent) {
			painter.setPercentComplete(percent);
			glassPane.repaint();
		}

		void done() {
			painter.setPercentComplete(0.0);
			glassPane.repaint();
			glassPane.removePainter(painter);
		}
	}

	public static abstract class BasicAnimationPainter implements GGlassPanePainter {
		protected double percentComplete = 0.0;

		void setPercentComplete(double percent) {
			percentComplete = percent;
		}

		protected Image paintImage(Component component) {
			Rectangle bounds = component.getBounds();
			BufferedImage bufferedImage =
				new BufferedImage(bounds.width, bounds.height, BufferedImage.TYPE_INT_ARGB);
			Graphics g = bufferedImage.getGraphics();
			component.paint(g);
			g.dispose();
			return bufferedImage;
		}
	}

	private static class UserDefinedPainter extends BasicAnimationPainter {

		private AnimationPainter painter;

		UserDefinedPainter(AnimationPainter painter) {
			this.painter = painter;
		}

		@Override
		public void paint(GGlassPane glassPane, Graphics graphics) {
			painter.paint(glassPane, graphics, percentComplete);
		}
	}

	public static class ComponentToComponentDriver extends BasicAnimationDriver {

		ComponentToComponentDriver(GGlassPane glassPane, Component fromComponent,
				Component toComponent) {
			super(glassPane, new ComponentToComponentPainter(fromComponent, toComponent));
		}
	}

	static class ComponentToComponentPainter extends BasicAnimationPainter {

		private Image startImage;
		private Image endImage;
		private Component startComponent;
		private Component endComponent;

		ComponentToComponentPainter(Component startComponent, Component endComponent) {
			this.startComponent = startComponent;
			this.endComponent = endComponent;
			startImage = paintImage(startComponent);
			endImage = paintImage(endComponent);
		}

		@Override
		public void paint(GGlassPane glassPane, Graphics graphics) {
			Graphics2D g2d = (Graphics2D) graphics;

			g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
				RenderingHints.VALUE_INTERPOLATION_BILINEAR);

			//
			// At 0%, paint the start component with 100% opacity; paint the end component with
			// 0% opacity. 
			//
			Composite originalComposite = g2d.getComposite();
			AlphaComposite alphaComposite = AlphaComposite.getInstance(
				AlphaComposite.SrcOver.getRule(), (float) (1 - percentComplete));
			g2d.setComposite(alphaComposite);

			//
			// Morph the size of the start component to that of the end component, based upon the
			// percent complete
			//
			Rectangle startBounds = startComponent.getBounds();
			startBounds =
				SwingUtilities.convertRectangle(startComponent.getParent(), startBounds, glassPane);

			Rectangle endBounds = endComponent.getBounds();
			endBounds =
				SwingUtilities.convertRectangle(endComponent.getParent(), endBounds, glassPane);

			Point startPoint = startBounds.getLocation();
			Point endPoint = endBounds.getLocation();
			int distanceX = endPoint.x - startPoint.x;
			int distanceY = endPoint.y - startPoint.y;

			double transition = 1 - percentComplete;
			double currentX = endPoint.x - (distanceX * transition);
			double currentY = endPoint.y - (distanceY * transition);

			int scaledWidth = (int) (startBounds.width * transition);
			int scaledHeight = (int) (startBounds.height * transition);

			if (endBounds.width < startBounds.width) {
				// don't go smaller than the destination component
				scaledWidth = Math.max(scaledWidth, endBounds.width);
			}
			else {
				// don't go larger than the destination component
				scaledWidth = Math.min(scaledWidth, endBounds.width);
			}

			if (endBounds.height < startBounds.height) {
				// don't go smaller than the destination component
				scaledHeight = Math.max(scaledHeight, endBounds.height);
			}
			else {
				// don't go larger than the destination component
				scaledHeight = Math.min(scaledHeight, endBounds.height);
			}

			g2d.drawImage(startImage, (int) currentX, (int) currentY, scaledWidth, scaledHeight,
				null);

			//
			// Change the transparency to that which will slowly become more visible as 
			// we progress.
			// 
			alphaComposite = AlphaComposite.getInstance(AlphaComposite.SrcOver.getRule(),
				(float) percentComplete);
			g2d.setComposite(alphaComposite);

			currentX = endPoint.x - (distanceX * transition);
			currentY = endPoint.y - (distanceY * transition);
			scaledWidth = (int) (endBounds.width * percentComplete);
			scaledHeight = (int) (endBounds.height * percentComplete);
			g2d.drawImage(endImage, (int) currentX, (int) currentY, scaledWidth, scaledHeight,
				null);

			g2d.setComposite(originalComposite);
		}
	}

	public static class RotateDriver {
		private Animator animator;
		private GGlassPane glassPane;
		private RotatePainter rotatePainter;

		RotateDriver(GGlassPane glassPane, Component component) {
			rotatePainter = new RotatePainter(component);
			this.glassPane = glassPane;

			double start = 0;
			double max = 1;
			animator = PropertySetter.createAnimator(1000, this, "percentComplete", start, max);

			animator.setAcceleration(0.2f);
			animator.setDeceleration(0.8f);

			animator.addTarget(new TimingTargetAdapter() {
				@Override
				public void end() {
					done();
				}
			});

			glassPane.addPainter(rotatePainter);

			animator.start();
		}

		public void setPercentComplete(double percentComplete) {
			rotatePainter.setPercentComplete(percentComplete);
			glassPane.repaint();
		}

		void cancel() {
			animator.stop();
			done();
		}

		void done() {
			glassPane.repaint();
			glassPane.removePainter(rotatePainter);
		}
	}

	private static class RotatePainter implements GGlassPanePainter {

		private Image image;
		private Component component;
		private double percentComplete = 0.0;

		RotatePainter(Component component) {
			this.component = component;
			image = ImageUtils.createImage(component);
		}

		void setPercentComplete(double percent) {
			percentComplete = percent;
		}

		@Override
		public void paint(GGlassPane glassPane, Graphics g) {

			Color background = new Color(218, 232, 250);
			g.setColor(background);

			Rectangle defaultBounds = component.getBounds();

			Rectangle bounds =
				SwingUtilities.convertRectangle(component.getParent(), defaultBounds, glassPane);
			g.fillRect(bounds.x, bounds.y, bounds.width, bounds.height);

			int width = defaultBounds.width;
			int height = defaultBounds.height;

			double transition = 1 - percentComplete;

			double smallest = .5;
			double shrinkage = smallest;
			if (transition > smallest) {
				shrinkage = transition;
			}
			else if (transition < (1 - smallest)) {
				shrinkage = 1 - transition;
			}

			int biggest = Math.min(defaultBounds.width, defaultBounds.height);
			double maxShrink = biggest * .50;
			int offset = (int) (maxShrink - (maxShrink * shrinkage));

			int x = defaultBounds.x + offset;
			int y = defaultBounds.y + offset;
			int w = defaultBounds.width - (offset * 2);
			int h = defaultBounds.height - (offset * 2);

			Rectangle emphasizedBounds = new Rectangle(x, y, w, h);

			emphasizedBounds =
				SwingUtilities.convertRectangle(component.getParent(), emphasizedBounds, glassPane);

			Graphics2D g2d = (Graphics2D) g;

			int offsetX = emphasizedBounds.x - ((width - defaultBounds.width) >> 1);
			int offsetY = emphasizedBounds.y - ((height - defaultBounds.height) >> 1);

			g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
				RenderingHints.VALUE_INTERPOLATION_BILINEAR);

			// spin count: 1 spin = 1.0; 2 spins = .5; 3 spins = .33
			double spinDivisor = .5;
			double cycleAndProgress = percentComplete / spinDivisor;
			int cycle = (int) cycleAndProgress;
			double progress = cycleAndProgress - cycle;

			int startDegree = 360;
			int degrees = (int) (startDegree * progress);
			double rad = Math.toRadians(degrees);

			double cx = emphasizedBounds.getCenterX();
			double cy = emphasizedBounds.getCenterY();
			g2d.rotate(rad, cx, cy);
			g.setColor(Color.BLACK);

			int iw = emphasizedBounds.width;
			int ih = emphasizedBounds.height;
			g.drawRect(offsetX, offsetY, iw, ih);
			g.drawImage(image, offsetX, offsetY, iw, ih, null);
		}
	}

	public static class ShakeDriver {
		private Animator animator;
		private GGlassPane glassPane;
		private ShakePainter shakePainter;

		ShakeDriver(GGlassPane glassPane, Component component) {
			shakePainter = new ShakePainter(component);
			this.glassPane = glassPane;

			double emphasis = 1;
			animator = PropertySetter.createAnimator(425, this, "emphasis", 1.0, emphasis, 1.0);

			animator.setAcceleration(0.2f);
			animator.setDeceleration(0.8f);
			animator.setRepeatCount(2); // non-focus->focus; focus->non-focus (*2)

			animator.setRepeatBehavior(RepeatBehavior.REVERSE);

			animator.addTarget(new TimingTargetAdapter() {
				@Override
				public void end() {
					done();
				}
			});

			glassPane.addPainter(shakePainter);

			animator.start();
		}

		public void setEmphasis(double emphasis) {
			// note: we don't really care about the value here, we are just using the callback
			//       as a repaint trigger
			glassPane.repaint();
		}

		void cancel() {
			animator.stop();
			done();
		}

		void done() {
			glassPane.repaint();
			glassPane.removePainter(shakePainter);
		}
	}

	public static class PulseDriver {
		private Animator animator;
		private GGlassPane glassPane;

		private PulsePainter pulsePainter;

		PulseDriver(GGlassPane glassPane, Component component, boolean shake, int pulseCount) {

			pulsePainter =
				shake ? new PulseAndShakePainter(component) : new PulsePainter(component);

			this.glassPane = glassPane;

			// TODO allow for greater emphasis
			double emphasis = 1.75;

			animator = PropertySetter.createAnimator(425, this, "emphasis", 1.0, emphasis, 1.0);

			animator.setAcceleration(0.2f);
			animator.setDeceleration(0.8f);
			animator.setRepeatCount(pulseCount); // non-focus->focus; focus->non-focus (pulseCount times)

			animator.setRepeatBehavior(RepeatBehavior.REVERSE);

			animator.addTarget(new TimingTargetAdapter() {
				@Override
				public void end() {
					done();
				}
			});

			glassPane.addPainter(pulsePainter);

			animator.start();
		}

		public void setEmphasis(double emphasis) {
			pulsePainter.setEmphasis(emphasis);
			glassPane.repaint();
		}

		void cancel() {
			animator.stop();
			done();
		}

		void done() {
			pulsePainter.setEmphasis(0);
			glassPane.repaint();
			glassPane.removePainter(pulsePainter);
		}
	}

	private static class PulsePainter implements GGlassPanePainter {

		protected Component component;
		protected Image image;
		protected double emphasis = 1.0;

		PulsePainter(Component component) {
			this.component = component;
			image = ImageUtils.createImage(component);
		}

		void setEmphasis(double emphasis) {
			this.emphasis = emphasis;
		}

		@Override
		public void paint(GGlassPane glassPane, Graphics g) {

			Rectangle defaultBounds = component.getBounds();

			int width = (int) (defaultBounds.width * emphasis);
			int height = (int) (defaultBounds.height * emphasis);

			Rectangle emphasizedBounds =
				new Rectangle(defaultBounds.x, defaultBounds.y, width, height);

			emphasizedBounds =
				SwingUtilities.convertRectangle(component.getParent(), emphasizedBounds, glassPane);

			Graphics2D g2d = (Graphics2D) g;

			int offsetX = emphasizedBounds.x - ((width - defaultBounds.width) >> 1);
			int offsetY = emphasizedBounds.y - ((height - defaultBounds.height) >> 1);

			g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
				RenderingHints.VALUE_INTERPOLATION_BILINEAR);

			g.drawImage(image, offsetX, offsetY, width, height, null);
		}
	}

	private static class ShakePainter implements GGlassPanePainter {
		private Component component;
		private Image image;
		private double lastDirection = 1;

		ShakePainter(Component component) {
			this.component = component;
			image = ImageUtils.createImage(component);
		}

		@Override
		public void paint(GGlassPane glassPane, Graphics g) {

			Rectangle defaultBounds = component.getBounds();

			int width = defaultBounds.width;
			int height = defaultBounds.height;

			Rectangle emphasizedBounds =
				new Rectangle(defaultBounds.x, defaultBounds.y, width, height);

			emphasizedBounds =
				SwingUtilities.convertRectangle(component.getParent(), emphasizedBounds, glassPane);

			Graphics2D g2d = (Graphics2D) g;

			int offsetX = emphasizedBounds.x - ((width - defaultBounds.width) >> 1);
			int offsetY = emphasizedBounds.y - ((height - defaultBounds.height) >> 1);

			g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
				RenderingHints.VALUE_INTERPOLATION_BILINEAR);

			//
			// Shake code
			// 
			if (lastDirection > 0) {
//				lastDirection = -.01; // small
				lastDirection = -.031; // bigger
			}
			else {
//				lastDirection = .01; // small
				lastDirection = .031; // bigger
			}

			g2d.rotate(lastDirection, emphasizedBounds.getCenterX(), emphasizedBounds.getCenterY());
			g.drawImage(image, offsetX, offsetY, width, height, null);
		}
	}

	private static class PulseAndShakePainter extends PulsePainter {

		private double lastDirection = 1;

		PulseAndShakePainter(Component component) {
			super(component);
		}

		@Override
		public void paint(GGlassPane glassPane, Graphics g) {

			Rectangle defaultBounds = component.getBounds();

			int width = (int) (defaultBounds.width * emphasis);
			int height = (int) (defaultBounds.height * emphasis);

			Rectangle emphasizedBounds =
				new Rectangle(defaultBounds.x, defaultBounds.y, width, height);

			emphasizedBounds =
				SwingUtilities.convertRectangle(component.getParent(), emphasizedBounds, glassPane);

			Graphics2D g2d = (Graphics2D) g;

			int offsetX = emphasizedBounds.x - ((width - defaultBounds.width) >> 1);
			int offsetY = emphasizedBounds.y - ((height - defaultBounds.height) >> 1);

			g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
				RenderingHints.VALUE_INTERPOLATION_BILINEAR);

			//
			// Shake code
			// 
			if (lastDirection > 0) {
				lastDirection = -.01;
				lastDirection = -.01 * emphasis;
			}
			else {
				lastDirection = .01;
				lastDirection = .01 * emphasis;
			}

			g2d.rotate(lastDirection, emphasizedBounds.getCenterX(), emphasizedBounds.getCenterY());

			g.drawImage(image, offsetX, offsetY, width, height, null);
		}
	}

	// Draws the system dragon icon over the given component
	public static class DragonImageDriver {

		private Animator animator;
		private GGlassPane glassPane;
		private DragonImagePainter rotatePainter;

		DragonImageDriver(Component component) {

			glassPane = AnimationUtils.getGlassPane(component);
			rotatePainter = new DragonImagePainter(component);

			double start = 0;
			double max = 1;
			int duration = 1500;
			animator =
				PropertySetter.createAnimator(duration, this, "percentComplete", start, max, start);

			animator.setAcceleration(0.2f);
			animator.setDeceleration(0.8f);

			animator.addTarget(new TimingTargetAdapter() {
				@Override
				public void end() {
					done();
				}
			});

			glassPane.addPainter(rotatePainter);

			animator.start();
		}

		public void setPercentComplete(double percentComplete) {
			rotatePainter.setPercentComplete(percentComplete);
			glassPane.repaint();
		}

		void done() {
			glassPane.repaint();
			glassPane.removePainter(rotatePainter);
		}
	}

	private static class DragonImagePainter implements GGlassPanePainter {

		private Component component;
		private double percentComplete = 0.0;

		DragonImagePainter(Component component) {
			this.component = component;
		}

		void setPercentComplete(double percent) {
			percentComplete = percent;
		}

		@Override
		public void paint(GGlassPane glassPane, Graphics g) {

			Graphics2D g2d = (Graphics2D) g;
			g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
				RenderingHints.VALUE_INTERPOLATION_BILINEAR);

			float alpha = (float) percentComplete;
			alpha = Math.min(alpha, .5f);
			Composite originaComposite = g2d.getComposite();
			AlphaComposite alphaComposite =
				AlphaComposite.getInstance(AlphaComposite.SrcOver.getRule(), alpha);
			g2d.setComposite(alphaComposite);

			ImageIcon ghidra = ResourceManager.loadImage("images/GhidraIcon256.png");
			Image ghidraImage = ghidra.getImage();

			Rectangle fullBounds = component.getBounds();
			fullBounds =
				SwingUtilities.convertRectangle(component.getParent(), fullBounds, glassPane);

			int gw = ghidraImage.getWidth(null);
			int gh = ghidraImage.getHeight(null);
			double smallest =
				fullBounds.width > fullBounds.height ? fullBounds.height : fullBounds.width;
			smallest -= 10; // padding

			double scale = smallest / gw;
			int w = (int) (gw * scale);
			int h = (int) (gh * scale);

			double cx = fullBounds.getCenterX();
			double cy = fullBounds.getCenterY();
			int offsetX = (int) (cx - (w >> 1));
			int offsetY = (int) (cy - (h >> 1));

			g2d.setClip(fullBounds);
			g2d.drawImage(ghidraImage, offsetX, offsetY, w, h, null);

			g2d.setComposite(originaComposite);
		}
	}

}
