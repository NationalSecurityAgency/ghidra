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

import java.awt.Graphics;
import java.time.Duration;
import java.util.Objects;

import javax.swing.JComponent;

import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.TimingTargetAdapter;
import org.jdesktop.animation.timing.interpolation.PropertySetter;

import ghidra.util.Msg;
import ghidra.util.bean.GGlassPane;
import ghidra.util.bean.GGlassPanePainter;
import utility.function.Callback;
import utility.function.Dummy;

/**
 * A class that does basic setup work for creating an {@link Animator}.  The animator will run a 
 * timer in a background thread, calling the client periodically until the animation progress is
 * finished.  The actual visual animation is handled by the client's {@link AnimationPainter}.
 * This class is provided for convenience.  Clients can create their own {@link Animator} as needed. 
 * <P>
 * A {@link #setPainter(AnimationPainter) painter} must be supplied before calling {@link #start()}.
 * A simple example usage: 
 * <PRE>
 *  GTable table = ...;
 *  AnimationPainter painter = new AnimationPainter() {
 *  	public void paint(GGlassPane glassPane, Graphics graphics, double value) {
 *  		
 *  		// repaint some contents to the glass pane's graphics using the current value as to 
 *  		// know where we are in the progress of animating
 *  	}
 *  };
 *  AnimationRunner animation = new AnimationRunner(table);
 *  animation.setPainter(painter);
 *  animation.start();
 *  
 *  ...
 *  
 *  // code to stop animation, such as when a request for a new animation is received
 *  if (animation != null) {
 *  	animation.stop();
 *  }
 *  
 * </PRE>
 * <P>
 * Clients who wish to perform more configuration can call {@link #createAnimator()} to perform the
 * basic setup, calling {@link #start()} when finished with any follow-up configuration.
 * <P>
 * See {@link Animator} for details on the animation process.
 */
public class AnimationRunner {

	private JComponent component;
	private GGlassPane glassPane;
	private Animator animator;
	private UserDefinedPainter painter;
	private boolean removePainterWhenFinished = true;
	private Callback doneCallback = Callback.dummy();

	private Duration duration = Duration.ofSeconds(1);
	private Double[] values = new Double[] { 0D, 1D };

	public AnimationRunner(JComponent component) {
		this.component = component;
	}

	/**
	 * Sets the painter required for the animator to work.
	 * @param animationPainter the painter.
	 */
	public void setPainter(AnimationPainter animationPainter) {
		this.painter = new UserDefinedPainter(animationPainter);
	}

	/**
	 * Sets the values passed to the animator created by this class.  These values will be split 
	 * into a range of values, broken up by the duration of the animator. The default values are 0 
	 * and 1.   
	 * <P>
	 * See {@link PropertySetter#createAnimator(int, Object, String, Object...)}.
	 * @param values the values
	 */
	public void setValues(Double... values) {
		if (values == null || values.length == 0) {
			throw new IllegalArgumentException("'values' cannot be null or empty");
		}
		this.values = values;
	}

	/**
	 * Signals to remove the painter from the glass pane when the animation is finished.  Clients
	 * can specify {@code false} which will allow the painting to continue after the animation has
	 * finished.
	 * @param b true to remove the painter.  The default value is true.
	 */
	public void setRemovePainterWhenFinished(boolean b) {
		this.removePainterWhenFinished = b;
	}

	/**
	 * Sets a callback to be called when the animation is finished.
	 * @param c the callback
	 */
	public void setDoneCallback(Callback c) {
		this.doneCallback = Dummy.ifNull(c);
	}

	/**
	 * Sets the animation duration.  The default is 1 second.
	 * @param duration the duration
	 */
	public void setDuration(Duration duration) {
		this.duration = Objects.requireNonNull(duration);
	}

	/**
	 * This is a method used by the animator.  Clients should not call this method.
	 * @param value the current value created by the animator
	 */
	public void setCurrentValue(Double value) {
		painter.setValue(value);
		glassPane.repaint();
	}

	/**
	 * Creates the animator used to perform animation.  Clients will call {@link Animator#start()}
	 * to begin animation.  Many attributes of the animator can be configured before starting. 
	 * @return the animator
	 * @throws IllegalStateException if require values have not been set on this class, such as 
	 * {@link #setValues(Double...)} or {@link #setPainter(AnimationPainter)}.
	 */
	public Animator createAnimator() {

		if (animator != null) {
			return animator;
		}

		glassPane = AnimationUtils.getGlassPane(component);
		if (glassPane == null) {
			Msg.debug(AnimationUtils.class,
				"Cannot animate without a " + GGlassPane.class.getName() + " installed");
			throw new IllegalStateException("Unable to find Glass Pane");
		}

		if (painter == null) {
			throw new IllegalStateException("A painter must be supplied");
		}

		setCurrentValue(values[0]); // set initial value

		int aniationDuration = (int) duration.toMillis();
		if (!AnimationUtils.isAnimationEnabled()) {
			aniationDuration = 0; // do not animate
		}

		animator = PropertySetter.createAnimator(aniationDuration, this, "currentValue", values);
		animator.setAcceleration(0.2f);
		animator.setDeceleration(0.8f);
		animator.addTarget(new TimingTargetAdapter() {
			@Override
			public void end() {
				done();
			}
		});

		return animator;
	}

	/**
	 * Starts the animation process, creating the animator as needed.  This method can be called
	 * repeatedly without calling stop first.
	 */
	public void start() {

		if (painter == null) {
			throw new IllegalStateException("A painter must be supplied");
		}

		if (animator != null) {
			if (animator.isRunning()) {
				animator.stop();
			}
		}
		else {
			animator = createAnimator();
		}

		glassPane.addPainter(painter);
		animator.start();
	}

	/**
	 * Stops all animation and removes the painter from the glass pane. {@link #start()} can be 
	 * called again after calling this method.
	 */
	public void stop() {
		if (animator != null) {
			animator.stop();
		}

		glassPane.removePainter(painter);
	}

	private void done() {
		setCurrentValue(values[values.length - 1]);

		if (removePainterWhenFinished) {
			glassPane.removePainter(painter);
		}
		else {
			glassPane.repaint();
		}

		doneCallback.call();
	}

	/**
	 * A painter that will call the user-supplied painter with the current value.
	 */
	private class UserDefinedPainter implements GGlassPanePainter {

		private AnimationPainter userPainter;
		private double value;

		UserDefinedPainter(AnimationPainter userPainter) {
			this.userPainter = userPainter;
		}

		void setValue(double value) {
			this.value = value;
		}

		@Override
		public void paint(GGlassPane gp, Graphics graphics) {
			userPainter.paint(gp, graphics, value);
		}
	}
}
