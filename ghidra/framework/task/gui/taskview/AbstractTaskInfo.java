/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.task.gui.taskview;

import ghidra.framework.task.GScheduledTask;
import ghidra.framework.task.GTaskGroup;
import ghidra.framework.task.gui.GProgressBar;

import java.awt.Color;
import java.awt.Container;

import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.interpolation.PropertySetter;

public abstract class AbstractTaskInfo implements Comparable<AbstractTaskInfo> {
	private final boolean useAnimation;
	private Animator backgroundAnimator;

	protected ScheduledTaskPanel component;
	protected GTaskGroup group;

	/**
	 * Constructor for both group infos and task infos
	 * @param group the GTaskGroup
	 * @param useAnimation if true, this info will create a component that performs an
	 * animation when shown.
	 */
	AbstractTaskInfo(GTaskGroup group, boolean useAnimation) {
		this.group = group;
		this.useAnimation = useAnimation;
	}

	protected abstract String getLabelText();

	public GTaskGroup getGroup() {
		return group;
	}

	@Override
	public int compareTo(AbstractTaskInfo o) {
		int result = getGroup().compareTo(o.getGroup());
		if (result == 0) {
			if (this instanceof GroupInfo) {
				return -1;
			}
			if (o instanceof GroupInfo) {
				return 1;
			}
			// they both must be TaskInfos
			GScheduledTask myTask = ((TaskInfo) this).getScheduledTask();
			GScheduledTask otherTask = ((TaskInfo) o).getScheduledTask();
			return myTask.compareTo(otherTask);
		}
		return result;
	}

	public ScheduledTaskPanel getComponent() {
		if (component == null) {
			component = new ScheduledTaskPanel(getLabelText(), getIndention());
			if (useAnimation) {
				Color startColor = Color.YELLOW;
				Color endColor = Color.white;
				backgroundAnimator =
					PropertySetter.createAnimator(4000, this, "Background", startColor, endColor);
				backgroundAnimator.start();
			}
		}
		return component;
	}

	/**
	 * sets the background of the component being managed by this info.  It is used by the animation 
	 * framework.
	 * @param c the color
	 */
	public void setBackground(Color c) {
		component.setBackground(c);
	}

	protected int getIndention() {
		return 0;
	}

	public GProgressBar setRunning() {
		getComponent().addProgressBar();
		if (backgroundAnimator != null) {
			backgroundAnimator.stop();
			component.setBackground(Color.WHITE);
			backgroundAnimator = null;
		}
		return getComponent().getProgressBar();
	}

	public void setScrollFraction(float fraction) {
		component.setHiddenViewAmount(fraction);
		component.invalidate();
		Container parent = component.getParent();
		if (parent != null) {
			Container grandParent = parent.getParent();
			if (grandParent != null) {
				grandParent.validate();
			}
		}
	}

}
