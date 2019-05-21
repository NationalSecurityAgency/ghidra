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
package ghidra.framework.task.gui.taskview;

import java.awt.*;

import javax.swing.*;

import docking.widgets.label.GDLabel;
import ghidra.framework.task.gui.GProgressBar;

public class ScheduledTaskPanel extends JPanel {
	private int scrollOffset = 0;
	private int indention = 0;
	private GProgressBar progressBar;
	private JLabel label;
	private ScheduledElementLayout layout;

	public ScheduledTaskPanel(String labelText, int indention) {
		super();
		this.indention = indention;

		setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));

		layout = new ScheduledElementLayout();
		setLayout(layout);
		label = new GDLabel(labelText);
		setBackground(Color.WHITE);
		add(label);
	}

	void addProgressBar() {
		progressBar = new GProgressBar(null, true, true, false, 12);
		progressBar.setBackgroundColor(Color.WHITE);
		add(progressBar);
		layout.clearPreferredSize();
		invalidate();
	}

	public GProgressBar getProgressBar() {
		return progressBar;
	}

	/**
	 * Sets the amount of the view that is hidden, i.e., "scrolled off".  The animation framework
	 * will cause this method to be called with a sequence of values from 0 to 1 which will be
	 * used to scroll the component off the view.
	 * @param fraction the amount of the component to hide.
	 */
	public void setHiddenViewAmount(float fraction) {
		Container parent = getParent();
		if (parent == null) {
			scrollOffset = 0;
		}
		this.scrollOffset = (int) (layout.getNormalPreferredSize(parent).height * fraction);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	// This layout handles the scrolling based on the scrollOffset as set by the setHiddenViewAmount()
	// It also optionally shows the scrollbar for the task or group.
	private class ScheduledElementLayout implements LayoutManager {
		private Dimension normalPreferredSize;

		@Override
		public void addLayoutComponent(String name, Component comp) {
			normalPreferredSize = null;
		}

		public void clearPreferredSize() {
			normalPreferredSize = null;
		}

		@Override
		public void removeLayoutComponent(Component comp) {
			normalPreferredSize = null;
		}

		@Override
		public Dimension preferredLayoutSize(Container parent) {
			Dimension d = getNormalPreferredSize(parent);
			if (scrollOffset == 0) {
				return d;
			}
			return new Dimension(d.width, d.height - scrollOffset);
		}

		private Dimension getNormalPreferredSize(Container parent) {
			if (normalPreferredSize == null) {
				Insets insets = parent.getInsets();
				int height = insets.top + insets.bottom + label.getPreferredSize().height;
				if (progressBar != null) {
					height += progressBar.getPreferredSize().height;
				}
				normalPreferredSize = new Dimension(100, height);
			}
			return normalPreferredSize;
		}

		@Override
		public Dimension minimumLayoutSize(Container parent) {
			return getPreferredSize();
		}

		@Override
		public void layoutContainer(Container parent) {
			Insets insets = parent.getInsets();
			Dimension size = parent.getSize();
			int width = size.width - insets.left - insets.right - indention;
			int x = insets.left + indention;
			int y = insets.top - scrollOffset;
			int labelHeight = label.getPreferredSize().height;
			label.setBounds(x, y, width, labelHeight);
			y += labelHeight;

			if (progressBar != null) {
				progressBar.setBounds(x, y, width, progressBar.getPreferredSize().height);
			}
		}

	}

}
