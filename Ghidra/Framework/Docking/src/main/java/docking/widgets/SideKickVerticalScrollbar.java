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
package docking.widgets;

import java.awt.*;
import java.awt.event.AdjustmentListener;

import javax.swing.*;
import javax.swing.plaf.ScrollBarUI;

/**
 * A Vertical JScrollbar that displays an additional component to its right and sized such that
 * its top is just below the top button of the scrollbar and its bottom is just above the bottom
 * button of the scrollbar.  Useful for providing an "overview" panel.
 *
 */
public class SideKickVerticalScrollbar extends JScrollBar {
	private JScrollBar delegate;
	private final JViewport viewport;

	public SideKickVerticalScrollbar(Component sideKick, JViewport viewport) {
		this.viewport = viewport;
		this.delegate = new MyScrollBar();
		setLayout(new BorderLayout());
		add(delegate, BorderLayout.WEST);
		JPanel panel = new JPanel(new SideKickLayout());
		panel.add(sideKick);
		add(panel, BorderLayout.EAST);
	}

	class MyScrollBar extends JScrollBar {
		@Override
		public int getUnitIncrement(int direction) {
			if (viewport != null && (viewport.getView() instanceof Scrollable)) {
				Scrollable view = (Scrollable) (viewport.getView());
				Rectangle vr = viewport.getViewRect();
				return view.getScrollableUnitIncrement(vr, getOrientation(), direction);
			}
			return super.getUnitIncrement(direction);
		}

		@Override
		public int getBlockIncrement(int direction) {
			if (viewport == null) {
				return delegate.getBlockIncrement(direction);
			}
			else if (viewport.getView() instanceof Scrollable) {
				Scrollable view = (Scrollable) (viewport.getView());
				Rectangle vr = viewport.getViewRect();
				return view.getScrollableBlockIncrement(vr, getOrientation(), direction);
			}
			return super.getBlockIncrement(direction);
		}
	}

	@Override
	public void addAdjustmentListener(AdjustmentListener l) {
		delegate.addAdjustmentListener(l);
	}

	/*	 
	 	Note: Using this method causes some screen reader hardware to fail.   We believe that this
	 	      method was overridden to follow the pattern of all the other methods of this class.
	 	      Apparently, the delegate's accessible context does not correctly return a parent,
	 	      presumably because this class's parent is not the parent of the delegate.
	 	      Not overriding this method seems to produce the correct result.
	 
		@Override
		public AccessibleContext getAccessibleContext() {
			return delegate.getAccessibleContext();
		}
	*/

	@Override
	public AdjustmentListener[] getAdjustmentListeners() {
		return delegate.getAdjustmentListeners();
	}

	@Override
	public int getBlockIncrement() {
		return delegate.getBlockIncrement();
	}

	@Override
	public int getBlockIncrement(int direction) {
		return delegate.getBlockIncrement(direction);
	}

	@Override
	public int getMaximum() {
		return delegate.getMaximum();
	}

	@Override
	public Dimension getMaximumSize() {
		return delegate.getMaximumSize();
	}

	@Override
	public int getMinimum() {
		return delegate.getMinimum();
	}

	@Override
	public Dimension getMinimumSize() {
		return delegate.getMinimumSize();
	}

	@Override
	public BoundedRangeModel getModel() {
		return delegate.getModel();
	}

	@Override
	public int getOrientation() {
		return delegate.getOrientation();
	}

	@Override
	public ScrollBarUI getUI() {
		return delegate.getUI();
	}

	@Override
	public String getUIClassID() {
		return delegate.getUIClassID();
	}

	@Override
	public int getUnitIncrement() {
		return delegate.getUnitIncrement();
	}

	@Override
	public int getUnitIncrement(int direction) {
		return delegate.getUnitIncrement(direction);
	}

	@Override
	public int getValue() {
		return delegate.getValue();
	}

	@Override
	public boolean getValueIsAdjusting() {
		return delegate.getValueIsAdjusting();
	}

	@Override
	public int getVisibleAmount() {
		return delegate.getVisibleAmount();
	}

	@Override
	public void removeAdjustmentListener(AdjustmentListener l) {
		delegate.removeAdjustmentListener(l);
	}

	@Override
	public void setBlockIncrement(int blockIncrement) {
		delegate.setBlockIncrement(blockIncrement);
	}

	@Override
	public void setEnabled(boolean x) {
		delegate.setEnabled(x);
	}

	@Override
	public void setMaximum(int maximum) {
		delegate.setMaximum(maximum);
	}

	@Override
	public void setMaximumSize(Dimension maximumSize) {
		delegate.setMaximumSize(maximumSize);
	}

	@Override
	public void setMinimum(int minimum) {
		delegate.setMinimum(minimum);
	}

	@Override
	public void setMinimumSize(Dimension minimumSize) {
		delegate.setMinimumSize(minimumSize);
	}

	@Override
	public void setModel(BoundedRangeModel newModel) {
		delegate.setModel(newModel);
	}

	@Override
	public void setOrientation(int orientation) {
		delegate.setOrientation(orientation);
	}

	@Override
	public void setUI(ScrollBarUI ui) {
		delegate.setUI(ui);
	}

	@Override
	public void setUnitIncrement(int unitIncrement) {
		delegate.setUnitIncrement(unitIncrement);
	}

	@Override
	public void setValue(int value) {
		delegate.setValue(value);
	}

	@Override
	public void setValueIsAdjusting(boolean b) {
		delegate.setValueIsAdjusting(b);
	}

	@Override
	public void setValues(int newValue, int newExtent, int newMin, int newMax) {
		delegate.setValues(newValue, newExtent, newMin, newMax);
	}

	@Override
	public void setVisibleAmount(int extent) {
		delegate.setVisibleAmount(extent);
	}

	@Override
	public void updateUI() {
		if (delegate == null) {
			return;
		}
		delegate.updateUI();
	}

	class SideKickLayout implements LayoutManager {

		@Override
		public void addLayoutComponent(String name, Component comp) {
			// stub
		}

		@Override
		public void removeLayoutComponent(Component comp) {
			// stub
		}

		@Override
		public void layoutContainer(Container parent) {
			Dimension size = parent.getSize();
			Component sideKick = parent.getComponent(0);
			int height = size.height;
			int y = 0;
			Component[] components = delegate.getComponents();
			if (components.length == 2) {
				Component topButton = delegate.getComponent(1);
				Component bottomButton = delegate.getComponent(0);
				Rectangle topBounds = topButton.getBounds();
				Rectangle bottomBounds = bottomButton.getBounds();
				height = size.height - topBounds.height - bottomBounds.height;
				y = topBounds.y + topBounds.height;
			}
			else {
				Dimension preferredSize = delegate.getPreferredSize();
				y = preferredSize.width / 2;
				height -= preferredSize.width;
			}

			sideKick.setBounds(0, y, size.width, height);
		}

		@Override
		public Dimension minimumLayoutSize(Container parent) {
			return new Dimension(0, 0);
		}

		@Override
		public Dimension preferredLayoutSize(Container parent) {
			return parent.getComponent(0).getPreferredSize();
		}

	}
}
