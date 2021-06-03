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
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;

import javax.swing.JPanel;
import javax.swing.Scrollable;

/**
 * A panel that is scrollable and uses a VariableHeightLayoutManager that
 * deals with components of varying heights.
 *
 */
public class VariableHeightPanel extends JPanel implements Scrollable {
	private boolean pack;
	private int hGap;
	private int vGap;

	/**
	 * Finds the highest-level Component parent for the given Component. This
	 * method will stop searching when it finds a Window parent.
	 * 
	 * @param component
	 *            The child for which to locate the highest-level parent.
	 * @return The highest-level parent of component.
	 */
	private static Component getRootComponent(Component component) {
		if (component instanceof Window) {
			return component;
		}
		Container parent = component.getParent();
		if (parent == null) {
			return component;
		}
		return getRootComponent(parent);
	}

	/**
	 * 
	 * Construct a new VariableHeigthPanel.
	 * @param pack true means to fit as many components on a row, not worrying about lining up 
	 *        columns; false means to fit as many components on a row, and line up the columns 
	 *        as if in a grid
	 * @param hgap horizontal gap between components
	 * @param vgap vertical gap between components
	 */
	public VariableHeightPanel(final boolean pack, int hgap, int vgap) {
		this.pack = pack;
		this.hGap = hgap;
		this.vGap = vgap;

		setLayout(new VariableHeightLayoutManager(hGap, vGap, pack));

		// this is needed to know when our the layout model changes this panel's height, which
		// requires that we notify our containing parent of the change so that it will re-layout
		// it's children to deal with our new space
		addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				invalidate();
				getRootComponent(VariableHeightPanel.this).validate();
			}
		});
	}

	@Override
	public void setBounds(int x, int y, int width, int height) {
		super.setBounds(x, y, width, height);
	}

	@Override
	public void setBounds(Rectangle r) {
		super.setBounds(r);
	}

	/**
	 * This method is in place because the clients of this panel are not the ones that 
	 * construct this panel and thus cannot create the desired type of layout at construction time.
	 * <b>This method has no effect if this panel was constructed with <code>pack</code> set to
	 * false, which makes this panel use a grid style layout.</b>
	 *  
	 * @param singleLineLayout True signals to put all children on a single row; false will use
	 *        as many rows as are needed to layout all of the children.
	 */
	public void setUseSingleLineLayout(boolean singleLineLayout) {
		if (pack) {
			if (singleLineLayout) {
				setLayout(new SingleRowLayoutManager(hGap, vGap));
			}
			else {
				setLayout(new VariableHeightLayoutManager(hGap, vGap, pack));
			}
		}
	}

	/**
	 * Return the preferred size of the layout manager of this panel.
	 */
	public Dimension getPreferredLayoutSize() {
		return ((VariableHeightLayoutManager) getLayout()).getPreferredSize(this);
	}

	/**
	 * @see javax.swing.Scrollable#getScrollableTracksViewportHeight()
	 */
	@Override
	public boolean getScrollableTracksViewportHeight() {
		return false;
	}

	/**
	 * @see javax.swing.Scrollable#getScrollableTracksViewportWidth()
	 */
	@Override
	public boolean getScrollableTracksViewportWidth() {
		return true;
	}

	/**
	 * @see javax.swing.Scrollable#getPreferredScrollableViewportSize()
	 */
	@Override
	public Dimension getPreferredScrollableViewportSize() {
		return getPreferredSize();
	}

	/**
	 * @see javax.swing.Scrollable#getScrollableBlockIncrement(java.awt.Rectangle, int, int)
	 */
	@Override
	public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
		return visibleRect.height;
	}

	/**
	 * @see javax.swing.Scrollable#getScrollableUnitIncrement(java.awt.Rectangle, int, int)
	 */
	@Override
	public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
		return 20;
	}
}

//==================================================================================================
//  Layout Managers
//==================================================================================================

class VariableHeightLayoutManager implements LayoutManager {
	final int hgap;
	final int vgap;
	boolean grid;

	VariableHeightLayoutManager(int hgap, int vgap, boolean pack) {
		this.hgap = hgap;
		this.vgap = vgap;
		this.grid = !pack; // packing squishes components; whereas a grid maintains equals sizing
	}

	@Override
	public Dimension minimumLayoutSize(Container parent) {
		return preferredLayoutSize(parent);
	}

	@Override
	public void removeLayoutComponent(Component comp) {
	}

	@Override
	public void addLayoutComponent(String name, Component comp) {
	}

	// the preferred layout size is constrained by the width of the parent, but has a height that
	// grows as children are placed into new rows
	@Override
	public Dimension preferredLayoutSize(Container parent) {
		if (parent.getParent() != null) {
			return getPreferredSize(parent, parent.getParent().getSize().width);
		}
		return getPreferredSize(parent, 0);
	}

	// this preferred size returns a height which is that of the tallest component and a 
	// width that is the width of all the components plus insets
	Dimension getPreferredSize(Container parent) {
		Insets insets = parent.getInsets();
		int n = parent.getComponentCount();

		if (n <= 0) {
			return new Dimension(insets.left + insets.right, insets.top + insets.bottom);
		}

		int width = 0;
		int height = 0;
		for (int i = 0; i < n; i++) {
			Component c = parent.getComponent(i);
			Dimension d = c.getPreferredSize();
			height = Math.max(height, d.height);
			width += d.width;
		}

		return new Dimension(width + insets.left + insets.right,
			height + insets.top + insets.bottom);
	}

	// This preferred size returns Dimension based upon the rows and columns of components that
	// are derived from placing as many components on a row that will fit within the given
	// max width.  So, the final height is the height of the tallest component contained in 
	// 'parent' plus insets, multiplied by the number of rows. 
	private Dimension getPreferredSize(Container parent, int maxWidth) {

		if (maxWidth == 0) {
			return getPreferredSize(parent);
		}
		Insets insets = parent.getInsets();
		int n = parent.getComponentCount();

		if (n <= 0) {
			return new Dimension(insets.left + insets.right, insets.top + insets.bottom);
		}

		int horizontalInsets = insets.left + insets.right;
		int verticalInsets = insets.top + insets.bottom;

		Dimension standardSize = computeStandardComponentSize(parent);
		Component c = parent.getComponent(0);
		Dimension preferredSize = getPreferredDimensionForComponent(c, standardSize);

		int rowWidth = preferredSize.width;
		int rowHeight = getStandardComponentHeight(parent);
		int height = rowHeight;
		int availableWidth = maxWidth - horizontalInsets;

		for (int i = 1; i < n; i++) {
			c = parent.getComponent(i);
			preferredSize = getPreferredDimensionForComponent(c, standardSize);

			// if we still have room on this line
			if (rowWidth + hgap + preferredSize.width <= availableWidth) {
				rowWidth += preferredSize.width + hgap;
			}
			else {
				height += rowHeight + vgap;
				rowWidth = preferredSize.width;
			}
		}

		return new Dimension(availableWidth + horizontalInsets, height + verticalInsets);
	}

	@Override
	public void layoutContainer(Container parent) {
		Insets insets = parent.getInsets();
		Dimension parentSize = parent.getSize();

		int useableWidth = parentSize.width - insets.left - insets.right;
		int n = parent.getComponentCount();
		int x = insets.left;
		int y = insets.top;
		if (n == 0) {
			return;
		}

		Component c = parent.getComponent(0);
		Dimension standardSize = computeStandardComponentSize(parent);
		Dimension preferredSize = getPreferredDimensionForComponent(c, standardSize);

		c.setBounds(x, y, preferredSize.width, preferredSize.height);
		x += preferredSize.width + hgap;

		int rowHeight = getStandardComponentHeight(parent);
		int rowWidth = preferredSize.width;

		for (int i = 1; i < n; i++) {
			c = parent.getComponent(i);
			preferredSize = getPreferredDimensionForComponent(c, standardSize);

			// if the current component fits width-wise on the remaining space
			if (rowWidth + hgap + preferredSize.width <= useableWidth) {
				rowWidth += preferredSize.width + hgap;
				c.setBounds(x, y + (rowHeight - preferredSize.height) / 2, preferredSize.width,
					preferredSize.height);
				x += preferredSize.width + hgap;
			}
			else {
				x = insets.left;
				y += rowHeight + vgap;
				rowWidth = preferredSize.width;
				c.setBounds(x, y + (rowHeight - preferredSize.height) / 2, preferredSize.width,
					preferredSize.height);
				x += preferredSize.width + hgap;
			}
		}
	}

	// isolates the preferred size, which varies depending upon the type of layout we are mocking
	private Dimension getPreferredDimensionForComponent(Component component,
			Dimension standardSize) {

		Dimension preferredDimension = component.getPreferredSize();

		// a grid layout uses the standard width
		if (grid) {
			preferredDimension.width = standardSize.width;
		}

		return preferredDimension;
	}

	// gets the max height of all components contained in parent
	int getStandardComponentHeight(Container parent) {
		int n = parent.getComponentCount();
		int compHeight = 0;

		for (int i = 0; i < n; i++) {
			Component c = parent.getComponent(i);
			Dimension d = c.getPreferredSize();
			compHeight = Math.max(compHeight, d.height);
		}
		return compHeight;
	}

	// this is the biggest height and width of all the components contained in parent
	Dimension computeStandardComponentSize(Container parent) {
		int n = parent.getComponentCount();
		int compWidth = 0;
		int compHeight = 0;

		for (int i = 0; i < n; i++) {
			Component c = parent.getComponent(i);
			Dimension d = c.getPreferredSize();
			compWidth = Math.max(compWidth, d.width);
			compHeight = Math.max(compHeight, d.height);
		}
		return new Dimension(compWidth, compHeight);
	}
}

class SingleRowLayoutManager extends VariableHeightLayoutManager {

	SingleRowLayoutManager(int hgap, int vgap) {
		super(hgap, vgap, true);
	}

	@Override
	public Dimension preferredLayoutSize(Container parent) {
		return getPreferredSize(parent);
	}
}
