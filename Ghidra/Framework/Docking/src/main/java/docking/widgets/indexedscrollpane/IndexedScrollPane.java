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
package docking.widgets.indexedscrollpane;

import java.awt.*;
import java.math.BigInteger;

import javax.swing.*;

import docking.widgets.SideKickVerticalScrollbar;

public class IndexedScrollPane extends JPanel implements IndexScrollListener {
	private JScrollPane scrollPane;
	private ViewToIndexMapper indexMapper;
	private JViewport viewport;
	private Dimension visibleSize = new Dimension(0, 0);
	private int verticalOffset;
	private boolean programaticallyAdjustingScrollbar;
	private IndexedScrollable scrollable;
	private final JComponent comp;
	private ScrollView viewComponent;
	private boolean useViewSizeAsPreferredSize;
	private boolean neverScroll;

	public IndexedScrollPane(JComponent comp) {
		this.comp = comp;
		if (!(comp instanceof IndexedScrollable)) {
			throw new IllegalArgumentException(
				"component must implement IndexedScrollable interface.");
		}

		scrollable = (IndexedScrollable) comp;
		scrollable.addIndexScrollListener(this);
		setLayout(new BorderLayout());
		viewComponent = new ScrollView(comp);
		scrollPane = new JScrollPane(viewComponent);

		add(scrollPane);
		viewport = scrollPane.getViewport();
		viewport.setBackground(comp.getBackground());
		viewport.addChangeListener(e -> viewportStateChanged());
		viewport.setScrollMode(JViewport.SIMPLE_SCROLL_MODE);
		this.indexMapper = createIndexMapper();
	}

	/**
	 * Sets this scroll pane to never show scroll bars.  This is useful when you want a container
	 * whose view is always as big as the component in this scroll pane.
	 */
	public void setNeverScroll(boolean b) {
		neverScroll = true;
		scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER);
		scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		useViewSizeAsPreferredSize = b;
	}

	private ViewToIndexMapper createIndexMapper() {
		if (neverScroll) {
			return new PreMappedViewToIndexMapper(scrollable);
		}

		BigInteger numIndexes = scrollable.getIndexCount();
		if (numIndexes.equals(BigInteger.ZERO)) {
			return new UniformViewToIndexMapper(scrollable);
		}
		if (scrollable.isUniformIndex()) {
			int layoutHeight = scrollable.getHeight(BigInteger.ZERO);
			BigInteger totalScrollHeight = numIndexes.multiply(BigInteger.valueOf(layoutHeight));
			if (totalScrollHeight.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) < 0) {
				return new UniformViewToIndexMapper(scrollable);
			}
		}
		if (numIndexes.compareTo(BigInteger.valueOf(1000)) < 0) {
			return new PreMappedViewToIndexMapper(scrollable);
		}
		return new DefaultViewToIndexMapper(scrollable, viewport.getExtentSize().height);

	}

	public Dimension getViewSize() {
		return new Dimension(comp.getPreferredSize().width, indexMapper.getViewHeight());
	}

	public void viewportStateChanged() {
		Dimension extentSize = viewport.getExtentSize();
		if (!extentSize.equals(visibleSize)) {
			visibleSize = new Dimension(extentSize);
			indexMapper.setVisibleViewHeight(extentSize.height);
			comp.invalidate();
			repaint();
		}
		Point viewPosition = viewport.getViewPosition();
		if (verticalOffset != viewPosition.y) {
			verticalOffset = viewPosition.y;
			comp.setLocation(0, verticalOffset);
			if (!programaticallyAdjustingScrollbar) {
				scrollable.showIndex(indexMapper.getIndex(verticalOffset),
					indexMapper.getVerticalOffset(verticalOffset));
			}
		}
	}

	@Override
	public void indexRangeChanged(BigInteger startIndex, BigInteger endIndex, int yStart,
			int yEnd) {
		programaticallyAdjustingScrollbar = true;
		try {
			int scrollValue = indexMapper.getScrollValue(startIndex, endIndex, yStart, yEnd);
			Point p = viewport.getViewPosition();
			if (p.y != scrollValue) {
				viewport.setViewPosition(new Point(p.x, scrollValue));
			}
		}
		finally {
			programaticallyAdjustingScrollbar = false;
		}
	}

	@Override
	public void indexModelChanged() {
		indexMapper = createIndexMapper();
		viewport.doLayout();
	}

	@Override
	public void indexModelDataChanged(BigInteger start, BigInteger end) {
		indexMapper.indexModelDataChanged(start, end);
		comp.invalidate();
		viewport.doLayout();
	}

	class ScrollViewLayout implements LayoutManager {

		@Override
		public void addLayoutComponent(String name, Component comp) {
		}

		@Override
		public void layoutContainer(Container parent) {
			comp.setBounds(0, verticalOffset, parent.getSize().width, visibleSize.height);
		}

		@Override
		public Dimension minimumLayoutSize(Container parent) {
			return preferredLayoutSize(parent);
		}

		@Override
		public Dimension preferredLayoutSize(Container parent) {
			Dimension compPreferredSize = comp.getPreferredSize();
			int height = Math.max(indexMapper.getViewHeight(), visibleSize.height);
			int viewWidth = compPreferredSize.width;
			return new Dimension(viewWidth, height);
		}

		@Override
		public void removeLayoutComponent(Component comp) {
		}

	}

	class ScrollView extends JPanel implements Scrollable {

		ScrollView(JComponent component) {
			setLayout(new ScrollViewLayout());
			add(component);
		}

		@Override
		public Dimension getPreferredScrollableViewportSize() {
			int preferredHeight = useViewSizeAsPreferredSize ? indexMapper.getViewHeight() : 500;
			int viewWidth = comp.getPreferredSize().width;
			return new Dimension(viewWidth, preferredHeight);
		}

		@Override
		public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation,
				int direction) {
			if (orientation == SwingConstants.HORIZONTAL) {
				return 10;
			}
			scrollPage(direction);
			return 0;
		}

		@Override
		public boolean getScrollableTracksViewportHeight() {
			return false;
		}

		@Override
		public void setSize(Dimension d) {
			super.setSize(d);
		}

		@Override
		protected void paintComponent(Graphics g) {
		}

		@Override
		public boolean getScrollableTracksViewportWidth() {
			int prefWidth = comp.getPreferredSize().width;
			int scrollPaneWidth = getScrollPaneWidth();
			return scrollPaneWidth > prefWidth;
		}

		private int getScrollPaneWidth() {
			Container myParent = getParent();
			if (myParent == null) {
				return 0;
			}
			Container grandParent = myParent.getParent();
			if (grandParent == null) {
				return 0;
			}
			return grandParent.getSize().width;
		}

		@Override
		public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation,
				int direction) {

			if (orientation == SwingConstants.HORIZONTAL) {
				return 10;
			}
			scrollLine(direction);
			return 0;
		}

		private void scrollPage(final int direction) {
			SwingUtilities.invokeLater(() -> {
				if (direction < 0) {
					scrollable.scrollPageUp();
				}
				else {
					scrollable.scrollPageDown();
				}
			});
		}

		private void scrollLine(final int direction) {
			SwingUtilities.invokeLater(() -> {
				if (direction < 0) {
					scrollable.scrollLineUp();
				}
				else {
					scrollable.scrollLineDown();
				}
			});
		}

	}

	public JScrollBar getHorizontalScrollBar() {
		return scrollPane.getHorizontalScrollBar();
	}

	public void setColumnHeader(JViewport header) {
		scrollPane.setColumnHeader(header);
	}

	public void setColumnHeaderComp(JComponent comp) {
		scrollPane.setColumnHeaderView(comp);

		// SWING WORK AROUND - setting the header panel on a scrollpane that is horizontally
		// scrolled does not initially scroll the header to match the main view.  Setting the
		// horizontal position to 0 and back to where it was, resynchronizes the header with the
		// view.
		Point viewPosition = viewport.getViewPosition();
		viewport.setViewPosition(new Point(0, viewPosition.y));
		viewport.setViewPosition(viewPosition);

	}

	public JViewport getColumnHeader() {
		return scrollPane.getColumnHeader();
	}

	public JScrollBar getVerticalScrollBar() {
		return scrollPane.getVerticalScrollBar();
	}

	public Rectangle getViewportBorderBounds() {
		return scrollPane.getViewportBorderBounds();
	}

	public void setScrollbarSideKickComponent(JComponent component) {
		scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
		if (component == null) {
			scrollPane.setVerticalScrollBar(new JScrollBar());
		}
		else {
			scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
			scrollPane.setVerticalScrollBar(
				new SideKickVerticalScrollbar(component, scrollPane.getViewport()));
		}
	}

	/**
	 * Sets whether the scroll wheel triggers scrolling <b>when over the scroll pane</b> of this
	 * class.   When disabled, scrolling will still work when over the component inside of 
	 * this class, but not when over the scroll bar.
	 * 
	 * @param enabled true to enable
	 */
	public void setWheelScrollingEnabled(boolean enabled) {
		scrollPane.setWheelScrollingEnabled(enabled);
	}
}
