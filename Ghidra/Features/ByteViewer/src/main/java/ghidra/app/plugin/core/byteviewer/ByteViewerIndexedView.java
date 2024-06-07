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
package ghidra.app.plugin.core.byteviewer;

import java.awt.BorderLayout;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.indexedscrollpane.*;
import generic.theme.GColor;
import generic.theme.Gui;
import ghidra.app.plugin.core.format.DataFormatModel;

/**
 * Main ByteViewer component that is scrolled in a {@link IndexedScrollPane}. Similar to the view
 * component in a {@link JScrollPane}. This component manages two or more {@link FieldPanel} 
 * components. It always contains the "index" field panel which displays the addresses of the
 * values being displayed. Then it has one or more data FieldPanels; one for each format being
 * displayed (e.g., hex, octal, binary).
 * <P>
 * There is also header component that displays the name of each column and allows the user to
 * reorder and resize the views. This class uses an {@link InteractivePanelManager} to handle
 * the reordering and resizing of the views in coordination with the header component. It is the
 * client's responsibility to get the header component and install it into the IndexedScrollPane.
 */
class ByteViewerIndexedView extends JPanel implements IndexedScrollable, IndexScrollListener {
	private static final String HEADER_FONT_ID = "font.byteviewer.header";
	private FieldPanel indexPanel;
	private List<FieldPanel> allPanels = new ArrayList<>();
	private boolean processingIndexRangeChanged;
	private InteractivePanelManager panelManager;

	ByteViewerIndexedView(FieldPanel indexPanel) {
		super(new BorderLayout());
		this.indexPanel = indexPanel;
		allPanels.add(indexPanel);
		panelManager = new InteractivePanelManager();
		panelManager.setHeaderFont(Gui.getFont(HEADER_FONT_ID));

		indexPanel.addIndexScrollListener(this);

		panelManager.addComponent(ByteViewerComponentProvider.INDEX_COLUMN_NAME, indexPanel);
		JComponent mainPanel = panelManager.getMainPanel();
		add(mainPanel, BorderLayout.CENTER);
		mainPanel.setBackground(new GColor("color.bg.byteviewer"));

		addMouseWheelListener(e -> {
			// this lets us scroll the byte viewer when the user is not over any panel, but still
			// over the view
			Layout firstLayout = indexPanel.getLayoutModel().getLayout(BigInteger.ZERO);
			int layoutScrollHt = firstLayout != null //
					? firstLayout.getScrollableUnitIncrement(0, 1)
					: 0;

			double wheelRotation = e.getPreciseWheelRotation();
			int scrollAmount =
				(int) (wheelRotation * layoutScrollHt * FieldPanel.MOUSEWHEEL_LINES_TO_SCROLL);

			indexPanel.scrollView(scrollAmount);
			e.consume();
		});
	}

	void addView(String viewName, ByteViewerComponent c) {
		panelManager.addComponent(viewName, c);
		allPanels.add(c);
		c.addIndexScrollListener(this);
	}

	void removeView(ByteViewerComponent c) {
		panelManager.removeComponent(c);
		allPanels.remove(c);
		c.removeIndexScrollListener(this);
	}

	JComponent getColumnHeader() {
		return panelManager.getColumnHeader();
	}

	public List<String> getViewNamesInDisplayOrder() {
		List<String> viewNames = new ArrayList<>();
		List<JComponent> components = panelManager.getComponents();
		for (JComponent component : components) {
			if (component == indexPanel) {
				continue;
			}
			if (component instanceof ByteViewerComponent byteViewerComponent) {
				DataFormatModel model = byteViewerComponent.getDataModel();
				viewNames.add(model.getName());
			}
		}
		return viewNames;
	}

	void resetViewWidthToDefaults() {
		List<String> viewNames = getViewNamesInDisplayOrder();
		for (String viewName : viewNames) {
			panelManager.resetColumnWidthToPreferredWidth(viewName);
		}
	}

	void setIndexName(String indexName) {
		panelManager.setName(indexPanel, indexName);
	}

	int getViewWidth(String viewName) {
		return panelManager.getColumnWidth(viewName);
	}

	void setColumnWidth(String viewName, int width) {
		panelManager.setColumnWidth(viewName, width);
	}

	@Override
	public void indexRangeChanged(BigInteger startIndex, BigInteger endIndex, int yStart,
			int yEnd) {
		if (processingIndexRangeChanged) {
			return;
		}
		processingIndexRangeChanged = true;
		try {
			// need to sync up the view position of all views when any view is scrolled
			for (FieldPanel fieldPanel : allPanels) {
				fieldPanel.showIndex(startIndex, yStart);
			}
		}
		finally {
			processingIndexRangeChanged = false;
		}

	}

	@Override
	public void addIndexScrollListener(IndexScrollListener listener) {
		indexPanel.addIndexScrollListener(listener);
	}

	@Override
	public int getHeight(BigInteger index) {
		return indexPanel.getHeight(index);
	}

	@Override
	public BigInteger getIndexAfter(BigInteger index) {
		return indexPanel.getIndexAfter(index);
	}

	@Override
	public BigInteger getIndexBefore(BigInteger index) {
		return indexPanel.getIndexBefore(index);
	}

	@Override
	public BigInteger getIndexCount() {
		return indexPanel.getIndexCount();
	}

	@Override
	public boolean isUniformIndex() {
		return true;
	}

	@Override
	public void removeIndexScrollListener(IndexScrollListener listener) {
		indexPanel.removeIndexScrollListener(listener);
	}

	@Override
	public void scrollLineDown() {
		indexPanel.scrollLineDown();
	}

	@Override
	public void scrollLineUp() {
		indexPanel.scrollLineUp();
	}

	@Override
	public void scrollPageDown() {
		indexPanel.scrollPageDown();
	}

	@Override
	public void scrollPageUp() {
		indexPanel.scrollPageUp();
	}

	@Override
	public void showIndex(BigInteger index, int verticalOffset) {
		indexPanel.showIndex(index, verticalOffset);
	}

	@Override
	public void indexModelChanged() {
		// handled by indexPanel
	}

	@Override
	public void indexModelDataChanged(BigInteger start, BigInteger end) {
		// handled by indexPanel
	}

	@Override
	public void mouseWheelMoved(double preciseWheelRotation, boolean isHorizontal) {
		indexPanel.mouseWheelMoved(preciseWheelRotation, isHorizontal);
	}

}
