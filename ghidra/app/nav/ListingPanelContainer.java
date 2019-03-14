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
package ghidra.app.nav;

import ghidra.app.util.viewer.util.TitledPanel;

import java.awt.BorderLayout;
import java.awt.Color;

import javax.swing.*;

public class ListingPanelContainer extends JPanel {

	private JSplitPane splitPane;
	private TitledPanel leftTitlePanel;
	private TitledPanel rightTitlePanelPanel;
	private JComponent leftListingPanel;
	private JComponent northComponent;

	public ListingPanelContainer(JComponent leftListingPanel, boolean isConnected) {
		this.leftListingPanel = leftListingPanel;
		setLayout(new BorderLayout());
		add(leftListingPanel);
		setConnnected( isConnected );
	}

	public ListingPanelContainer(JComponent leftListingPanel, JComponent rightListingPanel,
			String leftTitle, String rightTitle) {

		this(leftListingPanel, false);

		setOtherPanel(rightListingPanel, leftTitle, rightTitle);
	}

	public void setConnnected( boolean isConnected ) {
		if ( !isConnected ) {
			setBorder( BorderFactory.createLineBorder( Color.ORANGE, 2 ) );
		}
		else {
			setBorder( BorderFactory.createEmptyBorder() );
		}
	}

	public void setOtherPanel(JComponent rightListingPanel, String leftTitle, String rightTitle) {
		removeAll();
		leftTitlePanel = new TitledPanel(leftTitle, leftListingPanel, 20);
		rightTitlePanelPanel = new TitledPanel(rightTitle, rightListingPanel, 20);
		splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftTitlePanel, rightTitlePanelPanel);
		splitPane.setDividerLocation(0.5);
		splitPane.setResizeWeight(0.5);
		add(splitPane, BorderLayout.CENTER);
		if (northComponent != null) {
			add(northComponent, BorderLayout.NORTH);
		}
	}

	public void updateTitle(String newTitle) {
		if (leftTitlePanel != null) {
			leftTitlePanel.setName(newTitle);
		}
	}

	public void clearOtherPanel() {
		removeAll();
		add(leftListingPanel);
		if (northComponent != null) {
			add(northComponent, BorderLayout.NORTH);
		}
	}

	public void setOrientation(boolean isSideBySide) {
		splitPane.setOrientation(isSideBySide ? JSplitPane.HORIZONTAL_SPLIT : JSplitPane.VERTICAL_SPLIT);
		splitPane.setDividerLocation(0.5);
	}

	public void setNorthPanel(JComponent comp) {
		if (northComponent != null) {
			remove(northComponent);
		}
		northComponent = comp;
		if (northComponent != null) {
			add(northComponent, BorderLayout.NORTH);
		}
	}
}
