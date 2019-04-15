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
package ghidra.app.plugin.core.datamgr;

import java.awt.*;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.widgets.label.GDHtmlLabel;
import ghidra.app.util.ToolTipUtils;
import ghidra.app.util.html.HTMLDataTypeRepresentation;
import ghidra.program.model.data.DataType;
import ghidra.util.HTMLUtilities;

/**
 * Panel that displays two data types side by side.
 */
class DataTypeComparePanel extends JPanel {

	private JLabel dtLabel1;
	private JLabel dtLabel2;
	private JPanel leftPanel;
	private JPanel rightPanel;
	private JLabel leftPanelLabel;
	private JLabel rightPanelLabel;
	private String clientName;
	private String sourceName;

	/**
	 * Creates a panel for viewing two data types side by side.
	 * @param dataType1 the first data type to display.
	 * @param dataType2 the second data type to display.
	 * @param one_to_two true if this panel should display an arrow from data type 1 to data type 2.
	 * 		false if the should be from 2 to 1.
	 */
	DataTypeComparePanel(String clientName, String sourceName) {
		super(new GridLayout(0, 2));
		this.clientName = clientName;
		this.sourceName = sourceName;
		init();
	}

	private void init() {
		setPreferredSize(new Dimension(500, 200));
		leftPanel = new JPanel(new BorderLayout());
		rightPanel = new JPanel(new BorderLayout());

		leftPanelLabel = new GDHtmlLabel();
		rightPanelLabel = new GDHtmlLabel();
		leftPanelLabel.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 0));
		rightPanelLabel.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 0));

		setLabelText(leftPanelLabel, HTMLUtilities.escapeHTML(clientName) + ":");
		setLabelText(rightPanelLabel, HTMLUtilities.escapeHTML(sourceName) + ":");

		add(leftPanel);
		add(rightPanel);
		dtLabel1 = new GDHtmlLabel();
		dtLabel1.setOpaque(true);
		dtLabel1.setBackground(Color.WHITE);
		dtLabel1.setBorder(BorderFactory.createEmptyBorder(2, 8, 0, 0));
		dtLabel1.setVerticalAlignment(SwingConstants.TOP);
		dtLabel2 = new GDHtmlLabel();
		dtLabel2.setOpaque(true);
		dtLabel2.setBackground(Color.WHITE);
		dtLabel2.setBorder(BorderFactory.createEmptyBorder(2, 8, 0, 0));
		dtLabel2.setVerticalAlignment(SwingConstants.TOP);

		JScrollPane leftScrollPane = new JScrollPane(dtLabel1);
		JScrollPane rightScrollPane = new JScrollPane(dtLabel2);
		leftScrollPane.getVerticalScrollBar().setUnitIncrement(9);
		rightScrollPane.getVerticalScrollBar().setUnitIncrement(9);
		leftPanel.add(leftScrollPane);
		rightPanel.add(rightScrollPane);
		leftPanel.add(leftPanelLabel, BorderLayout.NORTH);
		rightPanel.add(rightPanelLabel, BorderLayout.NORTH);
		syncScrollers(leftScrollPane, rightScrollPane);

	}

	private void syncScrollers(JScrollPane leftScrollPane, JScrollPane rightScrollPane) {
		final JViewport viewport1 = leftScrollPane.getViewport();
		final JViewport viewport2 = rightScrollPane.getViewport();
		viewport1.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				int y = viewport1.getViewPosition().y;
				viewport2.setViewPosition(new Point(0, y));
			}
		});
		viewport2.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				int y = viewport2.getViewPosition().y;
				viewport1.setViewPosition(new Point(0, y));
			}
		});
	}

	/**
	 * Sets the data types currently displayed in this panel.
	 * @param dataType1 the first data type to display.
	 * @param dataType2 the second data type to display.
	 */
	void setDataTypes(DataType dataType1, DataType dataType2) {
		String path1 = dataType1 != null ? dataType1.getPathName() : "";
		String path2 = dataType2 != null ? dataType2.getPathName() : "";

		setLabelText(leftPanelLabel, clientName + ": " + path1);
		setLabelText(rightPanelLabel, sourceName + ": " + path2);

		HTMLDataTypeRepresentation representation1 = ToolTipUtils.getHTMLRepresentation(dataType1);
		HTMLDataTypeRepresentation representation2 = ToolTipUtils.getHTMLRepresentation(dataType2);

		HTMLDataTypeRepresentation[] diffs = representation1.diff(representation2);

		// Display the data types.
		String dt1Text = (dataType1 != null) ? diffs[0].getHTMLString() : "";
		String dt2Text =
			(dataType2 != null) ? diffs[1].getHTMLString() : (dataType1 != null) ? "<Removed>" : "";
		dtLabel1.setText(dt1Text);
		dtLabel2.setText(dt2Text);
	}

	private void setLabelText(JLabel label, String text) {
		label.setText(HTMLUtilities.wrapAsHTML(HTMLUtilities.bold(text)));

	}
}
