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

import docking.widgets.label.GDHtmlLabel;
import docking.widgets.textpane.GHtmlTextPane;
import generic.theme.GThemeDefaults.Colors;
import ghidra.app.util.ToolTipUtils;
import ghidra.app.util.html.HTMLDataTypeRepresentation;
import ghidra.program.model.data.DataType;
import ghidra.util.HTMLUtilities;

/**
 * Panel that displays two data types side by side.
 */
class DataTypeComparePanel extends JPanel {

	private GHtmlTextPane leftDtPane;
	private GHtmlTextPane rightDtPane;
	private JPanel leftPanel;
	private JPanel rightPanel;
	private JLabel leftNameLabel;
	private JLabel rightNameLabel;
	private String clientName;
	private String sourceName;

	DataTypeComparePanel(String clientName, String sourceName) {
		super(new GridLayout(0, 2));
		this.clientName = clientName;
		this.sourceName = sourceName;
		init();
	}

	private void init() {
		setPreferredSize(new Dimension(600, 400));

		leftPanel = new JPanel(new BorderLayout());
		rightPanel = new JPanel(new BorderLayout());

		leftNameLabel = new GDHtmlLabel();
		rightNameLabel = new GDHtmlLabel();
		leftNameLabel.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 0));
		rightNameLabel.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 0));

		setLabelText(leftNameLabel, HTMLUtilities.escapeHTML(clientName) + ":");
		setLabelText(rightNameLabel, HTMLUtilities.escapeHTML(sourceName) + ":");

		add(leftPanel);
		add(rightPanel);
		leftDtPane = new GHtmlTextPane();
		leftDtPane.setOpaque(true);
		leftDtPane.setBackground(Colors.BACKGROUND);
		leftDtPane.setBorder(BorderFactory.createEmptyBorder(2, 8, 0, 0));
		rightDtPane = new GHtmlTextPane();
		rightDtPane.setOpaque(true);
		rightDtPane.setBackground(Colors.BACKGROUND);
		rightDtPane.setBorder(BorderFactory.createEmptyBorder(2, 8, 0, 0));

		JScrollPane leftScrollPane = new JScrollPane(leftDtPane);
		JScrollPane rightScrollPane = new JScrollPane(rightDtPane);
		leftScrollPane.getVerticalScrollBar().setUnitIncrement(9);
		rightScrollPane.getVerticalScrollBar().setUnitIncrement(9);
		leftPanel.add(leftScrollPane);
		rightPanel.add(rightScrollPane);
		leftPanel.add(leftNameLabel, BorderLayout.NORTH);
		rightPanel.add(rightNameLabel, BorderLayout.NORTH);
		syncScrollers(leftScrollPane, rightScrollPane);

	}

	private void syncScrollers(JScrollPane leftScrollPane, JScrollPane rightScrollPane) {
		final JViewport viewport1 = leftScrollPane.getViewport();
		final JViewport viewport2 = rightScrollPane.getViewport();
		viewport1.addChangeListener(e -> {
			int y = viewport1.getViewPosition().y;
			viewport2.setViewPosition(new Point(0, y));
		});
		viewport2.addChangeListener(e -> {
			int y = viewport2.getViewPosition().y;
			viewport1.setViewPosition(new Point(0, y));
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

		setLabelText(leftNameLabel, clientName + ":<BR>" + path1);
		setLabelText(rightNameLabel, sourceName + ":<BR>" + path2);

		HTMLDataTypeRepresentation representation1 = ToolTipUtils.getHTMLRepresentation(dataType1);
		HTMLDataTypeRepresentation representation2 = ToolTipUtils.getHTMLRepresentation(dataType2);

		HTMLDataTypeRepresentation[] diffs = representation1.diff(representation2);

		// Display the data types.
		String dt1Text = (dataType1 != null) ? diffs[0].getFullHTMLString() : "";
		String dt2Text = (dataType2 != null) ? diffs[1].getFullHTMLString()
				: (dataType1 != null) ? "<Removed>" : "";
		leftDtPane.setText(dt1Text);
		rightDtPane.setText(dt2Text);
	}

	private void setLabelText(JLabel label, String text) {
		label.setText(HTMLUtilities.wrapAsHTML(HTMLUtilities.bold(text)));

	}

	public boolean isLeft(Component component) {
		return SwingUtilities.isDescendingFrom(component, leftPanel);
	}
}
