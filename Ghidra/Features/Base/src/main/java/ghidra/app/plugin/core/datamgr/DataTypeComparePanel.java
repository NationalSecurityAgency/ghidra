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
import java.awt.event.MouseEvent;

import javax.swing.*;

import docking.widgets.label.GDLabel;
import docking.widgets.textpane.GHtmlTextPane;
import generic.theme.GThemeDefaults.Colors;
import generic.theme.Gui;
import ghidra.app.util.ToolTipUtils;
import ghidra.app.util.html.HTMLDataTypeRepresentation;
import ghidra.program.model.data.*;

/**
 * Panel that displays two data types side by side.
 */
class DataTypeComparePanel extends JPanel {

	private static final String NAME_FONT_ID = "font.plugin.datamgr.compare.name";
	private GHtmlTextPane leftDtPane;
	private GHtmlTextPane rightDtPane;
	private JPanel leftPanel;
	private JPanel rightPanel;
	private JLabel leftNameLabel;
	private JLabel rightNameLabel;
	private JLabel leftDescriptionLabel;
	private JLabel rightDescriptionLabel;
	private String localName;
	private String sourceName;

	DataTypeComparePanel(String localName, String sourceName) {
		super(new GridLayout(0, 2));
		this.localName = localName;
		this.sourceName = sourceName;
		init();
	}

	private void init() {
		setPreferredSize(new Dimension(600, 400));

		leftPanel = new JPanel(new BorderLayout());
		rightPanel = new JPanel(new BorderLayout());

		leftNameLabel = createLabelWidet();
		rightNameLabel = createLabelWidet();
		leftDescriptionLabel = createLabelWidet();
		rightDescriptionLabel = createLabelWidet();

		leftNameLabel.setText(localName + ":");
		rightNameLabel.setText(sourceName + ":");

		JPanel leftLabelPanel = new JPanel();
		leftLabelPanel.setLayout(new BoxLayout(leftLabelPanel, BoxLayout.PAGE_AXIS));
		leftLabelPanel.add(leftNameLabel);
		leftLabelPanel.add(leftDescriptionLabel);

		JPanel rightLabelPanel = new JPanel();
		rightLabelPanel.setLayout(new BoxLayout(rightLabelPanel, BoxLayout.PAGE_AXIS));
		rightLabelPanel.add(rightNameLabel);
		rightLabelPanel.add(rightDescriptionLabel);

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
		leftPanel.add(leftLabelPanel, BorderLayout.NORTH);
		rightPanel.add(rightLabelPanel, BorderLayout.NORTH);
		syncScrollers(leftScrollPane, rightScrollPane);
	}

	private JLabel createLabelWidet() {
		JLabel label = new GDLabel() {
			@Override
			public String getToolTipText(MouseEvent e) {
				FontMetrics fm = getFontMetrics(getFont());
				int textWidth = fm.stringWidth(getText());
				int availableWidth = getWidth() - getInsets().left - getInsets().right;
				if (textWidth > availableWidth) {
					return getText();
				}
				return null;
			}
		};
		ToolTipManager.sharedInstance().registerComponent(label);
		label.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 0));

		Font font = Gui.getFont(NAME_FONT_ID);
		label.setFont(font);

		return label;
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

		DataTypePath path1 = dataType1 != null ? dataType1.getDataTypePath() : null;
		DataTypePath path2 = dataType2 != null ? dataType2.getDataTypePath() : null;

		CategoryPath catPath1 = path1.getCategoryPath();
		CategoryPath catPath2 = path2.getCategoryPath();
		leftNameLabel.setText(localName + ':' + catPath1.getPath());
		rightNameLabel.setText(sourceName + ':' + catPath2.getPath());

		leftDescriptionLabel.setText(path1.getDataTypeName());
		rightDescriptionLabel.setText(path2.getDataTypeName());

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

	public boolean isLeft(Component component) {
		return SwingUtilities.isDescendingFrom(component, leftPanel);
	}
}
