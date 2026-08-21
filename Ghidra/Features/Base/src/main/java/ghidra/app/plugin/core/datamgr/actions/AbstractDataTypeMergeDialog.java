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
package ghidra.app.plugin.core.datamgr.actions;

import java.awt.*;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;

import org.apache.commons.lang3.StringUtils;

import docking.DialogComponentProvider;
import docking.widgets.textpane.GHtmlTextPane;
import generic.theme.GThemeDefaults.Colors;
import ghidra.app.util.ToolTipUtils;
import ghidra.program.model.data.DataType;

/**
 * Base class for both the datatype merge confirmation dialog and the datatype merge error dialog
 */
public abstract class AbstractDataTypeMergeDialog extends DialogComponentProvider {
	private static final int MAX_PREFERRED_HEIGHT = 800;
	private DataType result;
	private DataType mergeTo;
	private DataType mergeFrom;
	private String message;

	public AbstractDataTypeMergeDialog(String title, DataType result, DataType mergeTo,
			DataType mergeFrom, String message) {
		super(title, true, false, true, false);
		this.result = result;
		this.mergeTo = mergeTo;
		this.mergeFrom = mergeFrom;
		this.message = message;
		this.setRememberSize(false);

		addWorkPanel(buildMainPanel());
	}

	protected abstract String getMessageAreaTitle();

	private JComponent buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));

		if (!StringUtils.isBlank(message)) {
			panel.add(buildWarningPanel(), BorderLayout.NORTH);
		}
		panel.add(buildScrollablePreviewPanel(), BorderLayout.CENTER);

		// Restrict the initial size so that larger sized datatypes doesn't make the dialog too big
		Dimension preferredSize = panel.getPreferredSize();
		if (preferredSize.height > MAX_PREFERRED_HEIGHT) {
			panel.setPreferredSize(new Dimension(preferredSize.width, 800));
		}
		return panel;
	}

	private JComponent buildScrollablePreviewPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(buildTitlePanel(), BorderLayout.NORTH);
		JScrollPane scroll = new JScrollPane(buildPreviewPanel());
		panel.add(scroll, BorderLayout.CENTER);

		return panel;
	}

	private JComponent buildTitlePanel() {
		JPanel panel = new JPanel(new GridLayout(1, 3, 10, 10));
		if (result != null) {
			panel.add(new JLabel("DataType 1 (will be overwritten)"));
			panel.add(new JLabel("Result Preview"));
			panel.add(new JLabel("DataType 2 (will be replaced and deleted)"));
		}
		else {
			panel.add(new JLabel("DataType 1"));
			panel.add(new JLabel("DataType 2"));
		}
		return panel;
	}

	private JComponent buildPreviewPanel() {
		JPanel panel = new PreviewPanel();
		panel.add(buildPreview(mergeTo));
		if (result != null) {
			panel.add(buildPreview(result));
		}
		panel.add(buildPreview(mergeFrom));
		return panel;
	}

	private Component buildPreview(DataType dataType) {
		JPanel panel = new JPanel(new BorderLayout());
		JTextPane previewPane = new GHtmlTextPane();
		previewPane.setEditable(false);
		previewPane.setBorder(BorderFactory.createLoweredBevelBorder());
		previewPane.setBackground(Colors.BACKGROUND);

		String previewText = ToolTipUtils.getFullToolTipText(dataType);
		previewPane.setText(previewText);
		previewPane.setCaretPosition(0);
		panel.add(previewPane, BorderLayout.CENTER);

		return panel;
	}

	private Component buildWarningPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		Border emptyBorder = BorderFactory.createEmptyBorder(10, 10, 10, 10);
		TitledBorder title = BorderFactory.createTitledBorder(emptyBorder, getMessageAreaTitle());
		Border innerBorder = BorderFactory.createEmptyBorder(5, 10, 0, 0);
		panel.setBorder(BorderFactory.createCompoundBorder(title, innerBorder));

		JTextArea textArea = new JTextArea();
		textArea.setEditable(false);
		textArea.insert(message, 0);
		panel.add(textArea, BorderLayout.CENTER);

		return panel;
	}

	private static class PreviewPanel extends JPanel implements Scrollable {
		PreviewPanel() {
			super(new GridLayout(1, 3, 10, 10));
		}

		@Override
		public Dimension getPreferredScrollableViewportSize() {
			return getPreferredSize();
		}

		@Override
		public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation,
				int direction) {
			return 10;
		}

		@Override
		public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation,
				int direction) {
			return 50;
		}

		@Override
		public boolean getScrollableTracksViewportWidth() {
			return true;
		}

		@Override
		public boolean getScrollableTracksViewportHeight() {
			// we want to stretch if viewport is bigger, but use scrollbars if smaller
			if (getParent() instanceof JViewport viewport) {
				return getPreferredSize().height < viewport.getHeight();
			}
			return false;
		}

	}

}
