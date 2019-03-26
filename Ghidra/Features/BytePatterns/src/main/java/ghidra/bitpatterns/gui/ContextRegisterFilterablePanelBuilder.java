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
package ghidra.bitpatterns.gui;

import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JPanel;

import ghidra.bitpatterns.info.ContextRegisterExtent;
import ghidra.bitpatterns.info.ContextRegisterFilter;

/**
 * 
 * This is an abstract class for defining panels whose contents can be filtered
 * based on the values of context registers.
 *
 */
public abstract class ContextRegisterFilterablePanelBuilder {
	private static final String APPLY_BUTTON_TEXT = "Apply Register Filter";
	private static final String CLEAR_BUTTON_TEXT = "Clear Register Filter";
	private JPanel buttonPanel;
	private JButton applyButton;
	private JButton clearButton;
	private ContextRegisterExtent extent;
	private ContextRegisterFilter registerFilter;
	protected JPanel mainPanel;

	/**
	 * Base class for panels whose contents can be filtered by context register values
	 */
	public ContextRegisterFilterablePanelBuilder() {
		buttonPanel = buildContextRegisterFilterPanel();
	}

	/**
	 * Returns the button panel
	 * @return panel
	 */
	public JPanel getButtonPanel() {
		return buttonPanel;
	}

	/**
	 * Updates the context register extent and clears the context register filter
	 * @param contextRegisterExtent new extent
	 */
	public void updateExtentAndClearFilter(ContextRegisterExtent contextRegisterExtent) {
		this.extent = contextRegisterExtent;
		this.registerFilter = null;
	}

	/**
	 * Enables or disables buttons relating to context register filtering
	 * @param enable whether to enable the buttons (if false buttons are disabled)
	 */
	public void enableFilterButtons(boolean enable) {
		if (applyButton != null) {
			applyButton.setEnabled(enable);
		}
		if (clearButton != null) {
			clearButton.setEnabled(enable);
		}
		return;
	}

	/**
	 * Returns the context register filter
	 * @return context register filter
	 */
	public ContextRegisterFilter getContextRegisterFilter() {
		return registerFilter;
	}

	private JPanel buildContextRegisterFilterPanel() {
		buttonPanel = new JPanel(new FlowLayout());

		applyButton = new JButton(APPLY_BUTTON_TEXT);
		buttonPanel.add(applyButton);
		applyButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				ContextRegisterFilterInputDialog filterDialog =
					new ContextRegisterFilterInputDialog("Set Context Register Filter", extent,
						mainPanel);
				registerFilter = filterDialog.getFilter();
				if (registerFilter == null) {
					return;
				}
				applyFilterAction();
			}
		});

		clearButton = new JButton(CLEAR_BUTTON_TEXT);
		buttonPanel.add(clearButton);
		clearButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				clearFilterAction();
			}

		});
		return buttonPanel;
	}

	/**
	 * Applies the context register filter
	 */
	public abstract void applyFilterAction();

	/**
	 * Clears the context register filter
	 */
	public abstract void clearFilterAction();

}
