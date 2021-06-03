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
package ghidra.framework.main.datatree;

import java.awt.BorderLayout;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.MultiLineLabel;
import docking.widgets.OptionDialog;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GIconLabel;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

public class CheckoutDialog extends DialogComponentProvider {

	public static final int OK = 0;
	public static final int CANCELED = 1;

	private JCheckBox exclusiveCB;
	private int actionID = CANCELED;

	public CheckoutDialog() {
		super("Checkout Versioned File(s)");
		setHelpLocation(new HelpLocation(GenericHelpTopics.REPOSITORY, "CheckoutDialog"));
		addWorkPanel(buildMainPanel());

		addOKButton();
		addCancelButton();
	}

	@Override
	protected void okCallback() {
		actionID = OK;
		close();
	}

	@Override
	protected void cancelCallback() {
		actionID = CANCELED;
		close();
	}

	/**
	 * Show the dialog; return an ID for the action that the user chose.
	 * 
	 * @param tool the tool used to show the dialog
	 * @return OK, or CANCEL
	 */
	public int showDialog(PluginTool tool) {
		exclusiveCB.setSelected(false);
		tool.showDialog(this);
		return actionID;
	}

	public boolean exclusiveCheckout() {
		return exclusiveCB.isSelected();
	}

	private JPanel buildMainPanel() {
		JPanel innerPanel = new JPanel();
		innerPanel.setLayout(new BorderLayout());
		innerPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));

		JPanel msgPanel = new JPanel(new BorderLayout());
		msgPanel.add(
			new GIconLabel(OptionDialog.getIconForMessageType(OptionDialog.QUESTION_MESSAGE)),
			BorderLayout.WEST);

		MultiLineLabel msgText = new MultiLineLabel("Checkout selected file(s)?");
		msgText.setMaximumSize(msgText.getPreferredSize());
		msgPanel.add(msgText, BorderLayout.CENTER);

		innerPanel.add(msgPanel, BorderLayout.CENTER);

		exclusiveCB = new GCheckBox("Request exclusive checkout");

		JPanel cbPanel = new JPanel(new BorderLayout());
		cbPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
		cbPanel.add(exclusiveCB);
		innerPanel.add(cbPanel, BorderLayout.SOUTH);

		return innerPanel;
	}
}
