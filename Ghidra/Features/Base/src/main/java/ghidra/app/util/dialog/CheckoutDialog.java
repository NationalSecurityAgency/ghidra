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
package ghidra.app.util.dialog;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.MultiLineLabel;
import docking.widgets.OptionDialog;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GIconLabel;
import ghidra.app.util.HelpTopics;
import ghidra.framework.model.DomainFile;
import ghidra.framework.remote.User;
import ghidra.util.HelpLocation;

/**
 * 
 */
public class CheckoutDialog extends DialogComponentProvider {

	public static final int CHECKOUT = 0;
	public static final int DO_NOT_CHECKOUT = 1;

	private boolean exclusiveCheckout;
	private int actionID = DO_NOT_CHECKOUT;

	public CheckoutDialog(DomainFile df, User user) {
		super("Versioned File not Checked Out", true);

		addWorkPanel(buildMainPanel(df, user));
		setHelpLocation(new HelpLocation(HelpTopics.PROGRAM, "FileNotCheckedOut"));

		JButton checkoutButton = new JButton("Yes");
		checkoutButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				actionID = CHECKOUT;
				close();
			}
		});
		addButton(checkoutButton);

		JButton noCheckoutButton = new JButton("No");
		noCheckoutButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				actionID = DO_NOT_CHECKOUT;
				close();
			}
		});
		addButton(noCheckoutButton);

	}

	/**
	 * Show the dialog; return an ID for the action that the user chose.
	 * @return OK, or CANCEL
	 */
	public int showDialog() {
		if (SwingUtilities.isEventDispatchThread()) {
			DockingWindowManager.showDialog(null, CheckoutDialog.this);
		}
		else {
			try {
				SwingUtilities.invokeAndWait(new Runnable() {
					@Override
					public void run() {
						DockingWindowManager.showDialog(null, CheckoutDialog.this);
					}
				});
			}
			catch (Exception e) {
			}
		}
		return actionID;
	}

	public boolean exclusiveCheckout() {
		return exclusiveCheckout;
	}

	private JPanel buildMainPanel(DomainFile df, User user) {
		JPanel innerPanel = new JPanel();
		innerPanel.setLayout(new BorderLayout());
		innerPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));

		JPanel msgPanel = new JPanel(new BorderLayout());
		msgPanel.add(
			new GIconLabel(OptionDialog.getIconForMessageType(OptionDialog.WARNING_MESSAGE)),
			BorderLayout.WEST);

		MultiLineLabel msgText = new MultiLineLabel("File " + df.getName() +
			" is NOT CHECKED OUT.\n" + "If you want to make changes and save them\n" +
			"to THIS file, then you must first check out the file.\n" +
			"Do you want to Check Out this file?");
		msgText.setMaximumSize(msgText.getPreferredSize());
		msgPanel.add(msgText, BorderLayout.CENTER);

		innerPanel.add(msgPanel, BorderLayout.CENTER);

		exclusiveCheckout = true;
		if (user != null) {
			exclusiveCheckout = false;
			if (user.hasWritePermission()) {
				final JCheckBox exclusiveCB = new GCheckBox("Request exclusive check out");
				exclusiveCB.setSelected(false);
				exclusiveCB.addActionListener(new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent e) {
						exclusiveCheckout = exclusiveCB.isSelected();
					}
				});
				JPanel cbPanel = new JPanel(new BorderLayout());
				cbPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
				cbPanel.add(exclusiveCB);
				innerPanel.add(cbPanel, BorderLayout.SOUTH);
			}
		}
		return innerPanel;
	}
}
