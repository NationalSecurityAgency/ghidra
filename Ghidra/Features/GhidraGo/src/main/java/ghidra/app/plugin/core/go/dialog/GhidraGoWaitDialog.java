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
package ghidra.app.plugin.core.go.dialog;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.MultiLineLabel;
import docking.widgets.OptionDialog;
import docking.widgets.label.GIconLabel;
import ghidra.app.plugin.core.go.exception.StopWaitingException;

public abstract class GhidraGoWaitDialog extends DialogComponentProvider {

	public static final int WAIT = 0;
	public static final int DO_NOT_WAIT = 1;

	protected int actionID = DO_NOT_WAIT;
	protected boolean answered = false;

	public GhidraGoWaitDialog(String title, String msgText, boolean modal) {
		super(title, modal);

		addWorkPanel(buildMainPanel(msgText));

		JButton waitButton = new JButton("Wait");
		waitButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				actionID = WAIT;
				answered = true;
				close();
			}
		});
		addButton(waitButton);

		JButton noWaitButton = new JButton("No");
		noWaitButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				actionID = DO_NOT_WAIT;
				answered = true;
				close();
			}
		});
		addButton(noWaitButton);
	}

	public void showDialog() throws StopWaitingException {
		answered = false;
		if (!isShowing()) {
			DockingWindowManager.showDialog(null, this);
		}

		if (answered && actionID == DO_NOT_WAIT) {
			throw new StopWaitingException();
		}
	}

	public boolean isAnsweredNo() {
		return answered && actionID == DO_NOT_WAIT;
	}

	public void reset() {
		answered = false;
		actionID = WAIT;
		close();
	}

	protected JPanel buildMainPanel(String msgTextString) {
		JPanel innerPanel = new JPanel();
		innerPanel.setLayout(new BorderLayout());
		innerPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));

		JPanel msgPanel = new JPanel(new BorderLayout());
		msgPanel.add(
			new GIconLabel(OptionDialog.getIconForMessageType(OptionDialog.WARNING_MESSAGE)),
			BorderLayout.WEST);

		MultiLineLabel msgText = new MultiLineLabel(msgTextString);
		msgText.setMaximumSize(msgText.getPreferredSize());
		msgPanel.add(msgText, BorderLayout.CENTER);

		innerPanel.add(msgPanel, BorderLayout.CENTER);
		return innerPanel;
	}
}
