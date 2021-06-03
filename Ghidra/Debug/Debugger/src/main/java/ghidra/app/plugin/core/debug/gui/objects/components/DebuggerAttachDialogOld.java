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
package ghidra.app.plugin.core.debug.gui.objects.components;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.Arrays;

import javax.swing.*;

import docking.DialogComponentProvider;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractAttachAction;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractLaunchAction;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.target.TargetAttacher;
import ghidra.dbg.util.ShellUtils;
import ghidra.util.MessageType;
import ghidra.util.Msg;

public class DebuggerAttachDialogOld extends DialogComponentProvider {
	protected DebuggerObjectsProvider provider;
	protected TargetAttacher attacher;

	protected JTextField pidField;

	protected JButton attachButton;

	public DebuggerAttachDialogOld(DebuggerObjectsProvider provider) {
		super(AbstractAttachAction.NAME, true, true, true, false);
		this.provider = provider;

		populateComponents();
	}

	protected void populateComponents() {
		JPanel panel = new JPanel(new BorderLayout());

		JPanel centerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
		panel.add(centerPanel, BorderLayout.CENTER);

		JPanel grid = new JPanel(new GridLayout(1, 2));
		centerPanel.add(grid);

		JLabel cmdLineLabel = new JLabel("Target pid");
		grid.add(cmdLineLabel);

		pidField = new JTextField();
		grid.add(pidField);

		// TODO: Configurable working directory, if applicable, etc.
		// Will require API and protocol extension.

		addWorkPanel(panel);

		attachButton = new JButton();
		AbstractLaunchAction.styleButton(attachButton);
		addButton(attachButton);

		addCancelButton();

		attachButton.addActionListener(this::attach);
	}

	protected void attach(ActionEvent evt) {
		String pidstr = pidField.getText();
		long pid = pidstr.startsWith("0x") ? Long.parseLong(pidstr, 16) : Long.parseLong(pidstr);
		AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			setStatusText("Attaching");
			attacher.attach(pid).handle(seq::next);
		}).finish().exceptionally(e -> {
			Msg.showError(this, getComponent(), "Could not attach", e);
			setStatusText("Could not attach: " + e.getMessage(), MessageType.ERROR);
			return null;
		});
	}

	public void setLauncher(TargetAttacher attacher) {
		this.attacher = attacher;
	}

	public void setArgs(String... args) {
		String cmdLine = ShellUtils.generateLine(Arrays.asList(args));
		pidField.setText(cmdLine);
	}

}
