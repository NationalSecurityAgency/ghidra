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

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.util.HashSet;
import java.util.Set;

import javax.swing.*;

import docking.DialogComponentProvider;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractSetBreakpointAction;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.dbg.target.TargetBreakpointSpecContainer;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.util.MessageType;
import ghidra.util.Msg;
import ghidra.util.layout.PairLayout;

public class DebuggerBreakpointDialog extends DialogComponentProvider {
	protected DebuggerObjectsProvider provider;
	protected TargetBreakpointSpecContainer container;

	protected JTextField expressionField;

	protected JButton addButton;

	public DebuggerBreakpointDialog(DebuggerObjectsProvider provider) {
		super(AbstractSetBreakpointAction.NAME, true, true, true, false);
		this.provider = provider;

		populateComponents();
	}

	protected void populateComponents() {
		JPanel panel = new JPanel(new BorderLayout());

		JPanel centerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
		panel.add(centerPanel, BorderLayout.CENTER);

		JPanel pairPanel = new JPanel(new PairLayout(5, 5));
		centerPanel.add(pairPanel);

		JLabel expressionLabel = new JLabel("Expression");
		pairPanel.add(expressionLabel);

		expressionField = new JTextField();
		pairPanel.add(expressionField);

		addWorkPanel(panel);

		addButton = new JButton();
		AbstractSetBreakpointAction.styleButton(addButton);
		addButton(addButton);

		addCancelButton();

		addButton.addActionListener(this::addBreakpoint);
	}

	protected void addBreakpoint(ActionEvent evt) {
		String expression = expressionField.getText();

		setStatusText("Adding");
		Set<TargetBreakpointKind> kinds = new HashSet<>();
		kinds.add(TargetBreakpointKind.SW_EXECUTE);
		container.placeBreakpoint(expression, kinds).exceptionally(e -> {
			Msg.showError(this, getComponent(), "Could not set breakpoint", e);
			setStatusText("Could not set breakpoint: " + e.getMessage(), MessageType.ERROR);
			return null;
		});
		close();
	}

	public void setContainer(TargetBreakpointSpecContainer container) {
		this.container = container;
	}

}
