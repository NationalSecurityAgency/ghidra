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
package ghidra.examples;

import java.awt.BorderLayout;

import javax.swing.*;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import resources.ResourceManager;

public class ShowInfoComponentProvider extends ComponentProviderAdapter {
	private final static ImageIcon CLEAR_ICON = ResourceManager.loadImage("images/erase16.png");
	private final static ImageIcon INFO_ICON = ResourceManager.loadImage("images/information.png");

	private JPanel panel;
	private JTextArea textArea;
	private DockingAction clearAction;
	private Program currentProgram;
	private ProgramLocation currentLocation;

	public ShowInfoComponentProvider(PluginTool tool, String name) {
		super(tool, name, name);
		create();
		setIcon(INFO_ICON);
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setTitle("Show Info");
		setVisible(true);
		createActions();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	void clear() {
		currentProgram = null;
		currentLocation = null;
		textArea.setText("");
	}

	void locationChanged(Program program, ProgramLocation location) {
		this.currentProgram = program;
		this.currentLocation = location;
		if (isVisible()) {
			updateInfo();
		}
	}

	private void updateInfo() {
		if (currentLocation == null || currentLocation.getAddress() == null) {
			return;
		}

		CodeUnit cu =
			currentProgram.getListing().getCodeUnitContaining(currentLocation.getAddress());

		// TODO -- create the string to set

		String preview = CodeUnitFormat.DEFAULT.getRepresentationString(cu, true);
		if (cu instanceof Instruction) {
			textArea.setText("Instruction: " + preview);
		}
		else {
			Data data = (Data) cu;
			if (data.isDefined()) {
				textArea.setText("Defined Data: " + preview);
			}
			else {
				textArea.setText("Undefined Data: " + preview);
			}
		}
	}

	private void create() {
		panel = new JPanel(new BorderLayout());
		textArea = new JTextArea(5, 25);
		textArea.setEditable(false);
		JScrollPane sp = new JScrollPane(textArea);
		panel.add(sp);
	}

	private void createActions() {
		clearAction = new DockingAction("Clear Text Area", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				textArea.setText("");
			}
		};
		clearAction.setToolBarData(new ToolBarData(CLEAR_ICON, null));

		clearAction.setEnabled(true);
		tool.addLocalAction(this, clearAction);
	}

	@Override
	public void componentShown() {
		updateInfo();
	}

}
