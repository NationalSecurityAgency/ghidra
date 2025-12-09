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
package ghidra.app.util;

import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.DropDownSelectionTextField;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.layout.PairLayout;
import ghidra.util.task.*;

/**
 * Class for choosing a namespace
 */
public class NamespaceChooserDialog extends DialogComponentProvider {

	private DropDownSelectionTextField<Namespace> dropDownField;
	private NamespaceDropDownModel namespaceModel;
	private Namespace chosenNamespace;

	public NamespaceChooserDialog() {
		super("Namespace Chooser");
		namespaceModel = new NamespaceDropDownModel();
		addWorkPanel(buildWorkPanel());
		addOKButton();
		addCancelButton();
	}

	public Namespace getNameSpace(Program program) {
		List<Namespace> namespaces = gatherNamespaces(program);
		if (namespaces == null) {
			// user cancelled while gathering namespaces
			return null;
		}
		namespaceModel.setNamespaces(namespaces);
		DockingWindowManager.showDialog(this);
		return chosenNamespace;
	}

	@Override
	protected void okCallback() {
		chosenNamespace = dropDownField.getSelectedValue();
		close();
	}

	@Override
	protected void cancelCallback() {
		chosenNamespace = null;
		close();
	}

	private List<Namespace> gatherNamespaces(Program program) {
		GatherNamespacesTask task = new GatherNamespacesTask(program);
		TaskLauncher.launch(task);
		return task.getNamespaces();
	}

	private JComponent buildWorkPanel() {
		JPanel panel = new JPanel(new PairLayout());
		panel.add(new JLabel("Namespace:  "));

		dropDownField = new DropDownSelectionTextField<>(namespaceModel);
		panel.add(dropDownField);
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		return panel;
	}

	private static class GatherNamespacesTask extends Task {
		private List<Namespace> namespaces;
		private Program program;

		GatherNamespacesTask(Program program) {
			super("Gather Namespaces");
			this.program = program;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			List<Namespace> list = new ArrayList<>();
			list.add(program.getGlobalNamespace());
			for (Symbol symbol : program.getSymbolTable().getDefinedSymbols()) {
				monitor.checkCancelled();
				if (!symbol.getSymbolType().isNamespace()) {
					continue;
				}
				Object object = symbol.getObject();
				if (object instanceof Function f && f.isThunk()) {
					continue;
				}
				list.add((Namespace) object);
			}
			namespaces = list;
		}

		List<Namespace> getNamespaces() {
			return namespaces;
		}

	}

}
