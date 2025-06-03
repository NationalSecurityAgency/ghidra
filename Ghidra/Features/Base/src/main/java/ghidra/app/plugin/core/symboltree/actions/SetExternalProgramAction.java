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
package ghidra.app.plugin.core.symboltree.actions;

import static ghidra.framework.main.DataTreeDialogType.*;

import javax.swing.Icon;
import javax.swing.SwingUtilities;
import javax.swing.tree.TreePath;

import docking.action.MenuData;
import docking.action.ToolBarData;
import generic.theme.GIcon;
import ghidra.app.cmd.refs.SetExternalNameCmd;
import ghidra.app.plugin.core.symboltree.*;
import ghidra.app.plugin.core.symboltree.nodes.LibrarySymbolNode;
import ghidra.framework.cmd.Command;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.util.HelpLocation;

public class SetExternalProgramAction extends SymbolTreeContextAction {
	private static Icon EDIT_ICON = new GIcon("icon.plugin.symboltree.set.external");
	private final SymbolTreePlugin plugin;
	private SymbolTreeProvider provider;

	public SetExternalProgramAction(SymbolTreePlugin plugin, SymbolTreeProvider provider) {
		super("Set External Program", plugin.getName());
		this.plugin = plugin;
		this.provider = provider;
		this.setPopupMenuData(
			new MenuData(new String[] { "Set External Program" }, EDIT_ICON, "0External"));

		this.setToolBarData(new ToolBarData(EDIT_ICON, null));

		setEnabled(false);
	}

	@Override
	public boolean isEnabledForContext(SymbolTreeActionContext context) {

		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		if (selectionPaths.length == 1) {
			Object object = selectionPaths[0].getLastPathComponent();
			if (object instanceof LibrarySymbolNode) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void actionPerformed(SymbolTreeActionContext context) {
		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		if (selectionPaths.length != 1) {
			return;
		}
		Object object = selectionPaths[0].getLastPathComponent();
		if (!(object instanceof LibrarySymbolNode)) {
			return;
		}

		LibrarySymbolNode libraryNode = (LibrarySymbolNode) object;
		final String externalName = libraryNode.getName();
		Program program = plugin.getProgram();
		ExternalManager externalManager = program.getExternalManager();
		final String externalLibraryPath = externalManager.getExternalLibraryPath(externalName);

		final DataTreeDialog dialog = new DataTreeDialog(provider.getComponent(),
			"Choose External Program (" + externalName + ")", OPEN);

		dialog.setSearchText(externalName);

		dialog.addOkActionListener(e1 -> {
			DomainFile domainFile = dialog.getDomainFile();
			if (domainFile == null) {
				return;
			}
			String pathName = domainFile.toString();
			dialog.close();
			if (!pathName.equals(externalLibraryPath)) {
				Command<Program> cmd =
					new SetExternalNameCmd(externalName, domainFile.getPathname());
				plugin.getTool().execute(cmd, plugin.getProgram());
			}
		});
		dialog.setHelpLocation(new HelpLocation("SymbolTreePlugin", "ChooseExternalProgram"));

		if (externalLibraryPath != null) {
			SwingUtilities.invokeLater(() -> {
				Project project = AppInfo.getActiveProject();
				ProjectData pd = project.getProjectData();
				DomainFile domainFile = pd.getFile(externalLibraryPath);
				if (domainFile != null) {
					dialog.selectDomainFile(domainFile);
				}
			});
		}

		plugin.getTool().showDialog(dialog);
	}
}
