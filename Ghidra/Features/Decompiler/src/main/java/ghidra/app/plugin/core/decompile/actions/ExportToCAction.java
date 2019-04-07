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
package ghidra.app.plugin.core.decompile.actions;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;

import java.io.*;

import javax.swing.ImageIcon;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;

public class ExportToCAction extends DockingAction {
	private static final ImageIcon EXPORT_ICON = ResourceManager.loadImage("images/page_edit.png");
	private static final String LAST_USED_C_FILE = "last.used.decompiler.c.export.file";
	private final DecompilerController controller;

	public ExportToCAction(String owner, DecompilerController controller) {
		super("Export to C", owner);
		this.controller = controller;
		setToolBarData(new ToolBarData(EXPORT_ICON, "Local"));
		setDescription("Export the current function to C");
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}
		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			// Let this through here and handle it in actionPerformed().  This lets us alert 
			// the user that they have to wait until the decompile is finished.  If we are not
			// enabled at this point, then the keybinding will be propagated to the global 
			// actions, which is not what we want.
			return true;
		}

		return controller.getFunction() != null && controller.getCCodeModel() != null;
	}

	private File readLastUsedFile() {
		String filename = Preferences.getProperty(LAST_USED_C_FILE);
		if (filename == null) {
			return null;
		}
		return new File(filename);
	}

	private void saveLastUsedFileFile(File file) {
		Preferences.setProperty(LAST_USED_C_FILE, file.getAbsolutePath());
		Preferences.store();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// Note: we intentionally do this check here and not in isEnabledForContext() so 
		// that global events do not get triggered.
		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			Msg.showInfo(getClass(), context.getComponentProvider().getComponent(),
				"Decompiler Action Blocked",
				"You cannot perform Decompiler actions while the Decompiler is busy");
			return;
		}

		File lastUsedFile = readLastUsedFile();

		String[] extensions = new String[] { "h", "c", "cpp" };
		GhidraFileChooser fileChooser = new GhidraFileChooser(controller.getDecompilerPanel());
		fileChooser.setFileFilter(new ExtensionFileFilter(extensions, "C/C++ Files"));
		if (lastUsedFile != null) {
			fileChooser.setSelectedFile(lastUsedFile);
		}
		File file = fileChooser.getSelectedFile();
		if (file == null) {
			return;
		}

		saveLastUsedFileFile(file);

		boolean hasExtension = false;
		String path = file.getAbsolutePath();
		for (String element : extensions) {
			if (path.toLowerCase().endsWith("." + element)) {
				hasExtension = true;
			}
		}

		if (!hasExtension) {
			file = new File(path + ".c");
		}

		if (file.exists()) {
			if (OptionDialog.showYesNoDialog(controller.getDecompilerPanel(),
				"Overwrite Existing File?", "Do you want to overwrite the existing file?") == OptionDialog.OPTION_TWO) {
				return;
			}
		}

		try {
			PrintWriter writer = new PrintWriter(new FileOutputStream(file));
			ClangTokenGroup grp = controller.getCCodeModel();
			PrettyPrinter printer = new PrettyPrinter(controller.getFunction(), grp);
			DecompiledFunction decompFunc = printer.print(true);
			writer.write(decompFunc.getC());
			writer.close();
			controller.setStatusMessage("Successfully exported function(s) to " +
				file.getAbsolutePath());
		}
		catch (IOException e) {
			Msg.showError(getClass(), controller.getDecompilerPanel(), "Export to C Failed",
				"Error exporting to C: " + e);
		}
	}

}
