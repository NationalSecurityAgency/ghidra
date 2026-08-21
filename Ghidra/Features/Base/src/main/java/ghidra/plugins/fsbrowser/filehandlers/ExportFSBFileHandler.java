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
package ghidra.plugins.fsbrowser.filehandlers;

import java.io.File;
import java.io.IOException;
import java.util.List;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.tree.GTree;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.plugins.fsbrowser.*;
import ghidra.plugins.fsbrowser.tasks.GFileSystemExtractAllTask;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

public class ExportFSBFileHandler implements FSBFileHandler {
	public static final String FSB_EXPORT_ALL = "FSB Export All";
	public static final String FSB_EXPORT = "FSB Export";

	private FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public List<DockingAction> createActions() {
		return List.of(new ActionBuilder(FSB_EXPORT, context.plugin().getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getFileFSRL() != null)
				.popupMenuIcon(FSBIcons.EXTRACT)
				.popupMenuPath("Export...")
				.popupMenuGroup("F", "C")
				.onAction(ac -> {
					FSRL fsrl = ac.getFileFSRL();
					if (fsrl == null) {
						return;
					}
					GTree tree = ac.getTree();
					GhidraFileChooser chooser = new GhidraFileChooser(tree);
					chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
					chooser.setTitle("Select Where To Export File");
					chooser.setApproveButtonText("Export");
					chooser.setSelectedFile(
						new File(context.plugin().getLastExportDirectory(), fsrl.getName()));
					File selectedFile = chooser.getSelectedFile();
					chooser.dispose();
					if (selectedFile == null) {
						return;
					}

					if (selectedFile.exists()) {
						int answer = OptionDialog.showYesNoDialog(tree, "Confirm Overwrite",
							"%s\nThe file already exists.\nDo you want to overwrite it?"
									.formatted(selectedFile.getAbsolutePath()));
						if (answer == OptionDialog.NO_OPTION) {
							return;
						}
					}
					context.plugin().setLastExportDirectory(selectedFile.getParentFile());
					tree.runTask(
						monitor -> doExtractFile(fsrl, selectedFile, ac.getSelectedNode(),
							monitor));
				})
				.build(),
			new ActionBuilder(FSB_EXPORT_ALL, context.plugin().getName())
					.withContext(FSBActionContext.class)
					.enabledWhen(ac -> ac.notBusy() && ac.isSelectedAllDirs())
					.popupMenuIcon(FSBIcons.EXTRACT)
					.popupMenuPath("Export All...")
					.popupMenuGroup("F", "C")
					.onAction(ac -> {
						FSRL fsrl = ac.getFSRL(true);
						if (fsrl == null) {
							return;
						}
						GTree tree = ac.getTree();
						if (fsrl instanceof FSRLRoot) {
							fsrl = fsrl.appendPath("/");
						}
						GhidraFileChooser chooser = new GhidraFileChooser(tree);
						chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
						chooser.setTitle("Select Export Directory");
						chooser.setApproveButtonText("Export All");
						chooser.setCurrentDirectory(context.plugin().getLastExportDirectory());
						File selectedFile = chooser.getSelectedFile();
						chooser.dispose();
						if (selectedFile == null) {
							return;
						}
						if (!selectedFile.isDirectory()) {
							Msg.showInfo(this, tree, "Export All",
								"Selected file is not a directory.");
							return;
						}
						context.plugin().setLastExportDirectory(selectedFile);

						TaskLauncher.launch(new GFileSystemExtractAllTask(fsrl, selectedFile, tree));
					})
					.build());
	}

	private void doExtractFile(FSRL fsrl, File outputFile, FSBNode node, TaskMonitor monitor) {
		if (!context.fsbComponent().ensureFileAccessable(fsrl, node, monitor)) {
			return;
		}
		monitor.setMessage("Exporting...");
		try (ByteProvider fileBP = context.fsService().getByteProvider(fsrl, false, monitor)) {
			monitor.initialize(fileBP.length(), "Exporting %s".formatted(fsrl.getName()));
			long bytesCopied = FSUtilities.copyByteProviderToFile(fileBP, outputFile, monitor);

			String msg = "Exported %s to %s, %d bytes copied.".formatted(fsrl.getName(), outputFile,
				bytesCopied);

			context.fsbComponent().getTool().setStatusInfo(msg);
			Msg.info(this, msg);
		}
		catch (IOException | CancelledException | UnsupportedOperationException e) {
			FSUtilities.displayException(this, context.plugin().getTool().getActiveWindow(),
				"Error Exporting File", e.getMessage(), e);
		}
	}

}
