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
package ghidra.file.formats.android.apk;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.apache.commons.io.FilenameUtils;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.file.eclipse.AndroidProjectCreator;
import ghidra.file.jad.JadProcessWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.plugins.fsbrowser.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ApkFSBFileHandler implements FSBFileHandler {

	private FSBFileHandlerContext context;
	private File lastDirectory;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	private static boolean isAPK(FSRL fsrl) {
		return (fsrl != null) && (fsrl.getName() != null) &&
			"apk".equalsIgnoreCase(FilenameUtils.getExtension(fsrl.getName()));
	}

	@Override
	public List<DockingAction> createActions() {
		return List.of(new ActionBuilder("FSB Export Eclipse Project", context.plugin().getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && JadProcessWrapper.isJadPresent() &&
					isAPK(ac.getFileFSRL()))
				.popupMenuPath("Export Eclipse Project")
				.popupMenuIcon(FSBIcons.ECLIPSE)
				.popupMenuGroup("H")
				.onAction(ac -> {
					FSRL fsrl = ac.getFileFSRL();
					if (fsrl == null) {
						Msg.info(this, "Unable to export eclipse project");
						return;
					}

					lastDirectory = lastDirectory == null
							? new File(System.getProperty("user.home"))
							: lastDirectory;

					GhidraFileChooser chooser = new GhidraFileChooser(ac.getSourceComponent());
					chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
					chooser.setTitle("Select Eclipse Project Directory");
					chooser.setApproveButtonText("SELECT");
					chooser.setCurrentDirectory(context.plugin().getLastExportDirectory());
					File selectedFile = chooser.getSelectedFile();
					chooser.dispose();
					if (selectedFile == null) {
						return;
					}
					lastDirectory = selectedFile;

					ac.getComponentProvider()
							.runTask(monitor -> doExportToEclipse(fsrl, lastDirectory, monitor));

				})
				.build());
	}

	private void doExportToEclipse(FSRL fsrl, File outputDirectory, TaskMonitor monitor) {
		try (RefdFile refdFile = FileSystemService.getInstance().getRefdFile(fsrl, monitor)) {
			AndroidProjectCreator creator =
				new AndroidProjectCreator(refdFile.file.getFSRL(), outputDirectory);
			creator.create(monitor);

			if (creator.getLog().hasMessages()) {
				Msg.showInfo(this, null, "Export to Eclipse Project", creator.getLog().toString());
			}
		}
		catch (IOException | CancelledException e) {
			FSUtilities.displayException(this, null, "Error Exporting to Eclipse", e.getMessage(),
				e);
		}
	}

}
