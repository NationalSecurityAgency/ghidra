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
package ghidra.file.jad;

import java.io.File;
import java.util.List;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.plugins.fsbrowser.*;
import ghidra.util.Msg;

public class JadFSBFileHandler implements FSBFileHandler {

	private FSBFileHandlerContext context;
	private File lastDirectory;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public List<DockingAction> createActions() {
		return List.of(new ActionBuilder("FSB Decompile JAR", context.plugin().getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && JadProcessWrapper.isJadPresent() &&
					ac.getFileFSRL() != null)
				.popupMenuPath("Decompile JAR")
				.popupMenuIcon(FSBIcons.JAR)
				.popupMenuGroup("J")
				.onAction(ac -> {
					FSRL jarFSRL = ac.getFileFSRL();
					if (jarFSRL == null) {
						return;
					}

					lastDirectory = lastDirectory == null
							? new File(System.getProperty("user.home"))
							: lastDirectory;

					GhidraFileChooser chooser = new GhidraFileChooser(ac.getSourceComponent());
					chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
					chooser.setTitle("Select JAR Output Directory");
					chooser.setApproveButtonText("SELECT");
					chooser.setCurrentDirectory(context.plugin().getLastExportDirectory());
					File selectedFile = chooser.getSelectedFile();
					chooser.dispose();
					if (selectedFile == null) {
						return;
					}
					lastDirectory = selectedFile;

					context.fsbComponent().runTask(monitor -> {
						try {
							JarDecompiler decompiler = new JarDecompiler(jarFSRL, selectedFile);
							decompiler.decompile(monitor);

							if (decompiler.getLog().hasMessages()) {
								Msg.showInfo(this, null, "Decompiling Jar " + jarFSRL.getName(),
									decompiler.getLog().toString());
							}
						}
						catch (Exception e) {
							FSUtilities.displayException(this, null, "Error Decompiling Jar",
								e.getMessage(), e);
						}
					});
				})
				.build()

		);
	}

}
