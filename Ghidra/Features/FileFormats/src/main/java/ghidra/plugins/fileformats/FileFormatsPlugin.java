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
package ghidra.plugins.fileformats;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.FilenameUtils;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.file.crypto.CryptoKeyFileTemplateWriter;
import ghidra.file.eclipse.AndroidProjectCreator;
import ghidra.file.formats.ios.prelink.PrelinkFileSystem;
import ghidra.file.jad.JadProcessWrapper;
import ghidra.file.jad.JarDecompiler;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.main.FrontEndable;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.plugins.fsbrowser.*;
import ghidra.plugins.fsbrowser.tasks.GFileSystemLoadKernelTask;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * A plugin that adds file format related actions to the file system browser.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "File format actions",
	description = "This plugin provides file format related actions to the File System Browser."
)
//@formatter:on
public class FileFormatsPlugin extends Plugin implements FrontEndable {

	private GhidraFileChooser chooserEclipse;
	private GhidraFileChooser chooserJarFolder;

	private List<DockingAction> actions = new ArrayList<>();

	public FileFormatsPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();

		actions.add(createEclipseProjectAction());
		actions.add(createDecompileJarAction());
		actions.add(createCryptoTemplateAction());
		actions.add(createLoadKernelAction());

		actions.forEach(action -> getTool().addAction(action));
	}

	@Override
	protected void dispose() {
		super.dispose();

		actions.forEach(action -> getTool().removeAction(action));
	}

	private boolean isAPK(FSRL fsrl) {
		return (fsrl != null) && (fsrl.getName() != null) &&
			"apk".equalsIgnoreCase(FilenameUtils.getExtension(fsrl.getName()));
	}

	private void doExportToEclipse(FSRL fsrl, File outputDirectory, TaskMonitor monitor) {
		try (RefdFile refdFile =
			FileSystemService.getInstance().getRefdFile(fsrl, monitor)) {
			AndroidProjectCreator creator =
				new AndroidProjectCreator(refdFile.file.getFSRL(), outputDirectory);
			creator.create(monitor);

			if (creator.getLog().hasMessages()) {
				Msg.showInfo(this, getTool().getActiveWindow(), "Export to Eclipse Project",
					creator.getLog().toString());
			}
		}
		catch (IOException | CancelledException e) {
			FSUtilities.displayException(this, getTool().getActiveWindow(),
				"Error Exporting to Eclipse", e.getMessage(), e);
		}
	}

	private DockingAction createEclipseProjectAction() {
		return new ActionBuilder("FSB Export Eclipse Project", this.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && JadProcessWrapper.isJadPresent() &&
					isAPK(ac.getFileFSRL()))
				.popupMenuPath("Export Eclipse Project")
				.popupMenuIcon(ImageManager.ECLIPSE)
				.popupMenuGroup("H")
				.onAction(
					ac -> {
						FSRL fsrl = ac.getFileFSRL();
						if (fsrl == null) {
							Msg.info(this, "Unable to export eclipse project");
							return;
						}

						if (chooserEclipse == null) {
							chooserEclipse = new GhidraFileChooser(null);
						}
						chooserEclipse.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
						chooserEclipse.setTitle("Select Eclipe Project Directory");
						chooserEclipse.setApproveButtonText("SELECT");
						chooserEclipse.setSelectedFile(null);
						File outputDirectory = chooserEclipse.getSelectedFile();
						if (outputDirectory == null) {
							return;
						}
						GTree gTree = ac.getTree();
						gTree.runTask(monitor -> doExportToEclipse(fsrl, outputDirectory, monitor));
					})
				.build();
	}

	private DockingAction createDecompileJarAction() {
		return new ActionBuilder("FSB Decompile JAR", this.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && JadProcessWrapper.isJadPresent() &&
					ac.getFileFSRL() != null)
				.popupMenuPath("Decompile JAR")
				.popupMenuIcon(ImageManager.JAR)
				.popupMenuGroup("J")
				.onAction(
					ac -> {
						FSRL jarFSRL = ac.getFileFSRL();
						if (jarFSRL == null) {
							return;
						}

						if (chooserJarFolder == null) {
							chooserJarFolder = new GhidraFileChooser(null);
						}
						chooserJarFolder.setFileSelectionMode(
							GhidraFileChooserMode.DIRECTORIES_ONLY);
						chooserJarFolder.setTitle("Select JAR Output Directory");
						chooserJarFolder.setApproveButtonText("SELECT");
						chooserJarFolder.setSelectedFile(null);
						File outputDirectory = chooserJarFolder.getSelectedFile();
						if (outputDirectory == null) {
							return;
						}
						GTree gTree = ac.getTree();
						gTree.runTask(monitor -> {
							try {
								JarDecompiler decompiler =
									new JarDecompiler(jarFSRL, outputDirectory);
								decompiler.decompile(monitor);

								if (decompiler.getLog().hasMessages()) {
									Msg.showInfo(this, gTree,
										"Decompiling Jar " + jarFSRL.getName(),
										decompiler.getLog().toString());
								}
							}
							catch (Exception e) {
								FSUtilities.displayException(this, gTree, "Error Decompiling Jar",
									e.getMessage(), e);
							}
						});
					})
				.build();
	}

	private DockingAction createCryptoTemplateAction() {
		return new ActionBuilder("FSB Create Crypto Key Template", this.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getSelectedNode() instanceof FSBRootNode &&
					ac.getFSRL(true) != null)
				.popupMenuPath("Create Crypto Key Template...")
				.popupMenuGroup("Z", "B")
				.onAction(
					ac -> {
						FSRL fsrl = ac.getFSRL(true);
						if (ac.getSelectedNode() instanceof FSBRootNode && fsrl != null) {
							createCryptoTemplate(fsrl, (FSBRootNode) ac.getSelectedNode());
						}
					})
				.build();
	}

	/**
	 * Creates a crypto key file template based on the specified files under the GTree node.
	 *
	 * @param fsrl FSRL of a child file of the container that the crypto will be associated with
	 * @param node GTree node with children that will be iterated
	 */
	private void createCryptoTemplate(FSRL fsrl, FSBRootNode node) {
		try {
			String fsContainerName = fsrl.getFS().getContainer().getName();
			CryptoKeyFileTemplateWriter writer = new CryptoKeyFileTemplateWriter(fsContainerName);
			if (writer.exists()) {
				int answer = OptionDialog.showYesNoDialog(getTool().getActiveWindow(),
					"WARNING!! Crypto Key File Already Exists",
					"WARNING!!" + "\n" + "The crypto key file already exists. " +
						"Are you really sure that you want to overwrite it?");
				if (answer == OptionDialog.NO_OPTION) {
					return;
				}
			}
			writer.open();
			try {
				// gTree.expandAll( node );
				writeFile(writer, node.getChildren());
			}
			finally {
				writer.close();
			}
		}
		catch (IOException e) {
			FSUtilities.displayException(this, getTool().getActiveWindow(),
				"Error writing crypt key file", e.getMessage(), e);
		}

	}

	private void writeFile(CryptoKeyFileTemplateWriter writer, List<GTreeNode> children)
			throws IOException {

		if (children == null || children.isEmpty()) {
			return;
		}
		for (GTreeNode child : children) {
			if (child instanceof FSBFileNode) {
				FSRL childFSRL = ((FSBFileNode) child).getFSRL();
				writer.write(childFSRL.getName());
			}
			else {
				writeFile(writer, child.getChildren());
			}
		}
	}

	private DockingAction createLoadKernelAction() {
		return new ActionBuilder("FSB Load iOS Kernel", this.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> {
					if (ac.isBusy()) {
						return false;
					}
					FSBRootNode rootNode = ac.getRootOfSelectedNode();
					return rootNode != null && rootNode.getFSRef() != null &&
						rootNode.getFSRef().getFilesystem() instanceof PrelinkFileSystem;
				})
				.popupMenuPath("Load iOS Kernel")
				.popupMenuIcon(ImageManager.iOS)
				.popupMenuGroup("I")
				.onAction(
					ac -> {
						FSRL fsrl = ac.getFSRL(true);
						List<FSRL> fileList = new ArrayList<>();

						if (fsrl != null) {
							FSBNode selectedNode = ac.getSelectedNode();
							if (selectedNode instanceof FSBRootNode) {
								for (GTreeNode childNode : ac.getSelectedNode().getChildren()) {
									if (childNode instanceof FSBNode) {
										FSBNode baseNode = (FSBNode) childNode;
										fileList.add(baseNode.getFSRL());
									}
								}
							}
							else if (selectedNode instanceof FSBFileNode ||
								selectedNode instanceof FSBDirNode) {
								fileList.add(fsrl);
							}
						}

						if (!fileList.isEmpty()) {
							if (OptionDialog.showYesNoDialog(null, "Load iOS Kernel?",
								"Performing this action will load the entire kernel and all KEXT files." +
									"\n" + "Do you want to continue?") == OptionDialog.YES_OPTION) {
								loadIOSKernel(fileList);
							}
						}
						else {
							getTool().setStatusInfo("Load iOS kernel -- nothing to do.");
						}
					})
				.build();
	}

	/**
	 * Loads or imports iOS kernel files.
	 *
	 * @param fileList List of {@link FSRL}s of the iOS kernel files.
	 */
	private void loadIOSKernel(List<FSRL> fileList) {
		ProgramManager pm = FSBUtils.getProgramManager(getTool(), true);
		if (pm != null) {
			TaskLauncher.launch(new GFileSystemLoadKernelTask(this, pm, fileList));
		}
	}
}
