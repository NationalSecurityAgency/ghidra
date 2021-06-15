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

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
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

	private DockingAction createEclipseProjectAction() {

		FSBAction action = new FSBAction("Export Eclipse Project", this) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (context instanceof FSBActionContext) {
					FSBActionContext fsbContext = (FSBActionContext) context;
					FSRL fsrl = FSBUtils.getFileFSRLFromContext(context);
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
					fsbContext.getTree()
							.runTask(
								monitor -> doExportToEclipse(fsrl, outputDirectory, monitor));
				}
			}

			private void doExportToEclipse(FSRL fsrl, File outputDirectory, TaskMonitor monitor) {
				try (RefdFile refdFile =
					FileSystemService.getInstance().getRefdFile(fsrl, monitor)) {
					AndroidProjectCreator creator =
						new AndroidProjectCreator(refdFile.file, outputDirectory);
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

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (JadProcessWrapper.isJadPresent() && (context instanceof FSBActionContext)) {
					FSBActionContext fsbContext = (FSBActionContext) context;
					FSRL fsrl = FSBUtils.getFileFSRLFromContext(context);
					return !fsbContext.getTree().isBusy() && (fsrl != null) &&
						(fsrl.getName() != null) &&
						("apk".equalsIgnoreCase(FilenameUtils.getExtension(fsrl.getName())));
				}
				return false;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return context instanceof FSBActionContext;
			}
		};
		action.setPopupMenuData(
			new MenuData(new String[] { action.getMenuText() }, ImageManager.ECLIPSE, "H"));
		action.setEnabled(true);
		return action;
	}

	private DockingAction createDecompileJarAction() {

		FSBAction action = new FSBAction("Decompile JAR", this) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (context instanceof FSBActionContext) {
					FSBActionContext fsbContext = (FSBActionContext) context;
					FSRL jarFSRL = FSBUtils.getFileFSRLFromContext(context);
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
					GTree gTree = fsbContext.getTree();
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
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (JadProcessWrapper.isJadPresent() && (context instanceof FSBActionContext)) {
					FSBActionContext fsbContext = (FSBActionContext) context;
					FSRL fsrl = FSBUtils.getFileFSRLFromContext(context);
					return !fsbContext.getTree().isBusy() && (fsrl != null) &&
						JarDecompiler.isJarFilename(fsrl.getName());
				}
				return false;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return context instanceof FSBActionContext;
			}

		};
		action.setPopupMenuData(
			new MenuData(new String[] { action.getMenuText() }, ImageManager.JAR, "J"));
		action.setEnabled(true);
		return action;
	}

	private DockingAction createCryptoTemplateAction() {
		FSBAction action = new FSBAction("Create Crypto Key Template", this) {
			@Override
			public void actionPerformed(ActionContext context) {
				FSRL fsrl = FSBUtils.getFSRLFromContext(context, true);
				if (context.getContextObject() instanceof FSBRootNode && fsrl != null) {
					createCryptoTemplate(fsrl, (FSBRootNode) context.getContextObject());
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (context instanceof FSBActionContext) {
					FSBActionContext fsbContext = (FSBActionContext) context;
					FSRL fsrl = FSBUtils.getFSRLFromContext(context, true);
					return !fsbContext.getTree().isBusy() && (fsrl != null) &&
						(context.getContextObject() instanceof FSBRootNode);
				}
				return false;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return context instanceof FSBActionContext;
			}
		};
		action.setPopupMenuData(new MenuData(new String[] { action.getMenuText() + "..." },
			ImageManager.KEY, "Z", MenuData.NO_MNEMONIC, "B"));
		action.setEnabled(true);
		return action;
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
		FSBAction action = new FSBAction("Load iOS Kernel", this) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (context instanceof FSBActionContext) {
					FSBActionContext fsbContext = (FSBActionContext) context;
					Object contextObject = fsbContext.getContextObject();

					FSRL fsrl = FSBUtils.getFSRLFromContext(context, true);
					List<FSRL> fileList = new ArrayList<>();

					if (fsrl != null) {
						if (contextObject instanceof FSBRootNode) {
							List<GTreeNode> children = ((FSBRootNode) contextObject).getChildren();
							for (GTreeNode childNode : children) {
								if (childNode instanceof FSBNode) {
									FSBNode baseNode = (FSBNode) childNode;
									fileList.add(baseNode.getFSRL());
								}
							}
						}
						else if (contextObject instanceof FSBFileNode ||
							contextObject instanceof FSBDirNode) {
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
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (context instanceof FSBActionContext) {
					FSBActionContext fsbContext = (FSBActionContext) context;
					if (fsbContext.getTree().isBusy()) {
						return false;
					}
					Object contextObject = context.getContextObject();
					if (contextObject instanceof FSBFileNode ||
						contextObject instanceof FSBDirNode) {
						contextObject = FSBUtils.getNodesRoot((FSBNode) contextObject);
					}
					if (contextObject instanceof FSBRootNode) {
						FSBRootNode node = (FSBRootNode) contextObject;
						return node.getFSRef() != null &&
							node.getFSRef().getFilesystem() instanceof PrelinkFileSystem;
					}
				}
				return false;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return context instanceof FSBActionContext;
			}
		};

		action.setPopupMenuData(
			new MenuData(new String[] { action.getMenuText() }, ImageManager.iOS, "I"));
		action.setEnabled(true);
		return action;
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
