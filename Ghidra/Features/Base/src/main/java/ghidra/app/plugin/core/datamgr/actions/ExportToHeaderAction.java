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
package ghidra.app.plugin.core.datamgr.actions;

import java.io.*;
import java.lang.reflect.Constructor;
import java.util.*;
import java.util.Map.Entry;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.CategoryNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.task.*;

public class ExportToHeaderAction extends DockingAction {
	private static final String LAST_DATA_TYPE_EXPORT_DIRECTORY = "LAST_DATA_TYPE_EXPORT_DIRECTORY";

	private final DataTypeManagerPlugin plugin;

	public ExportToHeaderAction(DataTypeManagerPlugin plugin) {
		super("Export Data Types", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Export C Header..." }, null, "VeryLast"));

		setEnabled(true);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (!isValidNode(node)) {
				return false;
			}
		}
		return true;
	}

	private boolean isValidNode(GTreeNode node) {
		if (node instanceof CategoryNode) {
			CategoryNode categoryNode = (CategoryNode) node;
			return categoryNode.isEnabled();
		}
		else if (node instanceof DataTypeNode) {
			return true;
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DataTypesActionContext dtActionContext = (DataTypesActionContext) context;
		GTree gTree = (GTree) dtActionContext.getContextObject();
		Program program = dtActionContext.getProgram();
		if (program == null) {
			Msg.showError(this, gTree, "Archive Export Failed",
				"A suitable program must be open and activated before\n" +
					"an archive export may be performed.");
			return;
		}
		if (OptionDialog.showYesNoDialog(gTree, "Confirm Archive Export",
			"Export selected archive(s) using program " + program.getName() +
				"'s compiler specification?") != OptionDialog.YES_OPTION) {
			return;
		}
		exportToC(gTree, program.getDataTypeManager());
	}

	/**
	 * Writes the selection out to a file of the user's choosing.  One file will be written for
	 * each DataTypeManager in the selection.
	 * @param gTree The tree that contains the selected nodes.
	 */
	private void exportToC(GTree gTree, DataTypeManager programDataTypeMgr) {

		List<Class<? extends AnnotationHandler>> classes =
			ClassSearcher.getClasses(AnnotationHandler.class);

		List<AnnotationHandler> list = new ArrayList<>();
		Class<?>[] constructorArgumentTypes = {};
		for (Class<? extends AnnotationHandler> clazz : classes) {

			if (clazz == DefaultAnnotationHandler.class) {
				continue;
			}

			try {
				Constructor<?> constructor = clazz.getConstructor(constructorArgumentTypes);
				Object obj = constructor.newInstance();
				list.add(AnnotationHandler.class.cast(obj));
			}
			catch (Exception e) {
				Msg.showError(this, plugin.getTool().getToolFrame(), "Export Data Types",
					"Error creating " + clazz.getName() + "\n" + e.toString(), e);
			}
		}

		AnnotationHandler handler = null;
		if (!list.isEmpty()) {
			list.add(0, new DefaultAnnotationHandler());
			AnnotationHandlerDialog dlg = new AnnotationHandlerDialog(list);
			plugin.getTool().showDialog(dlg);
			if (!dlg.wasSuccessful()) {
				return;
			}
			handler = dlg.getHandler();
		}
		else {
			handler = new DefaultAnnotationHandler();
		}

		TreePath[] paths = gTree.getSelectionPaths();
		Map<DataTypeManager, List<DataType>> managersToDataTypesMap = new HashMap<>();

		for (TreePath path : paths) {
			addToManager(path, managersToDataTypesMap);
		}

		GhidraFileChooser fileChooser = new GhidraFileChooser(gTree);

		// filter the files if we can
		String[] fileExtensions = handler.getFileExtensions();
		if (fileExtensions.length > 0) {
			fileChooser.setFileFilter(
				new ExtensionFileFilter(fileExtensions, handler.getLanguageName() + " Files"));
		}

		Set<Entry<DataTypeManager, List<DataType>>> entrySet = managersToDataTypesMap.entrySet();
		for (Entry<DataTypeManager, List<DataType>> entry : entrySet) {
			DataTypeManager dataTypeManager = entry.getKey();
			File file = getFile(gTree, fileChooser, dataTypeManager, handler);
			if (file == null) {
				return; // user cancelled
			}

			List<DataType> dataTypeList = entry.getValue();
			new TaskLauncher(
				new DataTypeWriterTask(gTree, programDataTypeMgr, dataTypeList, handler, file),
				gTree);
		}
	}

	private class DataTypeWriterTask extends Task {

		private final DataTypeManager programDataTypeMgr;
		private final List<DataType> dataTypeList;
		private final AnnotationHandler handler;
		private final File file;
		private final GTree gTree;

		DataTypeWriterTask(GTree gTree, DataTypeManager programDataTypeMgr,
				List<DataType> dataTypeList, AnnotationHandler handler, File file) {
			super("Export Data Types", true, false, true);
			this.gTree = gTree;
			this.programDataTypeMgr = programDataTypeMgr;
			this.dataTypeList = dataTypeList;
			this.handler = handler;
			this.file = file;
		}

		@Override
		public void run(TaskMonitor monitor) {
			try {
				monitor.setMessage("Export to " + file.getName() + "...");
				PrintWriter writer = new PrintWriter(file);
				try {
					DataTypeWriter dataTypeWriter =
						new DataTypeWriter(programDataTypeMgr, writer, handler);
					dataTypeWriter.write(dataTypeList, monitor, false);
				}
				finally {
					writer.close();
				}
				plugin.getTool().setStatusInfo(
					"Successfully exported data type(s) to " + file.getAbsolutePath());
			}
			catch (CancelledException e) {
				// user cancelled; ignore
			}
			catch (IOException e) {
				Msg.showError(getClass(), gTree, "Export Data Types Failed",
					"Error exporting Data Types: " + e);
				return;
			}
		}
	}

	private void addToManager(TreePath path,
			Map<DataTypeManager, List<DataType>> managersToDataTypesMap) {
		Object last = path.getLastPathComponent();
		if (last instanceof DataTypeNode) {
			DataTypeNode node = (DataTypeNode) last;
			DataType dataType = node.getDataType();
			DataTypeManager dataTypeManager = dataType.getDataTypeManager();

			List<DataType> dataTypeList = managersToDataTypesMap.get(dataTypeManager);
			if (dataTypeList == null) {
				dataTypeList = new ArrayList<>();
				managersToDataTypesMap.put(dataTypeManager, dataTypeList);
			}

			dataTypeList.add(dataType);
		}
		else if (last instanceof CategoryNode) {
			CategoryNode node = (CategoryNode) last;
			List<GTreeNode> children = node.getChildren();
			for (GTreeNode cnode : children) {
				addToManager(cnode.getTreePath(), managersToDataTypesMap);
			}
		}
	}

	private File getFile(GTree gTree, GhidraFileChooser fileChooser,
			DataTypeManager dataTypeManager, AnnotationHandler handler) {

		fileChooser.setTitle("Select File For Export: " + dataTypeManager.getName());
		fileChooser.setSelectedFile(null);

		String defaultExtendsionSuffix = ".h";

		String lastDirSelected = Preferences.getProperty(LAST_DATA_TYPE_EXPORT_DIRECTORY);
		if (lastDirSelected != null) {
			File file = new File(lastDirSelected);
			if (file.exists()) {
				fileChooser.setCurrentDirectory(file);
			}
		}

		fileChooser.rescanCurrentDirectory(); // pick up any recently added archives
		File currentDirectory = fileChooser.getCurrentDirectory();
		File newFile =
			new File(currentDirectory, dataTypeManager.getName() + defaultExtendsionSuffix);
		fileChooser.setSelectedFile(newFile);

		// show the chooser
		File file = fileChooser.getSelectedFile();
		if (file == null) {
			return null;
		}

		boolean hasKnownExtension = false;
		String path = file.getAbsolutePath();

		String[] fileExtensions = handler.getFileExtensions();
		for (String element : fileExtensions) {
			if (path.toLowerCase().endsWith("." + element)) {
				hasKnownExtension = true;
			}
		}

		if (!hasKnownExtension) {
			// no user provided extension and we have a suggested value, so pick the first one
			file = new File(path + defaultExtendsionSuffix);
		}

		if (file.exists()) {
			if (OptionDialog.showYesNoDialog(gTree, "Overwrite Existing File?",
				"Do you want to overwrite the existing file \"" + file.getAbsolutePath() +
					"\"?") == OptionDialog.OPTION_TWO) {
				return null;
			}
		}

		// save the directory off for the next export
		Preferences.setProperty(LAST_DATA_TYPE_EXPORT_DIRECTORY, file.getAbsolutePath());

		return file;
	}
}
