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
package ghidra.framework.main.datatree;

import java.awt.Component;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DropTargetDropEvent;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import docking.widgets.tree.GTreeNode;
import ghidra.app.services.FileImporterService;
import ghidra.app.util.FileOpenDataFlavorHandler;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.Msg;

/**
 * A special handler to deal with files dragged from Linux to Ghidra.   This class does double
 * duty in that it opens files for DataTrees and for Tools (signaled via the interfaces it
 * implements).
 */
public final class LinuxFileUrlHandler implements DataTreeFlavorHandler, FileOpenDataFlavorHandler {

	@Override
	// This is for the DataFlavorHandler interface for handling node drops in DataTrees
	public void handle(PluginTool tool, DataTree dataTree, GTreeNode destinationNode,
			Object transferData, int dropAction) {

		DomainFolder folder = getDomainFolder(destinationNode);
		doImport(dataTree, transferData, tool, folder);
	}

	@Override
	// This is for the FileOpenDataFlavorHandler for handling file drops from Linux to a Tool
	public void handle(PluginTool tool, Object transferData, DropTargetDropEvent e, DataFlavor f) {

		DomainFolder folder = tool.getProject().getProjectData().getRootFolder();
		doImport(tool.getToolFrame(), transferData, tool, folder);
	}

	private void doImport(Component component, Object transferData, ServiceProvider sp,
			DomainFolder folder) {

		FileImporterService im = sp.getService(FileImporterService.class);
		if (im == null) {
			Msg.showError(this, component, "Could Not Import", "Could not find importer service.");
			return;
		}

		List<File> files = toFiles(transferData);
		if (files.isEmpty()) {
			return;
		}

		if (files.size() == 1 && files.get(0).isFile()) {
			im.importFile(folder, files.get(0));
		}
		else {
			im.importFiles(folder, files);
		}
	}

	private List<File> toFiles(Object transferData) {

		return toUrls(transferData, s -> {
			try {
				return new File(new URL(s).toURI());
			}
			catch (MalformedURLException e) {
				// this could be the case that this handler is attempting to process an arbitrary
				// String that is not actually a URL
				Msg.trace(this, "Not a URL: '" + s + "'", e);
				return null;
			}
			catch (Exception e) {
				Msg.error(this, "Unable to open dropped URL: '" + s + "'", e);
				return null;
			}
		});
	}

	private List<File> toUrls(Object transferData, Function<String, File> converter) {

		List<File> files = new ArrayList<>();
		String string = (String) transferData;
		String[] urls = string.split("\\n");
		for (String url : urls) {
			File file = converter.apply(url);
			if (file != null) {
				files.add(file);
			}
		}

		return files;
	}

	private DomainFolder getDomainFolder(GTreeNode destinationNode) {
		if (destinationNode instanceof DomainFolderNode) {
			return ((DomainFolderNode) destinationNode).getDomainFolder();
		}
		else if (destinationNode instanceof DomainFileNode) {
			DomainFolderNode parent = (DomainFolderNode) destinationNode.getParent();
			return parent.getDomainFolder();
		}
		return null;
	}
}
