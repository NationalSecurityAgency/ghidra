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

import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DropTargetDropEvent;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import docking.widgets.tree.GTreeNode;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

/**
 * A handler to facilitate drag-n-drop for a Linux URL-based file list which is dropped
 * onto the Project data tree or a running Ghidra Tool (see {@link #linuxFileUrlFlavor}).
 */
public final class LinuxFileUrlHandler extends AbstractFileListFlavorHandler {

	/**
	 * Linux URL-based file list {@link DataFlavor} to be used during handler registration
	 * using {@link DataTreeDragNDropHandler#addActiveDataFlavorHandler}.
	 */
	public static final DataFlavor linuxFileUrlFlavor =
		new DataFlavor("application/x-java-serialized-object;class=java.lang.String",
			"String file URL");

	@Override
	// This is for the FileOpenDataFlavorHandler for handling file drops from Linux to a Tool
	public void handle(PluginTool tool, Object transferData, DropTargetDropEvent e, DataFlavor f) {
		List<File> files = toFiles(transferData);
		doImport(null, files, tool, tool.getToolFrame());
	}

	@Override
	// This is for the DataFlavorHandler interface for handling node drops in DataTrees
	public boolean handle(PluginTool tool, DataTree dataTree, GTreeNode destinationNode,
			Object transferData, int dropAction) {
		List<File> files = toFiles(transferData);
		if (files.isEmpty()) {
			return false;
		}
		doImport(getDomainFolder(destinationNode), files, tool, dataTree);
		return true;
	}

	private List<File> toFiles(Object transferData) {

		return toFiles(transferData, s -> {
			try {
				return new File(new URL(s.replaceAll(" ", "%20")).toURI()); // fixup spaces
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

	private List<File> toFiles(Object transferData, Function<String, File> urlToFileConverter) {

		List<File> files = new ArrayList<>();
		String string = (String) transferData;
		String[] urls = string.split("\\n");
		for (String url : urls) {
			File file = urlToFileConverter.apply(url);
			if (file != null) {
				files.add(file);
			}
		}
		return files;
	}
}
