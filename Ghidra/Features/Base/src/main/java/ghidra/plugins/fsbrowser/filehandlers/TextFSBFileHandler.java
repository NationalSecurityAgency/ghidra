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

import java.awt.Component;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.plugins.fsbrowser.*;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class TextFSBFileHandler implements FSBFileHandler {
	public static final String FSB_VIEW_AS_TEXT = "FSB View As Text";

	private static final int MAX_TEXT_FILE_LEN = 64 * 1024;

	FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public boolean fileDefaultAction(FSBFileNode fileNode) {
		if (fileNode.getFileExtension().equalsIgnoreCase("txt")) {
			FSBComponentProvider fsbComponent = context.fsbComponent();
			fsbComponent.runTask(
				monitor -> doViewAsText(fileNode.getFSRL(), fsbComponent.getComponent(), monitor));
			return true;
		}
		return false;
	}

	@Override
	public List<DockingAction> createActions() {
		DockingAction action = new ActionBuilder(FSB_VIEW_AS_TEXT, context.plugin().getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getFileFSRL() != null)
				.popupMenuIcon(FSBIcons.VIEW_AS_TEXT)
				.popupMenuPath("View As", "Text")
				.popupMenuGroup("G")
				.onAction(ac -> {
					if (ac.getSelectedNode() instanceof FSBFileNode fileNode &&
						fileNode.getFSRL() != null) {
						ac.getTree()
								.runTask(monitor -> doViewAsText(fileNode.getFSRL(),
									ac.getSourceComponent(), monitor));
					}
				})
				.build();

		action.getPopupMenuData().setParentMenuGroup("C");
		return List.of(action);

	}

	void doViewAsText(FSRL fsrl, Component parent, TaskMonitor monitor) {
		try (ByteProvider fileBP = context.fsService().getByteProvider(fsrl, false, monitor)) {

			if (fileBP.length() > MAX_TEXT_FILE_LEN) {
				Msg.showInfo(this, context.fsbComponent().getComponent(), "View As Text Failed",
					"File too large to view as text inside Ghidra. " +
						"Please use the \"EXPORT\" action.");
				return;
			}

			try (InputStream is = fileBP.getInputStream(0)) {
				String text = FileUtilities.getText(is);
				Swing.runLater(() -> {
					new TextEditorComponentProvider(context.plugin(), fsrl.getName(), text);
				});
			}
		}
		catch (IOException | CancelledException e) {
			FSUtilities.displayException(this, parent, "Error Viewing Text File",
				"Error when trying to view text file %s".formatted(fsrl.getName()), e);
		}
	}

}
