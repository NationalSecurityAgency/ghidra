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
import java.util.List;
import java.util.Set;

import javax.swing.*;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.label.GIconLabel;
import ghidra.formats.gfilesystem.*;
import ghidra.plugins.fsbrowser.*;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ImageFSBFileHandler implements FSBFileHandler {
	public static final String FSB_VIEW_AS_IMAGE = "FSB View As Image";

	private static final Set<String> COMMON_IMAGE_EXTENSIONS = Set.of("png", "jpg", "jpeg", "gif");

	private FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public boolean fileDefaultAction(FSBFileNode fileNode) {
		if (COMMON_IMAGE_EXTENSIONS.contains(fileNode.getFileExtension().toLowerCase())) {
			FSBComponentProvider fsbComponent = context.fsbComponent();
			fsbComponent.runTask(monitor -> doViewAsImage(fileNode.getFSRL(),
				fsbComponent.getComponent(), monitor));
			return true;
		}
		return false;
	}

	@Override
	public List<DockingAction> createActions() {
		DockingAction action = new ActionBuilder(FSB_VIEW_AS_IMAGE, context.plugin().getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getFileFSRL() != null)
				.popupMenuIcon(FSBIcons.VIEW_AS_IMAGE)
				.popupMenuPath("View As", "Image")
				.popupMenuGroup("G")
				.onAction(ac -> {
					FSRL fsrl = ac.getFileFSRL();
					if (fsrl != null) {
						ac.getTree()
								.runTask(monitor -> doViewAsImage(fsrl, ac.getSourceComponent(),
									monitor));
					}
				})
				.build();
		action.getPopupMenuData().setParentMenuGroup("C");

		return List.of(action);
	}

	void doViewAsImage(FSRL fsrl, Component parent, TaskMonitor monitor) {

		try (RefdFile refdFile = context.fsService().getRefdFile(fsrl, monitor)) {

			Icon icon = GIconProvider.getIconForFile(refdFile.file, monitor);
			if (icon == null) {
				Msg.showError(this, parent, "Unable To View Image",
					"Unable to view " + fsrl.getName() + " as an image.");
				return;
			}
			Swing.runLater(() -> {
				JLabel label = new GIconLabel(icon);
				JOptionPane.showMessageDialog(null, label, "Image Viewer: " + fsrl.getName(),
					JOptionPane.INFORMATION_MESSAGE);
			});
		}
		catch (IOException | CancelledException e) {
			FSUtilities.displayException(this, parent, "Error Viewing Image File", e.getMessage(),
				e);
		}
	}

}
