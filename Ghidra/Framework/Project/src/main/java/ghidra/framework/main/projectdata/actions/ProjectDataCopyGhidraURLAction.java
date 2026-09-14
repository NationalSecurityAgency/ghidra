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
package ghidra.framework.main.projectdata.actions;

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.net.URL;

import org.apache.commons.collections4.CollectionUtils;

import docking.action.MenuData;
import docking.dnd.GClipboard;
import ghidra.framework.main.datatree.FrontEndProjectTreeContext;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.LinkFileInfo;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

public class ProjectDataCopyGhidraURLAction extends ProjectDataCopyCutBaseAction {

	public ProjectDataCopyGhidraURLAction(String owner, String group) {
		super("Copy GhidraURL", owner);
		setPopupMenuData(new MenuData(new String[] { "Copy GhidraURL" }, null, group));
		setHelpLocation(new HelpLocation("FrontEndPlugin", "Copy GhidraURL"));
	}

	@Override
	protected void actionPerformed(FrontEndProjectTreeContext context) {
		Clipboard clipboard = GClipboard.getSystemClipboard();
		
		try {
			if(CollectionUtils.isNotEmpty(context.getSelectedFiles())) {
				DomainFile df = context.getSelectedFiles().getFirst();
				LinkFileInfo linkInfo = df.getLinkInfo();
				if (linkInfo != null && linkInfo.isFolderLink()) {
					return; // folder-link not supported
				}
				URL url = df.getSharedProjectURL(null);
				if(url == null) {
					url = df.getLocalProjectURL(null);
				}
				if (url != null) {
					clipboard.setContents(new StringSelection(url.toString()), null);
				}
				else {
					Msg.showError(ProjectDataCopyGhidraURLAction.class, null,
						"Copy GhidraURL Failed",
						"Failed to create file URL for: " + df.getPathname());
				}
			}
		}
		catch (IllegalStateException ise) {
			// this can happen when other applications are accessing the system clipboard
			Msg.showError(ProjectDataCopyGhidraURLAction.class, null, "Unable to Access Clipboard",
				"Unable to perform cut/copy operation on the system clipboard.  The " +
					"clipboard may just be busy at this time. Please try again.");
		}
	}

	@Override
	protected boolean isEnabledForContext(FrontEndProjectTreeContext context) {
		if (context.hasExactlyOneFileOrFolder() && context.getFileCount() != 1) {
			return false;
		}
		DomainFile df = context.getSelectedFiles().getFirst();
		LinkFileInfo linkInfo = df.getLinkInfo();
		if (linkInfo != null && linkInfo.isFolderLink()) {
			return false;
		}
		return true;
	}
}
