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

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.SelectFromListDialog;
import ghidra.formats.gfilesystem.*;
import ghidra.plugins.fsbrowser.*;

public class ListMountedFSBFileHandler implements FSBFileHandler {

	private FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public List<DockingAction> createActions() {
		return List.of(new ActionBuilder("FSB List Mounted Filesystems", context.plugin().getName())
				.description("List Mounted Filesystems")
				.withContext(FSBActionContext.class)
				.enabledWhen(FSBActionContext::notBusy)
				.toolBarIcon(FSBIcons.LIST_MOUNTED)
				.toolBarGroup("ZZZZ")
				.popupMenuIcon(FSBIcons.LIST_MOUNTED)
				.popupMenuPath("List Mounted Filesystems")
				.popupMenuGroup("L")
				.onAction(ac -> {
					List<FSRL> sortedFSRLs = new ArrayList<>();
					sortedFSRLs.addAll(context.plugin().getCurrentlyOpenBrowsers());
					sortedFSRLs.sort((f1, f2) -> f1.toString().compareTo(f2.toString()));
					FSRL fsrl = SelectFromListDialog.selectFromList(sortedFSRLs,
						"Select filesystem", "Choose filesystem to view",
						f -> getPrettyFSRLString(f));

					if (fsrl != null) {
						context.plugin().showProvider(context.plugin().getProviderFor(fsrl));

					}
				})
				.build());
	}

	private String getPrettyFSRLString(FSRL fsrl) {
		FileSystemService fsService = context.fsService();
		LocalFileSystem localFS = fsService.getLocalFS();
		if (localFS.getRootDir().getFSRL().equals(fsrl)) {
			return "My Computer";
		}
		else if (fsrl.getNestingDepth() == 1) {
			return new File(fsrl.getPath()).getPath();
		}
		else {
			if (fsrl.getPath().equals("/")) {
				fsrl = fsrl.getFS();
			}
			String result = "";
			List<FSRL> fsrlParts = fsrl.split();
			for (int i = 0; i < fsrlParts.size(); i++) {
				FSRL part = fsrlParts.get(i);
				if (i == 0) {
					result = new File(part.getPath()).getPath();
				}
				else {
					if (part instanceof FSRLRoot) {
						// skip, will be last element
					}
					else {
						result += "|" + part.getPath();
					}
				}
			}
			return result;
		}
	}

}
