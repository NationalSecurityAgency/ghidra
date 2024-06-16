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
package ghidra.app.plugin.core.datamgr.tree;

import javax.swing.Icon;

import generic.jar.ResourceFile;
import generic.theme.GIcon;
import ghidra.app.plugin.core.datamgr.archive.FileArchive;
import resources.MultiIcon;
import resources.icons.TranslateIcon;

public class FileArchiveNode extends ArchiveNode {

	private static Icon CHECKED_OUT_EXCLUSIVE_ICON =
		new GIcon("icon.plugin.datatypes.tree.node.archive.file.checked.out.exclusive");

	FileArchive fileArchive; // casted reference for easy access

	public FileArchiveNode(FileArchive archive, ArrayPointerFilterState filterState) {
		super(archive, filterState);
		this.fileArchive = archive;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		DtBackgroundIcon bgIcon = new DtBackgroundIcon();
		MultiIcon multiIcon = new MultiIcon(bgIcon);
		boolean hasWriteLock = fileArchive.hasWriteLock();
		Icon baseIcon = fileArchive.getIcon(expanded);
		multiIcon.addIcon(baseIcon);
		if (hasWriteLock) {
			multiIcon.addIcon(new TranslateIcon(CHECKED_OUT_EXCLUSIVE_ICON, 8, -4));
		}

		// TODO: add program architecture state

		return multiIcon;
	}

	@Override
	public String getToolTip() {
		ResourceFile file = fileArchive.getFile();
		return buildTooltip(file != null ? file.getAbsolutePath() : "[Unsaved New Archive]");
	}

	public boolean hasWriteLock() {
		return fileArchive.hasWriteLock();
	}
}
