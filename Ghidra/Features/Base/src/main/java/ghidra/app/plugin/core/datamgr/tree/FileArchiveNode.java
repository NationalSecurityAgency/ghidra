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
import ghidra.program.model.dtarchive.FileDataTypeArchive;
import ghidra.util.HTMLUtilities;
import resources.MultiIcon;
import resources.icons.TranslateIcon;

/**
 * Nodes that represent FileDataTypeArchives
 */
public class FileArchiveNode extends ArchiveNode {
	private static Icon CLOSED_ICON = new GIcon("icon.plugin.datatypes.archive.file.closed");
	private static Icon OPEN_ICON = new GIcon("icon.plugin.datatypes.archive.file.open");

	private static Icon CHECKED_OUT_EXCLUSIVE_ICON =
		new GIcon("icon.plugin.datatypes.tree.node.archive.file.checked.out.exclusive");

	public FileArchiveNode(FileDataTypeArchive archive, DtFilterState filterState) {
		super(archive, filterState);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		DtBackgroundIcon bgIcon = new DtBackgroundIcon();
		MultiIcon multiIcon = new MultiIcon(bgIcon);
		Icon baseIcon = expanded ? OPEN_ICON : CLOSED_ICON;
		multiIcon.addIcon(baseIcon);
		if (archive.isChangeable()) {
			multiIcon.addIcon(new TranslateIcon(CHECKED_OUT_EXCLUSIVE_ICON, 8, -4));
		}

		return multiIcon;
	}

	@Override
	public String getToolTip() {
		ResourceFile file = ((FileDataTypeArchive) archive).getFile();
		String path = file != null ? file.getAbsolutePath() : "[Unsaved New Archive]";

		StringBuilder buf = new StringBuilder(HTMLUtilities.HTML);
		buf.append(HTMLUtilities.escapeHTML(path));
		buf.append(HTMLUtilities.BR);
		buf.append(getArchitectureDetails());
		buf.append(HTMLUtilities.HTML_CLOSE);
		return buf.toString();
	}

	@Override
	public FileDataTypeArchive getArchive() {
		return (FileDataTypeArchive) super.getArchive();
	}
}
