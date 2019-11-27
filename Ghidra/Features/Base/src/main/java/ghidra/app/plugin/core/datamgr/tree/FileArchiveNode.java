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
import javax.swing.ImageIcon;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.datamgr.archive.FileArchive;
import ghidra.util.HTMLUtilities;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.TranslateIcon;

public class FileArchiveNode extends ArchiveNode {

	private static ImageIcon CHECKED_OUT_EXCLUSIVE_ICON =
		ResourceManager.loadImage("images/checkex.png");

	FileArchive fileArchive; // casted reference for easy access

	public FileArchiveNode(FileArchive archive, ArrayPointerFilterState filterState) {
		super(archive, filterState);
		this.fileArchive = archive;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		BackgroundIcon bgIcon = new BackgroundIcon(24, 16, false);
		MultiIcon multiIcon = new MultiIcon(bgIcon);
		boolean hasWriteLock = fileArchive.hasWriteLock();
		ImageIcon baseIcon = fileArchive.getIcon(expanded);
		multiIcon.addIcon(baseIcon);
		if (hasWriteLock) {
			multiIcon.addIcon(new TranslateIcon(CHECKED_OUT_EXCLUSIVE_ICON, 8, -4));
		}
		return multiIcon;
	}

	@Override
	public String getToolTip() {
		ResourceFile file = fileArchive.getFile();
		if (file != null) {
			return "<html>" + HTMLUtilities.escapeHTML(file.getAbsolutePath());
		}
		return "[Unsaved New Archive]";
	}

	public boolean hasWriteLock() {
		return fileArchive.hasWriteLock();
	}

	/**
	 * Overridden to avoid path conflicts that arise in CategoryNode.equals()
	 *
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (getClass() != o.getClass()) {
			return false;
		}

		if (super.equals(o)) {
			ResourceFile myFile = fileArchive.getFile();
			ResourceFile otherFile = ((FileArchiveNode) o).fileArchive.getFile();
			return myFile.equals(otherFile);
		}
		return false;
	}

}
