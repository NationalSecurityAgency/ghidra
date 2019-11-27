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

import ghidra.app.plugin.core.datamgr.archive.DomainFileArchive;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.HTMLUtilities;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.TranslateIcon;

public class DomainFileArchiveNode extends ArchiveNode {

	private static ImageIcon CHECKED_OUT_ICON = ResourceManager.loadImage("images/check.png");
	private static ImageIcon CHECKED_OUT_EXCLUSIVE_ICON =
		ResourceManager.loadImage("images/checkex.png");
	private static ImageIcon HIJACKED_ICON = ResourceManager.loadImage("images/small_hijack.gif");
	private static ImageIcon READ_ONLY_ICON =
		ResourceManager.loadImage("images/user-busy.png", 10, 10);
	private static ImageIcon NOT_LATEST_CHECKED_OUT_ICON =
		ResourceManager.loadImage("images/checkNotLatest.gif");

	private boolean isChanged;
	private boolean isReadOnly;
	private boolean isHijacked;
	private boolean isCheckedOut;
	private boolean isCheckedOutExclusive;
	private boolean isVersioned;
	private int version;
	private int latestVersion;

	private String domainFileInfoString;

	public DomainFileArchiveNode(DomainFileArchive archive, ArrayPointerFilterState filterState) {
		super(archive, filterState);

		updateDomainFileInfo();
	}

	private void updateDomainFileInfo() {
		DomainObject domainObject = ((DomainFileArchive) archive).getDomainObject();
		DomainFile domainFile = ((DomainFileArchive) archive).getDomainFile();

		isChanged = domainObject.isChanged();
		isReadOnly = domainFile.isReadOnly();
		isHijacked = domainFile.isHijacked();
		isVersioned = domainFile.isVersioned();
		version = (isVersioned || !domainFile.canSave()) ? domainFile.getVersion()
				: DomainFile.DEFAULT_VERSION;
		isCheckedOutExclusive =
			(!isVersioned && domainObject.hasExclusiveAccess() && !isReadOnly) ||
				(isVersioned && domainFile.isCheckedOutExclusive());
		isCheckedOut = isCheckedOutExclusive || domainFile.isCheckedOut();

		latestVersion = domainFile.getLatestVersion();

		domainFileInfoString = createDomainFileInfoString();
	}

	private String createDomainFileInfoString() {
		DomainObject domainObject = ((DomainFileArchive) archive).getDomainObject();
		String name = "";
		if (isHijacked) {
			name += " (hijacked)";
		}
		else if (isVersioned) {
			if (version == latestVersion && !isCheckedOut) {
				name += " (" + version + ")";
			}
			else {
				name += " (" + version + " of " + latestVersion + ")";
			}
		}
		else if (version != DomainFile.DEFAULT_VERSION) {
			name += " @ " + version;
		}
		if (!(domainObject instanceof Program) && isChanged) {
			name += " *";
		}

		return name;
	}

	@Override
	public String getToolTip() {
		DomainFile file = ((DomainFileArchive) archive).getDomainFile();
		if (file != null) {
			return "<html>" + HTMLUtilities.escapeHTML(file.getPathname());
		}
		return "[Unsaved New Domain File Archive]";
	}

	@Override
	public boolean canDelete() {
		return false;
	}

	@Override
	public Icon getIcon(boolean expanded) {

		ImageIcon baseIcon = archive.getIcon(expanded);
		BackgroundIcon bgIcon = new BackgroundIcon(24, 16, isVersioned);
		MultiIcon multiIcon = new MultiIcon(bgIcon);
		multiIcon.addIcon(baseIcon);

		if (isReadOnly) {
			multiIcon.addIcon(new TranslateIcon(READ_ONLY_ICON, 6, 6));
		}
		else if (isHijacked) {
			multiIcon.addIcon(new TranslateIcon(HIJACKED_ICON, 8, -4));
		}
		else if (isCheckedOut) {
			if (isCheckedOutExclusive) {
				multiIcon.addIcon(new TranslateIcon(CHECKED_OUT_EXCLUSIVE_ICON, 8, -4));
			}
			else if (version < latestVersion) {
				multiIcon.addIcon(new TranslateIcon(NOT_LATEST_CHECKED_OUT_ICON, 8, -4));
			}
			else {
				multiIcon.addIcon(new TranslateIcon(CHECKED_OUT_ICON, 8, -4));
			}
		}

		return multiIcon;
	}

	protected String getDomainObjectInfo() {
		return domainFileInfoString;
	}

	public DomainFile getDomainFile() {
		return ((DomainFileArchive) archive).getDomainFile();
	}

	@Override
	public void nodeChanged() {
		super.nodeChanged();
		updateDomainFileInfo();
	}
}
