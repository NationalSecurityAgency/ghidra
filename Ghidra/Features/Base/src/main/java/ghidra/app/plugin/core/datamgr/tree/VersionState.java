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

import generic.theme.GIcon;
import ghidra.framework.data.DomainFileProxy;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import resources.MultiIcon;
import resources.icons.TranslateIcon;

/**
 * Class to keep track of version information. Used by the {@link ProgramArchiveNode} and the 
 * {@link ProjectArchiveNode}
 */
public class VersionState {
	//@formatter:off
	private static Icon CHECKED_OUT_ICON = new GIcon("icon.plugin.datatypes.tree.node.archive.file.checked.out");
	private static Icon CHECKED_OUT_EXCLUSIVE_ICON = new GIcon("icon.plugin.datatypes.tree.node.archive.file.checked.out.exclusive");
	private static Icon HIJACKED_ICON = new GIcon("icon.plugin.datatypes.tree.node.archive.file.hijacked");
	private static Icon READ_ONLY_ICON = new GIcon("icon.plugin.datatypes.tree.node.archive.file.read.only");
	private static Icon NOT_LATEST_CHECKED_OUT_ICON = new GIcon("icon.plugin.datatypes.tree.node.archive.file.checked.out.not.latest");
	//@formatter:on

	private boolean isChanged;
	private boolean isReadOnly;
	private boolean isHijacked;
	private boolean isCheckedOut;
	private boolean isCheckedOutExclusive;
	private boolean isVersioned;
	private int version;
	private int latestVersion;
	private DomainObject domainObject;
	private String domainFileInfoString;

	VersionState(DomainObject domainObject) {
		this.domainObject = domainObject;
		updateDomainFileInfo();
	}

	void updateDomainFileInfo() {
		DomainFile domainFile = domainObject.getDomainFile();
		DomainFile originalDomainFile = getOriginalDomainFile();

		isChanged = domainObject.isChanged();

		isReadOnly = domainFile.isReadOnly();

		isVersioned = originalDomainFile.isVersioned();

		// NOTE: DomainFileProxy may indicate version as DEFAULT_VERSION (-1) if latest version
		// was open read-only.  A specific version is only provided when that version was 
		// explicitly opened read-only.
		latestVersion = originalDomainFile.getLatestVersion();
		version = domainFile.getVersion();
		if (version == DomainFile.DEFAULT_VERSION && isVersioned && latestVersion > 0) {
			version = latestVersion; // default version tracks latest version
		}

		isHijacked = !isReadOnly && originalDomainFile.isHijacked();
		isCheckedOutExclusive = !isReadOnly && originalDomainFile.isCheckedOutExclusive();
		isCheckedOut = !isReadOnly && originalDomainFile.isCheckedOut();

		domainFileInfoString = createDomainFileInfoString();
	}

	/**
	 * {@return the original domain file associated with this archive node or 
	 * the same as {@link #getDomainFile()} if not opened from project storage}
	 */
	public DomainFile getOriginalDomainFile() {
		DomainFile domainFile = domainObject.getDomainFile();
		if (domainFile instanceof DomainFileProxy proxy) {
			DomainFile originalDomainFile = proxy.getOriginalDomainFile();
			if (originalDomainFile != null) {
				return originalDomainFile;
			}
		}
		return domainFile;
	}

	/**
	 * Returns an icon that overlays a given base icon with version state information.
	 * @param baseIcon the base icon to be decorated
	 * @return a new Icon that decorates a base icon with version state information
	 */
	public Icon getIcon(Icon baseIcon) {
		DtBackgroundIcon bgIcon = new DtBackgroundIcon(isVersioned);
		MultiIcon multiIcon = new MultiIcon(bgIcon);
		multiIcon.addIcon(baseIcon);

		if (isReadOnly) {
			multiIcon.addIcon(new TranslateIcon(READ_ONLY_ICON, 14, 3));
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

	private String createDomainFileInfoString() {
		String name = "";
		if (isHijacked) {
			name += " (hijacked)";
		}
		if (isVersioned && version != DomainFile.DEFAULT_VERSION) {
			if (version == latestVersion) {
				name += " (" + version + ")";
			}
			else {
				name += " (" + version + " of " + latestVersion + ")";
			}
		}
		if (!(domainObject instanceof Program) && isChanged) {
			name += " *";
		}

		return name;
	}

	public String getDomainObjectInfo() {
		return domainFileInfoString;
	}

}
