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
package ghidra.framework.main.datatable;

import java.util.*;

import javax.swing.Icon;

import ghidra.framework.model.DomainFile;

public class DomainFileInfo {

	// TODO: should not hang onto DomainFile since it may not track changes anymore
	// Think of DomainFile like a File object

	private DomainFile domainFile;
	private String name;
	private String path;
	private Map<String, String> metadata;
	private Date modificationDate;
	private DomainFileType domainFileType;

	public DomainFileInfo(DomainFile domainFile) {
		this.domainFile = domainFile;
		this.path = domainFile.getParent().getPathname();
	}

	private String computeName() {
		String displayName = domainFile.getName();

		if (domainFile.isHijacked()) {
			displayName += " (hijacked)";
		}
		else if (domainFile.isVersioned()) {
			int versionNumber = domainFile.getVersion();
			String versionStr = "" + versionNumber;

			if (versionNumber < 0) {
				versionStr = "?";
			}

			if (domainFile.isCheckedOut()) {
				int latestVersionNumber = domainFile.getLatestVersion();
				String latestVersionStr = "" + latestVersionNumber;
				if (latestVersionNumber <= 0) {
					latestVersionStr = "?";
				}
				displayName += " (" + versionStr + " of " + latestVersionStr + ")";
				if (domainFile.modifiedSinceCheckout()) {
					displayName += "*";
				}
			}
			else {
				displayName += " (" + versionStr + ")";
			}
		}
		return displayName;
	}

	public synchronized String getDisplayName() {
		if (name == null) {
			name = computeName();
		}
		return name;
	}

	public synchronized String getPath() {
		if (path == null) {
			path = domainFile.getParent().getPathname();
		}
		return path;
	}

	public Icon getIcon() {
		return domainFile.getIcon(false);
	}

	public synchronized DomainFileType getDomainFileType() {
		if (domainFileType == null) {
			String contentType = domainFile.getContentType();
			Icon icon = domainFile.getIcon(false);
			boolean isVersioned = domainFile.isVersioned();
			domainFileType = new DomainFileType(contentType, icon, isVersioned);
		}
		return domainFileType;
	}

	public synchronized Date getModificationDate() {

		if (modificationDate == null) {
			modificationDate = getLastModifiedTime();
		}
		return modificationDate;
	}

	private Date getLastModifiedTime() {
		long lastModified = domainFile.getLastModifiedTime();
		if (lastModified != 0) {
			return new Date(lastModified);
		}
		return new Date();
	}

	private synchronized Map<String, String> getMetadata() {
		if (metadata == null) {
			metadata = domainFile.getMetadata();
			if (metadata == null) {
				metadata = new HashMap<String, String>();
			}
		}
		return metadata;
	}

	public DomainFile getDomainFile() {
		return domainFile;
	}

	public synchronized void clearMetaCache() {
		metadata = null;
		modificationDate = null;
		domainFileType = null;
		refresh();
	}

	public synchronized void refresh() {
		this.name = null;
		this.path = null;

	}

	public String getMetaDataValue(String key) {
		Map<String, String> meta = getMetadata();
		return meta.get(key);
	}

	public String getName() {
		return domainFile.getName();
	}

}
