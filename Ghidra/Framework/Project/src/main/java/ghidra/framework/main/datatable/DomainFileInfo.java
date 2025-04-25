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

import ghidra.framework.data.LinkHandler;
import ghidra.framework.data.LinkHandler.LinkStatus;
import ghidra.framework.main.BrokenLinkIcon;
import ghidra.framework.main.datatree.DomainFileNode;
import ghidra.framework.model.DomainFile;

public class DomainFileInfo {

	private DomainFile domainFile;
	private String name;
	private String path;
	private Map<String, String> metadata;
	private Date modificationDate;
	private DomainFileType domainFileType;
	private Boolean isBrokenLink;
	private String toolTipText;

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

	public synchronized DomainFileType getDomainFileType() {
		if (domainFileType == null) {
			checkStatus();
			String contentType = domainFile.getContentType();
			Icon icon = domainFile.getIcon(false);
			if (isBrokenLink) {
				icon = new BrokenLinkIcon(icon);
			}
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
		refresh();
	}

	public synchronized void refresh() {
		domainFileType = null;
		isBrokenLink = null;
		toolTipText = null;
		name = null;
		path = null;
	}

	public String getMetaDataValue(String key) {
		Map<String, String> meta = getMetadata();
		return meta.get(key);
	}

	public String getName() {
		return domainFile.getName();
	}

	private void checkStatus() {
		if (isBrokenLink == null) {
			isBrokenLink = false;
			List<String> linkErrors = null;
			if (domainFile.isLink()) {
				List<String> errors = new ArrayList<>();
				LinkStatus linkStatus =
					LinkHandler.getLinkFileStatus(domainFile, msg -> errors.add(msg));
				isBrokenLink = (linkStatus == LinkStatus.BROKEN);
				if (isBrokenLink) {
					linkErrors = errors;
				}
			}
			toolTipText = DomainFileNode.getToolTipText(domainFile, linkErrors);
		}
	}

	public String getToolTip() {
		checkStatus();
		return toolTipText;
	}

}
