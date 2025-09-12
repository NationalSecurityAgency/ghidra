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
package ghidra.framework.data;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;

import javax.help.UnsupportedOperationException;
import javax.swing.Icon;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.store.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * {@code LinkedGhidraFile} corresponds to a {@link DomainFile} contained within a
 * {@link LinkedGhidraSubFolder}.
 */
class LinkedGhidraFile implements LinkedDomainFile {

	private final LinkedGhidraSubFolder parent;
	private final String fileName;
	private final DomainFile realDomainFile;
	private final LinkFileInfo linkInfo;

	LinkedGhidraFile(LinkedGhidraSubFolder parent, DomainFile realDomainFile) {
		this.parent = parent;
		this.fileName = realDomainFile.getName();
		this.realDomainFile = realDomainFile;
		this.linkInfo = realDomainFile.isLink() ? new LinkedFileLinkInfo() : null;
	}

	@Override
	public DomainFile getRealFile() throws IOException {
		return parent.getLinkedFile(fileName);
	}

	@Override
	public DomainFolder getParent() {
		return parent;
	}

	@Override
	public String getName() {
		return fileName;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof LinkedGhidraFile other)) {
			return false;
		}
		return fileName.equals(other.fileName) && parent.equals(other.parent);
	}

	@Override
	public int hashCode() {
		return getPathname().hashCode();
	}

	@Override
	public int compareTo(DomainFile df) {
		return fileName.compareToIgnoreCase(df.getName());
	}

	@Override
	public boolean exists() {
		DomainFile df = parent.getLinkedFileNoError(fileName);
		return df != null && df.exists();
	}

	@Override
	public String getFileID() {
		return realDomainFile.getFileID();
	}

	@Override
	public DomainFile setName(String newName) throws InvalidNameException, IOException {
		String name = getRealFile().setName(newName).getName();
		return parent.getFile(name);
	}

	@Override
	public String getPathname() {
		// pathname within project containing folder-link 
		// getParent() may return a non-linked folder
		String path = getParent().getPathname();
		if (path.length() != FileSystem.SEPARATOR.length()) {
			path += FileSystem.SEPARATOR;
		}
		path += fileName;
		return path;
	}

	@Override
	public URL getSharedProjectURL(String ref) {
		URL folderURL = parent.getSharedProjectURL();
		if (GhidraURL.isServerRepositoryURL(folderURL)) {
			try {
				String spec = fileName;
				if (!StringUtils.isEmpty(ref)) {
					spec += "#" + ref;
				}
				return new URL(folderURL, spec);
			}
			catch (MalformedURLException e) {
				// ignore
			}
		}
		return null;
	}

	@Override
	public URL getLocalProjectURL(String ref) {
		ProjectLocator projectLocator = parent.getProjectLocator();
		if (!projectLocator.isTransient()) {
			return GhidraURL.makeURL(projectLocator, getPathname(), ref);
		}
		return null;
	}

	@Override
	public ProjectLocator getProjectLocator() {
		// TODO: Should this reflect real project?
		return parent.getProjectLocator();
	}

	@Override
	public String getContentType() {
		return realDomainFile.getContentType();
	}

	@Override
	public Class<? extends DomainObject> getDomainObjectClass() {
		return realDomainFile.getDomainObjectClass();
	}

	@Override
	public ChangeSet getChangesByOthersSinceCheckout() throws VersionException, IOException {
		return getRealFile().getChangesByOthersSinceCheckout();
	}

	@Override
	public DomainObject getDomainObject(Object consumer, boolean okToUpgrade, boolean okToRecover,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {
		return getRealFile().getDomainObject(consumer, okToUpgrade, okToRecover, monitor);
	}

	@Override
	public DomainObject getOpenedDomainObject(Object consumer) {
		return realDomainFile.getOpenedDomainObject(consumer);
	}

	@Override
	public DomainObject getReadOnlyDomainObject(Object consumer, int version, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		return getRealFile().getReadOnlyDomainObject(consumer, version, monitor);
	}

	@Override
	public DomainObject getImmutableDomainObject(Object consumer, int version, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		return getRealFile().getImmutableDomainObject(consumer, version, monitor);
	}

	@Override
	public void save(TaskMonitor monitor) throws IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean canSave() {
		return false;
	}

	@Override
	public boolean canRecover() {
		return false;
	}

	@Override
	public boolean takeRecoverySnapshot() throws IOException {
		return true;
	}

	@Override
	public boolean isInWritableProject() {
		// TODO: Is this correct?
		return parent.isInWritableProject();
	}

	@Override
	public long getLastModifiedTime() {
		return realDomainFile.getLastModifiedTime();
	}

	@Override
	public Icon getIcon(boolean disabled) {
		return realDomainFile.getIcon(disabled);
	}

	@Override
	public boolean isCheckedOut() {
		return realDomainFile.isCheckedOut();
	}

	@Override
	public boolean isCheckedOutExclusive() {
		return realDomainFile.isCheckedOutExclusive();
	}

	@Override
	public boolean modifiedSinceCheckout() {
		return realDomainFile.modifiedSinceCheckout();
	}

	@Override
	public boolean canCheckout() {
		return realDomainFile.canCheckout();
	}

	@Override
	public boolean canCheckin() {
		return realDomainFile.canCheckin();
	}

	@Override
	public boolean canMerge() {
		return realDomainFile.canMerge();
	}

	@Override
	public boolean canAddToRepository() {
		return realDomainFile.canAddToRepository();
	}

	@Override
	public void setReadOnly(boolean state) throws IOException {
		getRealFile().setReadOnly(state);
	}

	@Override
	public boolean isReadOnly() {
		return realDomainFile.isReadOnly();
	}

	@Override
	public boolean isVersioned() {
		return realDomainFile.isVersioned();
	}

	@Override
	public boolean isHijacked() {
		return realDomainFile.isHijacked();
	}

	@Override
	public int getLatestVersion() {
		return realDomainFile.getLatestVersion();
	}

	@Override
	public boolean isLatestVersion() {
		return realDomainFile.isLatestVersion();
	}

	@Override
	public int getVersion() {
		return realDomainFile.getVersion();
	}

	@Override
	public Version[] getVersionHistory() throws IOException {
		DomainFile df = getRealFile();
		return df != null ? df.getVersionHistory() : new Version[0];
	}

	@Override
	public void addToVersionControl(String comment, boolean keepCheckedOut, TaskMonitor monitor)
			throws IOException, CancelledException {
		getRealFile().addToVersionControl(comment, keepCheckedOut, monitor);
	}

	@Override
	public boolean checkout(boolean exclusive, TaskMonitor monitor)
			throws IOException, CancelledException {
		return getRealFile().checkout(exclusive, monitor);
	}

	@Override
	public void checkin(CheckinHandler checkinHandler, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {
		getRealFile().checkin(checkinHandler, monitor);
	}

	@Override
	public void merge(boolean okToUpgrade, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {
		getRealFile().merge(okToUpgrade, monitor);
	}

	@Override
	public void undoCheckout(boolean keep) throws IOException {
		getRealFile().undoCheckout(keep);
	}

	@Override
	public void undoCheckout(boolean keep, boolean force) throws IOException {
		getRealFile().undoCheckout(keep, force);
	}

	@Override
	public void terminateCheckout(long checkoutId) throws IOException {
		getRealFile().terminateCheckout(checkoutId);
	}

	@Override
	public ItemCheckoutStatus[] getCheckouts() throws IOException {
		return getRealFile().getCheckouts();
	}

	@Override
	public ItemCheckoutStatus getCheckoutStatus() throws IOException {
		return getRealFile().getCheckoutStatus();
	}

	@Override
	public void delete() throws IOException {
		getRealFile().delete();
	}

	@Override
	public void delete(int version) throws IOException {
		getRealFile().delete(version);
	}

	@Override
	public DomainFile moveTo(DomainFolder newParent) throws IOException {
		return getRealFile().moveTo(newParent);
	}

	@Override
	public DomainFile copyTo(DomainFolder newParent, TaskMonitor monitor)
			throws IOException, CancelledException {
		return getRealFile().copyTo(newParent, monitor);
	}

	@Override
	public DomainFile copyVersionTo(int version, DomainFolder destFolder, TaskMonitor monitor)
			throws IOException, CancelledException {
		return getRealFile().copyVersionTo(version, destFolder, monitor);
	}

	@Override
	public DomainFile copyToAsLink(DomainFolder newParent, boolean relative) throws IOException {
		return getRealFile().copyToAsLink(newParent, relative);
	}

	@Override
	public boolean isLinkingSupported() {
		return realDomainFile.isLinkingSupported();
	}

	@Override
	public List<?> getConsumers() {
		return List.of();
	}

	@Override
	public boolean isChanged() {
		return realDomainFile.isChanged();
	}

	@Override
	public boolean isOpen() {
		return false; // real file may be but this is not
	}

	@Override
	public boolean isBusy() {
		return false; // real file may be but this is not
	}

	@Override
	public void packFile(File file, TaskMonitor monitor) throws IOException, CancelledException {
		getRealFile().packFile(file, monitor);
	}

	@Override
	public Map<String, String> getMetadata() {
		return realDomainFile.getMetadata();
	}

	@Override
	public long length() throws IOException {
		return realDomainFile.length();
	}

	@Override
	public boolean isLink() {
		return linkInfo != null;
	}

	@Override
	public LinkFileInfo getLinkInfo() {
		return linkInfo;
	}

	private class LinkedFileLinkInfo implements LinkFileInfo {

		@Override
		public DomainFile getFile() {
			return LinkedGhidraFile.this;
		}

		@Override
		public LinkedGhidraFolder getLinkedFolder() {
			try {
				return FolderLinkContentHandler.getLinkedFolder(LinkedGhidraFile.this);
			}
			catch (IOException e) {
				// Ignore
			}
			return null;
		}

		@Override
		public String getLinkPath() {
			return realDomainFile.getLinkInfo().getLinkPath();
		}

		@Override
		public String getAbsoluteLinkPath() throws IOException {
			return realDomainFile.getLinkInfo().getAbsoluteLinkPath();
		}

	}

	@Override
	public String getLinkedPathname() {
		return parent.getLinkedPathname(fileName);
	}

	@Override
	public String toString() {
		return getPathname() + "->" + realDomainFile.getPathname();
	}

}
