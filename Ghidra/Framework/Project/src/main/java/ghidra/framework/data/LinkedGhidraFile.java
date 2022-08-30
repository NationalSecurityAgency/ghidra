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

import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.store.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * {@code LinkedGhidraFile} corresponds to a {@link DomainFile} contained within a
 * {@link LinkedGhidraFolder}.
 */
class LinkedGhidraFile implements LinkedDomainFile {

	private final LinkedGhidraSubFolder parent;
	private final String fileName;

	LinkedGhidraFile(LinkedGhidraSubFolder parent, String fileName) {
		this.parent = parent;
		this.fileName = fileName;
	}

	@Override
	public DomainFile getLinkedFile() throws IOException {
		return parent.getLinkedFile(fileName);
	}

	private DomainFile getLinkedFileNoError() {
		return parent.getLinkedFileNoError(fileName);
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
	public int compareTo(DomainFile df) {
		return fileName.compareToIgnoreCase(df.getName());
	}

	@Override
	public boolean exists() {
		return getLinkedFileNoError() != null;
	}

	@Override
	public String getFileID() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.getFileID() : null;
	}

	@Override
	public DomainFile setName(String newName) throws InvalidNameException, IOException {
		throw new ReadOnlyException("linked file is read only");
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
	public URL getSharedProjectURL() {
		URL folderURL = parent.getSharedProjectURL();
		if (GhidraURL.isServerRepositoryURL(folderURL)) {
			// Direct URL construction done so that ghidra protocol 
			// extension may be supported
			try {
				return new URL(folderURL.toExternalForm() + fileName);
			}
			catch (MalformedURLException e) {
				// ignore
			}
		}
		return null;
	}

	@Override
	public ProjectLocator getProjectLocator() {
		return parent.getProjectLocator();
	}

	@Override
	public String getContentType() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.getContentType() : ContentHandler.UNKNOWN_CONTENT;
	}

	@Override
	public Class<? extends DomainObject> getDomainObjectClass() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.getDomainObjectClass() : DomainObject.class;
	}

	@Override
	public ChangeSet getChangesByOthersSinceCheckout() throws VersionException, IOException {
		return null;
	}

	@Override
	public DomainObject getDomainObject(Object consumer, boolean okToUpgrade, boolean okToRecover,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {
		return getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor);
	}

	@Override
	public DomainObject getOpenedDomainObject(Object consumer) {
		return null;
	}

	@Override
	public DomainObject getReadOnlyDomainObject(Object consumer, int version, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		return getLinkedFile().getReadOnlyDomainObject(consumer, version, monitor);
	}

	@Override
	public DomainObject getImmutableDomainObject(Object consumer, int version, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		return getLinkedFile().getImmutableDomainObject(consumer, version, monitor);
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
		return false; // While project may be writeable this folder/file is not
	}

	@Override
	public long getLastModifiedTime() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.getLastModifiedTime() : 0;
	}

	@Override
	public Icon getIcon(boolean disabled) {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.getIcon(disabled) : UNSUPPORTED_FILE_ICON;
	}

	@Override
	public boolean isCheckedOut() {
		return false;
	}

	@Override
	public boolean isCheckedOutExclusive() {
		return false;
	}

	@Override
	public boolean modifiedSinceCheckout() {
		return false;
	}

	@Override
	public boolean canCheckout() {
		return false;
	}

	@Override
	public boolean canCheckin() {
		return false;
	}

	@Override
	public boolean canMerge() {
		return false;
	}

	@Override
	public boolean canAddToRepository() {
		return false;
	}

	@Override
	public void setReadOnly(boolean state) throws IOException {
		// ignore
	}

	@Override
	public boolean isReadOnly() {
		return true; // not reflected by icon
	}

	@Override
	public boolean isVersioned() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.isVersioned() : false;
	}

	@Override
	public boolean isHijacked() {
		return false;
	}

	@Override
	public int getLatestVersion() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.getLatestVersion() : DomainFile.DEFAULT_VERSION;
	}

	@Override
	public boolean isLatestVersion() {
		return true;
	}

	@Override
	public int getVersion() {
		// TODO: Do we want to reveal linked-local-project checkout details?
		return getLatestVersion();
	}

	@Override
	public Version[] getVersionHistory() throws IOException {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.getVersionHistory() : new Version[0];
	}

	@Override
	public void addToVersionControl(String comment, boolean keepCheckedOut, TaskMonitor monitor)
			throws IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean checkout(boolean exclusive, TaskMonitor monitor)
			throws IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void checkin(CheckinHandler checkinHandler, boolean okToUpgrade, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void merge(boolean okToUpgrade, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void undoCheckout(boolean keep) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void undoCheckout(boolean keep, boolean force) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void terminateCheckout(long checkoutId) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public ItemCheckoutStatus[] getCheckouts() throws IOException {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.getCheckouts() : new ItemCheckoutStatus[0];
	}

	@Override
	public ItemCheckoutStatus getCheckoutStatus() throws IOException {
		// TODO: Do we want to reveal linked-local-project checkout details?
		return null;
	}

	@Override
	public void delete() throws IOException {
		throw new ReadOnlyException("linked file is read only");
	}

	@Override
	public void delete(int version) throws IOException {
		throw new ReadOnlyException("linked file is read only");
	}

	@Override
	public DomainFile moveTo(DomainFolder newParent) throws IOException {
		throw new ReadOnlyException("linked file is read only");
	}

	@Override
	public DomainFile copyTo(DomainFolder newParent, TaskMonitor monitor)
			throws IOException, CancelledException {
		return getLinkedFile().copyTo(newParent, monitor);
	}

	@Override
	public DomainFile copyVersionTo(int version, DomainFolder destFolder, TaskMonitor monitor)
			throws IOException, CancelledException {
		return getLinkedFile().copyVersionTo(version, destFolder, monitor);
	}

	@Override
	public DomainFile copyToAsLink(DomainFolder newParent) throws IOException {
		return getLinkedFile().copyToAsLink(newParent);
	}

	@Override
	public boolean isLinkingSupported() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.isLinkingSupported() : false;
	}

	@Override
	public List<?> getConsumers() {
		return List.of();
	}

	@Override
	public boolean isChanged() {
		return false;
	}

	@Override
	public boolean isOpen() {
		return false;  // domain file proxy always used
	}

	@Override
	public boolean isBusy() {
		return false;  // domain file proxy always used
	}

	@Override
	public void packFile(File file, TaskMonitor monitor) throws IOException, CancelledException {
		getLinkedFile().packFile(file, monitor);
	}

	@Override
	public Map<String, String> getMetadata() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.getMetadata() : Map.of();
	}

	@Override
	public long length() throws IOException {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.length() : 0;
	}

	@Override
	public boolean isLinkFile() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.isLinkFile() : false;
	}

	@Override
	public DomainFolder followLink() {
		try {
			return FolderLinkContentHandler.getReadOnlyLinkedFolder(this);
		}
		catch (IOException e) {
			Msg.error(this, "Failed to following folder-link: " + getPathname());
		}
		return null;
	}

	@Override
	public String toString() {
		return "LinkedGhidraFile: " + getPathname();
	}
}
