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
		return getLinkedFileNoError() != null;
	}

	@Override
	public String getFileID() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.getFileID() : null;
	}

	@Override
	public DomainFile setName(String newName) throws InvalidNameException, IOException {
		String name = getLinkedFile().setName(newName).getName();
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
		return getLinkedFile().getChangesByOthersSinceCheckout();
	}

	@Override
	public DomainObject getDomainObject(Object consumer, boolean okToUpgrade, boolean okToRecover,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {
		return getLinkedFile().getDomainObject(consumer, okToUpgrade, okToRecover, monitor);
	}

	@Override
	public DomainObject getOpenedDomainObject(Object consumer) {
		DomainFile df = getLinkedFileNoError();
		if (df != null) {
			return df.getOpenedDomainObject(consumer);
		}
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
		// TODO: Is this correct?
		return parent.isInWritableProject();
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
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.isCheckedOut() : false;
	}

	@Override
	public boolean isCheckedOutExclusive() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.isCheckedOutExclusive() : false;
	}

	@Override
	public boolean modifiedSinceCheckout() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.modifiedSinceCheckout() : false;
	}

	@Override
	public boolean canCheckout() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.canCheckout() : false;
	}

	@Override
	public boolean canCheckin() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.canCheckin() : false;
	}

	@Override
	public boolean canMerge() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.canMerge() : false;
	}

	@Override
	public boolean canAddToRepository() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.canAddToRepository() : false;
	}

	@Override
	public void setReadOnly(boolean state) throws IOException {
		getLinkedFile().setReadOnly(state);
	}

	@Override
	public boolean isReadOnly() {
		DomainFile df = getLinkedFileNoError();
		// read-only state not reflected by icon
		return df != null ? df.isReadOnly() : true;
	}

	@Override
	public boolean isVersioned() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.isVersioned() : false;
	}

	@Override
	public boolean isHijacked() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.isHijacked() : false;
	}

	@Override
	public int getLatestVersion() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.getLatestVersion() : DomainFile.DEFAULT_VERSION;
	}

	@Override
	public boolean isLatestVersion() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.isLatestVersion() : true;
	}

	@Override
	public int getVersion() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.getVersion() : DomainFile.DEFAULT_VERSION;
	}

	@Override
	public Version[] getVersionHistory() throws IOException {
		DomainFile df = getLinkedFile();
		return df != null ? df.getVersionHistory() : new Version[0];
	}

	@Override
	public void addToVersionControl(String comment, boolean keepCheckedOut, TaskMonitor monitor)
			throws IOException, CancelledException {
		getLinkedFile().addToVersionControl(comment, keepCheckedOut, monitor);
	}

	@Override
	public boolean checkout(boolean exclusive, TaskMonitor monitor)
			throws IOException, CancelledException {
		return getLinkedFile().checkout(exclusive, monitor);
	}

	@Override
	public void checkin(CheckinHandler checkinHandler, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {
		getLinkedFile().checkin(checkinHandler, monitor);
	}

	@Override
	public void merge(boolean okToUpgrade, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {
		getLinkedFile().merge(okToUpgrade, monitor);
	}

	@Override
	public void undoCheckout(boolean keep) throws IOException {
		getLinkedFile().undoCheckout(keep);
	}

	@Override
	public void undoCheckout(boolean keep, boolean force) throws IOException {
		getLinkedFile().undoCheckout(keep, force);
	}

	@Override
	public void terminateCheckout(long checkoutId) throws IOException {
		getLinkedFile().terminateCheckout(checkoutId);
	}

	@Override
	public ItemCheckoutStatus[] getCheckouts() throws IOException {
		return getLinkedFile().getCheckouts();
	}

	@Override
	public ItemCheckoutStatus getCheckoutStatus() throws IOException {
		return getLinkedFile().getCheckoutStatus();
	}

	@Override
	public void delete() throws IOException {
		getLinkedFile().delete();
	}

	@Override
	public void delete(int version) throws IOException {
		getLinkedFile().delete(version);
	}

	@Override
	public DomainFile moveTo(DomainFolder newParent) throws IOException {
		return getLinkedFile().moveTo(newParent);
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
	public DomainFile copyToAsLink(DomainFolder newParent, boolean relative) throws IOException {
		return getLinkedFile().copyToAsLink(newParent, relative);
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
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.isChanged() : false;
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
	public boolean isLink() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.isLink() : false;
	}

	@Override
	public LinkFileInfo getLinkInfo() {
		DomainFile df = getLinkedFileNoError();
		return df != null ? df.getLinkInfo() : null;
	}

	@Override
	public String getLinkedPathname() {
		return parent.getLinkedPathname(fileName);
	}

	@Override
	public String toString() {
		String str = parent.toString();
		if (!str.endsWith("/")) {
			str += "/";
		}
		str += getName();
		return str;
	}

}
