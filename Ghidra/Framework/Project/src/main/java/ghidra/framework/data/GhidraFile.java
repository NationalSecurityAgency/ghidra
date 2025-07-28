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

import java.io.*;
import java.net.URL;
import java.util.*;

import javax.swing.Icon;

import ghidra.framework.model.*;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.util.InvalidNameException;
import ghidra.util.ReadOnlyException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class GhidraFile implements DomainFile, LinkFileInfo {

	protected DefaultProjectData projectData;

	private LocalFileSystem fileSystem;
	private DomainFolderChangeListener listener;

	private GhidraFolder parent;
	private String name;

	GhidraFile(GhidraFolder parent, String name) {
		this.parent = parent;
		this.name = name;

		this.projectData = parent.getProjectData();
		this.fileSystem = parent.getLocalFileSystem();
		this.listener = parent.getChangeListener();
	}

	public LocalFileSystem getUserFileSystem() {
		return projectData.getUserFileSystem();
	}

	private GhidraFileData getFileData() throws FileNotFoundException, IOException {
		return parent.getFileData(name);
	}

	private void fileError(IOException e) {
		// can easily occur during server disconnect
		//Msg.error(this, "IO Error on file " + getPathname() + ": " + e.getMessage());
	}

	@Override
	public boolean exists() {
		try {
			getFileData();
			return true;
		}
		catch (IOException e) {
			// All IO exceptions treated as missing file
			return false;
		}
	}

	@Override
	public String getFileID() {
		try {
			return getFileData().getFileID();
		}
		catch (IOException e) {
			fileError(e);
		}
		return null;
	}

	/**
	 * Reassign a new file-ID to resolve file-ID conflict.
	 * Conflicts can occur as a result of a cancelled check-out.
	 * @throws IOException if an IO error occurs
	 */
	void resetFileID() throws IOException {
		getFileData().resetFileID();
	}

	void clearDomainObj() {
		String path = getPathname();
		DomainObjectAdapter doa = projectData.getOpenedDomainObject(path);
		if (doa != null && projectData.clearDomainObject(getPathname())) {
			listener.domainFileObjectClosed(this, doa);
		}
	}

	@Override
	public GhidraFile setName(String newName) throws InvalidNameException, IOException {
		return getFileData().setName(newName);
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getPathname() {
		return parent.getPathname(name);
	}

	@Override
	public ProjectLocator getProjectLocator() {
		return projectData.getProjectLocator();
	}

	@Override
	public URL getSharedProjectURL(String ref) {
		try {
			return getFileData().getSharedProjectURL(ref);
		}
		catch (IOException e) {
			// ignore
		}
		return null;
	}

	@Override
	public URL getLocalProjectURL(String ref) {
		try {
			return getFileData().getLocalProjectURL(ref);
		}
		catch (IOException e) {
			// ignore
		}
		return null;
	}

	@Override
	public String getContentType() {
		try {
			return getFileData().getContentType();
		}
		catch (IOException e) {
			fileError(e);
		}
		return ContentHandler.UNKNOWN_CONTENT;
	}

	@Override
	public boolean isLink() {
		try {
			return getFileData().isLink();
		}
		catch (IOException e) {
			return false;
		}
	}

	@Override
	public LinkFileInfo getLinkInfo() {
		return isLink() ? this : null;
	}

	@Override
	public DomainFile getFile() {
		return this;
	}

	@Override
	public String getLinkPath() {
		try {
			return getFileData().getLinkPath(false);
		}
		catch (IOException e) {
			// ignore
		}
		return null;
	}

	@Override
	public String getAbsoluteLinkPath() throws IOException {
		return LinkHandler.getAbsoluteLinkPath(this);
	}

	@Override
	public LinkedGhidraFolder getLinkedFolder() {
		try {
			return FolderLinkContentHandler.getLinkedFolder(this);
		}
		catch (IOException e) {
			// Ignore
		}
		return null;
	}

	@Override
	public boolean isLinkingSupported() {
		try {
			return getFileData().isLinkingSupported();
		}
		catch (IOException e) {
			return false;
		}
	}

	@Override
	public Class<? extends DomainObject> getDomainObjectClass() {
		try {
			return getFileData().getDomainObjectClass();
		}
		catch (IOException e) {
			fileError(e);
		}
		return DomainObject.class;
	}

	@Override
	public GhidraFolder getParent() {
		return parent;
	}

	@Override
	public int compareTo(DomainFile df) {
		return name.compareToIgnoreCase(df.getName());
	}

	@Override
	public ChangeSet getChangesByOthersSinceCheckout() throws VersionException, IOException {
		return getFileData().getChangesByOthersSinceCheckout();
	}

	@Override
	public DomainObject getOpenedDomainObject(Object consumer) {
		DomainObjectAdapter domainObj = projectData.getOpenedDomainObject(getPathname());
		if (domainObj != null) {
			if (!domainObj.addConsumer(consumer)) {
				projectData.clearDomainObject(getPathname());
				throw new IllegalStateException("Domain Object is closed: " + domainObj.getName());
			}
		}
		return domainObj;
	}

	@Override
	public DomainObject getDomainObject(Object consumer, boolean okToUpgrade, boolean okToRecover,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {
		return getFileData().getDomainObject(consumer, okToUpgrade, okToRecover,
			monitor != null ? monitor : TaskMonitor.DUMMY);
	}

	@Override
	public DomainObject getReadOnlyDomainObject(Object consumer, int version, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		return getFileData().getReadOnlyDomainObject(consumer, version,
			monitor != null ? monitor : TaskMonitor.DUMMY);
	}

	@Override
	public DomainObject getImmutableDomainObject(Object consumer, int version, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		return getFileData().getImmutableDomainObject(consumer, version,
			monitor != null ? monitor : TaskMonitor.DUMMY);
	}

	@Override
	public void save(TaskMonitor monitor) throws IOException, CancelledException {
		DomainObjectAdapter dobj = projectData.getOpenedDomainObject(getPathname());
		if (dobj == null) {
			throw new AssertException("Cannot save, domainObj not open");
		}
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException("Cannot save to read-only project");
		}
		if (isReadOnly()) {
			throw new ReadOnlyException("Cannot save to read-only file");
		}
		dobj.save(null, monitor != null ? monitor : TaskMonitor.DUMMY);
	}

	@Override
	public boolean canSave() {
		DomainObjectAdapter dobj = projectData.getOpenedDomainObject(getPathname());
		if (dobj == null) {
			return false;
		}
		return dobj.canSave();
	}

	@Override
	public boolean canRecover() {
		try {
			return getFileData().canRecover();
		}
		catch (IOException e) {
			fileError(e);
		}
		return false;
	}

	@Override
	public boolean takeRecoverySnapshot() throws IOException {
		return getFileData().takeRecoverySnapshot();
	}

	@Override
	public boolean isInWritableProject() {
		return !fileSystem.isReadOnly();
	}

	@Override
	public long getLastModifiedTime() {
		try {
			return getFileData().getLastModifiedTime();
		}
		catch (IOException e) {
			fileError(e);
		}
		return 0;
	}

	@Override
	public Icon getIcon(boolean disabled) {
		try {
			return getFileData().getIcon(disabled);
		}
		catch (IOException e) {
			fileError(e);
		}
		return UNSUPPORTED_FILE_ICON;
	}

	@Override
	public boolean isCheckedOut() {
		try {
			return getFileData().isCheckedOut();
		}
		catch (IOException e) {
			fileError(e);
		}
		return false;
	}

	@Override
	public boolean isCheckedOutExclusive() {
		try {
			return getFileData().isCheckedOutExclusive();
		}
		catch (IOException e) {
			fileError(e);
		}
		return false;
	}

	@Override
	public boolean modifiedSinceCheckout() {
		try {
			return getFileData().modifiedSinceCheckout();
		}
		catch (IOException e) {
			fileError(e);
		}
		return false;
	}

	@Override
	public boolean canCheckout() {
		try {
			return getFileData().canCheckout();
		}
		catch (IOException e) {
			fileError(e);
		}
		return false;
	}

	@Override
	public boolean canCheckin() {
		try {
			return getFileData().canCheckin();
		}
		catch (IOException e) {
			fileError(e);
		}
		return false;
	}

	@Override
	public boolean canMerge() {
		try {
			return getFileData().canMerge();
		}
		catch (IOException e) {
			fileError(e);
		}
		return false;
	}

	@Override
	public boolean canAddToRepository() {
		try {
			getFileData().checkCanAddToRepository();
			return true;
		}
		catch (IOException e) {
			// ignore
		}
		return false;
	}

	@Override
	public void setReadOnly(boolean state) throws IOException {
		getFileData().setReadOnly(state);
	}

	@Override
	public boolean isReadOnly() {
		try {
			return getFileData().isReadOnly();
		}
		catch (IOException e) {
			fileError(e);
		}
		return true;
	}

	@Override
	public boolean isVersioned() {
		try {
			return getFileData().isVersioned();
		}
		catch (IOException e) {
			fileError(e);
		}
		return false;
	}

	@Override
	public boolean isHijacked() {
		try {
			return getFileData().isHijacked();
		}
		catch (IOException e) {
			fileError(e);
		}
		return false;
	}

	@Override
	public int getLatestVersion() {
		try {
			return getFileData().getLatestVersion();
		}
		catch (IOException e) {
			fileError(e);
		}
		return 0;
	}

	@Override
	public boolean isLatestVersion() {
		return true;
	}

	@Override
	public int getVersion() {
		try {
			return getFileData().getVersion();
		}
		catch (IOException e) {
			fileError(e);
		}
		return -1;
	}

	@Override
	public Version[] getVersionHistory() throws IOException {
		return getFileData().getVersionHistory();
	}

	@Override
	public void addToVersionControl(String comment, boolean keepCheckedOut, TaskMonitor monitor)
			throws IOException, CancelledException {
		getFileData().addToVersionControl(comment, keepCheckedOut, monitor);
	}

	@Override
	public boolean checkout(boolean exclusive, TaskMonitor monitor)
			throws IOException, CancelledException {
		return getFileData().checkout(exclusive, monitor != null ? monitor : TaskMonitor.DUMMY);
	}

	@Override
	public void checkin(CheckinHandler checkinHandler, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {
		getFileData().checkin(checkinHandler, monitor != null ? monitor : TaskMonitor.DUMMY);
	}

	@Override
	public void merge(boolean okToUpgrade, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {
		getFileData().merge(okToUpgrade, monitor != null ? monitor : TaskMonitor.DUMMY);
	}

	@Override
	public void undoCheckout(boolean keep) throws IOException {
		getFileData().undoCheckout(keep, false);
	}

	@Override
	public void undoCheckout(boolean keep, boolean force) throws IOException {
		getFileData().undoCheckout(keep, force, false);
	}

	@Override
	public void terminateCheckout(long checkoutId) throws IOException {
		getFileData().terminateCheckout(checkoutId);
	}

	@Override
	public ItemCheckoutStatus[] getCheckouts() throws IOException {
		return getFileData().getCheckouts();
	}

	@Override
	public ItemCheckoutStatus getCheckoutStatus() throws IOException {
		return getFileData().getCheckoutStatus();
	}

	@Override
	public void delete() throws IOException {
		getFileData().delete();
	}

	@Override
	public void delete(int version) throws IOException {
		getFileData().delete(version);
	}

	@Override
	public GhidraFile moveTo(DomainFolder newParent) throws IOException {

		if (getParent().getProjectData() != newParent.getProjectData() || !isInWritableProject()) {
			throw new IOException("Move only supported within the same writable project");
		}

		GhidraFolder newGhidraParent = GhidraFolder.getDestinationFolder(newParent);

		return getFileData().moveTo(newGhidraParent.getFolderData());
	}

	@Override
	public DomainFile copyTo(DomainFolder newParent, TaskMonitor monitor)
			throws IOException, CancelledException {

		GhidraFolder newGhidraParent = GhidraFolder.getDestinationFolder(newParent);

		return getFileData().copyTo(newGhidraParent.getFolderData(),
			monitor != null ? monitor : TaskMonitor.DUMMY);
	}

	@Override
	public DomainFile copyToAsLink(DomainFolder newParent, boolean relative) throws IOException {

		GhidraFolder newGhidraParent = GhidraFolder.getDestinationFolder(newParent);

		return getFileData().copyToAsLink(newGhidraParent.getFolderData(), relative);
	}

	@Override
	public DomainFile copyVersionTo(int version, DomainFolder destFolder, TaskMonitor monitor)
			throws IOException, CancelledException {

		GhidraFolder destGhidraFolder = GhidraFolder.getDestinationFolder(destFolder);

		return getFileData().copyVersionTo(version, destGhidraFolder.getFolderData(),
			monitor != null ? monitor : TaskMonitor.DUMMY);
	}

	/**
	 * Copy this file to make a private file if it is versioned. This method should be called
	 * only when a non shared project is being converted to a shared project.
	 * @param monitor task monitor
	 * @throws IOException if an IO error occurs
	 * @throws CancelledException if task is cancelled
	 */
	void convertToPrivateFile(TaskMonitor monitor) throws IOException, CancelledException {
		getFileData().convertToPrivateFile(monitor != null ? monitor : TaskMonitor.DUMMY);
	}

	@Override
	public ArrayList<?> getConsumers() {
		DomainObjectAdapter dobj = projectData.getOpenedDomainObject(getPathname());
		if (dobj == null) {
			return new ArrayList<>();
		}
		return dobj.getConsumerList();
	}

	@Override
	public boolean isChanged() {
		DomainObjectAdapter dobj = projectData.getOpenedDomainObject(getPathname());
		return dobj != null && dobj.isChanged();
	}

	@Override
	public boolean isOpen() {
		return projectData.getOpenedDomainObject(getPathname()) != null;
	}

	@Override
	public boolean isBusy() {
		synchronized (fileSystem) {
			try {
				return getFileData().isBusy();
			}
			catch (IOException e) {
				fileError(e);
			}
		}
		return false;
	}

	@Override
	public void packFile(File file, TaskMonitor monitor) throws IOException, CancelledException {
		getFileData().packFile(file, monitor != null ? monitor : TaskMonitor.DUMMY);
	}

	@Override
	public Map<String, String> getMetadata() {
		try {
			return getFileData().getMetadata();
		}
		catch (IOException e) {
			fileError(e);
		}
		return new HashMap<>();
	}

	void fileChanged() {
		try {
			getFileData().getParent().fileChanged(name);
		}
		catch (IOException e) {
			fileError(e);
		}
	}

	@Override
	public long length() throws IOException {
		return getFileData().length();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof GhidraFile other)) {
			return false;
		}
		if (projectData != other.projectData) {
			return false;
		}
		return getPathname().equals(other.getPathname());
	}

	@Override
	public int hashCode() {
		return getPathname().hashCode();
	}

	@Override
	public String toString() {
		ProjectLocator projectLocator = projectData.getProjectLocator();
		if (projectLocator.isTransient()) {
			return projectLocator.getName() + getPathname();
		}
		return projectLocator.getName() + ":" + getPathname();
	}

}
