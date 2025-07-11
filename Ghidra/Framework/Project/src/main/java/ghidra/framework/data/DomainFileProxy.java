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
import java.util.*;

import javax.swing.Icon;

import ghidra.framework.client.*;
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.store.*;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.util.InvalidNameException;
import ghidra.util.ReadOnlyException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Implements the DomainFile interface for DomainObjects that are not currently
 * associated with any real DomainFile. This class enforces the sharing of
 * objects between tools.  After the first tool gets the implementation, all
 * other gets() just get the same instance.  This class also keeps track of
 * which tools are using a its domain object.
 */
public class DomainFileProxy implements DomainFile {

	private DomainObjectAdapter domainObj;
	private ProjectLocator projectLocation;
	private String name;
	private int version;
	private String parentPath;
	private long lastModified = 0;
	private String fileID;

	public DomainFileProxy(String name, DomainObjectAdapter doa) {
		domainObj = doa;
		this.name = name;
		doa.setDomainFile(this);
		TransientDataManager.addTransient(this);
		version = DomainFile.DEFAULT_VERSION;
	}

	DomainFileProxy(String name, String parentPath, DomainObjectAdapter doa, int version,
			String fileID, ProjectLocator projectLocation) throws IOException {

		this(name, doa);
		this.parentPath = parentPath;
		this.version = version;
		this.fileID = fileID;
		this.projectLocation = projectLocation;
	}

	@Override
	public boolean exists() {
		return false;
	}

	@Override
	public synchronized DomainFile setName(String newName) {
		// synchronization employed to ensure thread visibility when name changed
		this.name = newName;
		return this;
	}

	@Override
	public ProjectLocator getProjectLocator() {
		return projectLocation;
	}

	@Override
	public long length() throws IOException {
		// TODO not sure what we should report here
		return 0;
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public void setReadOnly(boolean state) {
		throw new UnsupportedOperationException("setReadOnly() not suppported on DomainFileProxy");
	}

	@Override
	public boolean isInWritableProject() {
		return false;
	}

	@Override
	public String getPathname() {
		if (parentPath == null || parentPath.equals(DomainFolder.SEPARATOR)) {
			return DomainFolder.SEPARATOR + getName();
		}
		return parentPath + DomainFolder.SEPARATOR + getName();
	}

	private URL getSharedFileURL(URL sharedProjectURL, String ref) {
		try {
			// Direct URL construction done so that ghidra protocol extension may be supported
			String urlStr = sharedProjectURL.toExternalForm();
			if (urlStr.endsWith(FileSystem.SEPARATOR)) {
				urlStr = urlStr.substring(0, urlStr.length() - 1);
			}
			urlStr += getPathname();
			return new URL(urlStr);
		}
		catch (MalformedURLException e) {
			// ignore
		}
		return null;
	}

	private URL getSharedFileURL(Properties properties, String ref) {
		if (properties == null) {
			return null;
		}
		String serverName = properties.getProperty(DefaultProjectData.SERVER_NAME);
		String repoName = properties.getProperty(DefaultProjectData.REPOSITORY_NAME);
		if (serverName == null || repoName == null) {
			return null;
		}
		int port = Integer.parseInt(properties.getProperty(DefaultProjectData.PORT_NUMBER, "0"));

		if (!ClientUtil.isConnected(serverName, port)) {
			return null; // avoid initiating a server connection. 
		}

		RepositoryAdapter repository = null;
		try {
			RepositoryServerAdapter repositoryServer =
				ClientUtil.getRepositoryServer(serverName, port);
			Set<String> repoNames = Set.of(repositoryServer.getRepositoryNames());
			if (!repoNames.contains(repoName)) {
				return null; // only consider repos which user has access to
			}
			repository = repositoryServer.getRepository(repoName);
			if (repository == null) {
				return null;
			}
			repository.connect();
			RepositoryItem item = repository.getItem(parentPath, name);
			if (item == null || !Objects.equals(item.getFileID(), fileID)) {
				return null;
			}
			ServerInfo serverInfo = repository.getServerInfo();
			return GhidraURL.makeURL(serverInfo.getServerName(), serverInfo.getPortNumber(),
				repository.getName(), item.getPathName(), ref);
		}
		catch (IOException e) {
			// ignore
		}
		finally {
			if (repository != null) {
				repository.disconnect();
			}
		}
		return null;
	}

	@Override
	public URL getSharedProjectURL(String ref) {
		if (projectLocation != null && version == DomainFile.DEFAULT_VERSION) {
			URL projectURL = projectLocation.getURL();
			if (GhidraURL.isServerRepositoryURL(projectURL)) {
				return getSharedFileURL(projectURL, ref);
			}
			Properties properties =
				DefaultProjectData.readProjectProperties(projectLocation.getProjectDir());
			return getSharedFileURL(properties, ref);
		}
		return null;
	}

	@Override
	public URL getLocalProjectURL(String ref) {
		if (projectLocation != null && version == DomainFile.DEFAULT_VERSION) {
			URL projectURL = projectLocation.getURL();
			if (GhidraURL.isServerRepositoryURL(projectURL)) {
				return null;
			}
			return GhidraURL.makeURL(projectLocation, getPathname(), ref);
		}
		return null;
	}

	@Override
	public int compareTo(DomainFile df) {
		return getName().compareToIgnoreCase(df.getName());
	}

	@Override
	public String toString() {
		String s = getPathname();
		if (projectLocation != null) {
			s = projectLocation.getName() + ":" + s;
		}
		if (version != DomainFile.DEFAULT_VERSION) {
			s += "@" + version;
		}
		return s;
	}

	@Override
	public synchronized String getName() {
		return name;
	}

	@Override
	public String getFileID() {
		return fileID;
	}

	@Override
	public String getContentType() {
		DomainObjectAdapter dobj = getDomainObject();
		if (dobj != null) {
			try {
				ContentHandler<?> ch = DomainObjectAdapter.getContentHandler(dobj);
				return ch.getContentType();
			}
			catch (IOException e) {
				// ignore missing content handler
			}
		}
		return "Unknown File";
	}

	@Override
	public boolean isLink() {
		return false;
	}

	@Override
	public LinkFileInfo getLinkInfo() {
		return null;
	}

	@Override
	public Class<? extends DomainObject> getDomainObjectClass() {
		DomainObjectAdapter dobj = getDomainObject();
		return dobj != null ? dobj.getClass() : null;
	}

	@Override
	public DomainFolder getParent() {
		return null;
	}

	synchronized void setLastModified(long time) {
		// TODO: this method should never be called and should throw an exception
		lastModified = time;
	}

	@Override
	public synchronized long getLastModifiedTime() {
		// TODO: this method should return 0
		return lastModified;
	}

	@Override
	public void save(TaskMonitor monitor) throws IOException {
		throw new ReadOnlyException("Location does not exist for a save operation!");
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
	public boolean takeRecoverySnapshot() {
		throw new UnsupportedOperationException("Recovery snapshot not supported for proxy file");
	}

	public boolean isInUse() {
		return true;
	}

	@Override
	public ArrayList<?> getConsumers() {
		DomainObjectAdapter dobj = getDomainObject();
		if (dobj != null) {
			return dobj.getConsumerList();
		}
		return new ArrayList<>();
	}

	void clearDomainObj() {
		synchronized (this) {
			// synchronization employed to ensure thread visibility when domainObj cleared
			domainObj = null;
		}
		TransientDataManager.removeTransient(this);
	}

	void release(Object consumer) {
		DomainObjectAdapter dobj = getDomainObject();
		if (dobj != null) {
			try {
				dobj.release(consumer);
			}
			catch (IllegalArgumentException e) {
				// ignore unknown consumer error
			}
		}
	}

	@Override
	public int hashCode() {
		return super.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		return obj == this;
	}

	public boolean isUsedBy(Object consumer) {
		DomainObjectAdapter dobj = getDomainObject();
		if (dobj != null) {
			return dobj.isUsedBy(consumer);
		}
		return false;
	}

	@Override
	public void addToVersionControl(String comment, boolean keepCheckedOut, TaskMonitor monitor)
			throws IOException, CancelledException {
		throw new UnsupportedOperationException("Repository operations not supported");
	}

	@Override
	public boolean canAddToRepository() {
		return false;
	}

	@Override
	public boolean isBusy() {
		DomainObjectAdapter dobj = getDomainObject();
		return dobj != null && !dobj.canLock();
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
	public boolean checkout(boolean exclusive, TaskMonitor monitor) {
		throw new UnsupportedOperationException("Repository operations not supported");
	}

	@Override
	public void checkin(CheckinHandler checkinHandler, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {
		throw new UnsupportedOperationException("Repository operations not supported");
	}

	@Override
	public void merge(boolean okToUpgrade, TaskMonitor monitor) {
		throw new UnsupportedOperationException("Repository operations not supported");
	}

	@Override
	public boolean isLinkingSupported() {
		return false;
	}

	@Override
	public DomainFile copyToAsLink(DomainFolder newParent, boolean relative) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DomainFile copyTo(DomainFolder newParent, TaskMonitor monitor)
			throws IOException, CancelledException {
		DomainObjectAdapter dobj = getDomainObject();
		if (dobj == null) {
			throw new ClosedException();
		}
		try {
			return newParent.createFile(getName(), dobj, monitor);
		}
		catch (InvalidNameException e) {
			throw new AssertException("Unexpected error", e);
		}
	}

	@Override
	public DomainFile copyVersionTo(int ver, DomainFolder destFolder, TaskMonitor monitor)
			throws IOException, CancelledException {
		throw new UnsupportedOperationException("copyVersionTo unsupported for DomainFileProxy");
	}

	@Override
	public synchronized void delete() throws IOException {
		if (domainObj != null) {
			throw new FileInUseException("Proxy file for " + name + " is in use");
		}
	}

	@Override
	public void delete(int fileVersion) throws IOException {
		throw new UnsupportedOperationException("delete(version) unsupported for DomainFileProxy");
	}

	@Override
	public int getLatestVersion() {
		return 0;
	}

	@Override
	public boolean isLatestVersion() {
		return version == DEFAULT_VERSION;
	}

	@Override
	public int getVersion() {
		return version;
	}

	@Override
	public Version[] getVersionHistory() throws IOException {
		return new Version[0];
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
	public DomainFile moveTo(DomainFolder newParent) throws IOException {
		throw new UnsupportedOperationException("Cannot move a proxy file - must call copyTo()");
	}

	@Override
	public void undoCheckout(boolean keep) throws IOException {
		throw new UnsupportedOperationException("undoCheckout() unsupported for DomainFileProxy");
	}

	@Override
	public void undoCheckout(boolean keep, boolean force) throws IOException {
		throw new UnsupportedOperationException("undoCheckout() unsupported for DomainFileProxy");
	}

	@Override
	public ChangeSet getChangesByOthersSinceCheckout() throws IOException {
		return null;
	}

	private synchronized DomainObjectAdapter getDomainObject() {
		return domainObj;
	}

	@Override
	public DomainObject getDomainObject(Object consumer, boolean okToUpgrade, boolean okToRecover,
			TaskMonitor monitor) throws VersionException, IOException {
		return getOpenedDomainObject(consumer);
	}

	@Override
	public DomainObject getOpenedDomainObject(Object consumer) {
		DomainObjectAdapter dobj = getDomainObject();
		if (dobj != null) {
			dobj.addConsumer(consumer);
		}
		return dobj;
	}

	@Override
	public boolean isVersioned() {
		return false;
	}

	@Override
	public synchronized void packFile(File file, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (!(domainObj instanceof DomainObjectAdapterDB)) {
			throw new UnsupportedOperationException("packFile() only valid for Database files");
		}
		DomainObjectAdapterDB dbObj = (DomainObjectAdapterDB) domainObj;
		ContentHandler<?> ch = DomainObjectAdapter.getContentHandler(domainObj);
		PackedDatabase.packDatabase(dbObj.getDBHandle(), dbObj.getName(), ch.getContentType(), file,
			monitor);
	}

	@Override
	public Icon getIcon(boolean disabled) {
		return null;
	}

	@Override
	public DomainObject getImmutableDomainObject(Object consumer, int fileVersion,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {
		throw new UnsupportedOperationException(
			"getImmutableDomainObject unsupported for DomainFileProxy");
	}

	@Override
	public DomainObject getReadOnlyDomainObject(Object consumer, int fileVersion,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {
		if (fileVersion != DEFAULT_VERSION && fileVersion != this.version) {
			throw new AssertException("Version mismatch on DomainFileProxy");
		}
		return getOpenedDomainObject(consumer);
	}

	@Override
	public boolean isHijacked() {
		return false;
	}

	@Override
	public boolean modifiedSinceCheckout() {
		return false;
	}

	@Override
	public boolean isChanged() {
		DomainObjectAdapter dobj = getDomainObject();
		if (dobj != null) {
			return dobj.isChanged();
		}
		return false;
	}

	@Override
	public boolean isOpen() {
		DomainObjectAdapter dobj = getDomainObject();
		return dobj != null && !dobj.isClosed();
	}

	@Override
	public void terminateCheckout(long checkoutId) throws IOException {
		throw new UnsupportedOperationException(
			"terminateCheckout() unsupported for DomainFileProxy");
	}

	@Override
	public ItemCheckoutStatus[] getCheckouts() throws IOException {
		throw new UnsupportedOperationException("getCheckouts() unsupported for DomainFileProxy");
	}

	@Override
	public ItemCheckoutStatus getCheckoutStatus() throws IOException {
		throw new UnsupportedOperationException(
			"getCheckoutStatus() unsupported for DomainFileProxy");
	}

	@Override
	public Map<String, String> getMetadata() {
		DomainObjectAdapter dobj = getDomainObject();
		if (dobj != null) {
			dobj.getMetadata();
		}
		return new HashMap<>();
	}

}
