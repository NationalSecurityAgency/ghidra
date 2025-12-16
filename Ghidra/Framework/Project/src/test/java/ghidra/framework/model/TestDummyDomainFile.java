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
package ghidra.framework.model;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Map;

import javax.swing.Icon;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.Application;
import ghidra.framework.data.*;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;
import ghidra.util.InvalidNameException;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * A dummy domain file used to stub project files.
 * 
 * @see TestDummyDomainFolder
 */
public class TestDummyDomainFile implements DomainFile, LinkFileInfo {

	private String name;
	private TestDummyDomainFolder parent;
	private boolean isCheckedOut;
	private boolean isReadOnly;
	private boolean isVersioned;
	private boolean isInUse;

	private String contentType;
	private Class<? extends DomainObject> domainObjectClass;

	/**
	 * Construct test file with unknown content-type.
	 * 
	 * @param parent parent folder
	 * @param name file name
	 */
	public TestDummyDomainFile(TestDummyDomainFolder parent, String name) {
		this(parent, name, null);
	}

	/**
	 * Construct test file with a specified content-type.  When a content-type other than 
	 * {@link ContentHandler#UNKNOWN_CONTENT} is specified the corresponding {@link ContentHandler} 
	 * must be available which will require the {@link ClassSearcher} to be active with 
	 * appropriate {@link Application} initialization.
	 * <P>
	 * NOTE: Support for a link-file will require a derived implementation.
	 * 
	 * @param parent parent folder
	 * @param name file name
	 * @param fileContentType {@link DomainObject} content-type as specified by corresponding 
	 * {@link ContentHandler} implementation class.
	 */
	public TestDummyDomainFile(TestDummyDomainFolder parent, String name, String fileContentType) {
		this.parent = parent;
		this.name = name;
		contentType = fileContentType != null ? fileContentType : ContentHandler.UNKNOWN_CONTENT;
		domainObjectClass = DomainObject.class;
		if (!ContentHandler.UNKNOWN_CONTENT.equals(contentType)) {
			try {
				ContentHandler<?> ch = DomainObjectAdapter.getContentHandler(contentType);
				domainObjectClass = ch.getDomainObjectClass();
			}
			catch (IOException e) {
				// Ensure corresponding content-handler has been found by ClassSearcher.
				throw new AssertException("Unsupported content type: " + contentType);
			}
		}
	}

	public void setInUse() {
		this.isInUse = true;
	}

	public void setCheckedOut() {
		isVersioned = true;
		isCheckedOut = true;
	}

	public void setVersioned() {
		isVersioned = true;
	}

	@Override
	public int compareTo(DomainFile o) {
		throw new UnsupportedOperationException();
	}

	@Override
	public synchronized String getName() {
		return name;
	}

	@Override
	public boolean exists() {
		return true;
	}

	@Override
	public String getFileID() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DomainFile setName(String newName) throws InvalidNameException, IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getPathname() {
		String parentPathname = StringUtils.appendIfMissing(parent.getPathname(), "/");
		return parentPathname + name;
	}

	@Override
	public ProjectLocator getProjectLocator() {
		throw new UnsupportedOperationException();
	}

	@Override
	public URL getSharedProjectURL(String ref) {
		throw new UnsupportedOperationException();
	}

	@Override
	public URL getLocalProjectURL(String ref) {
		throw new UnsupportedOperationException();
	}

	ContentHandler<?> getContentHandler() throws IOException {
		if (contentType == null) {
			throw new UnsupportedOperationException();
		}
		return DomainObjectAdapter.getContentHandler(contentType);
	}

	@Override
	public String getContentType() {
		return contentType;
	}

	@Override
	public boolean isLink() {
		try {
			return getContentHandler() instanceof LinkHandler;
		}
		catch (IOException e) {
			return false; // unknown content
		}
	}

	@Override
	public LinkFileInfo getLinkInfo() {
		return isLink() ? this : null;
	}

	@Override
	public Class<? extends DomainObject> getDomainObjectClass() {
		return domainObjectClass;
	}

	@Override
	public synchronized DomainFolder getParent() {
		return parent;
	}

	@Override
	public ChangeSet getChangesByOthersSinceCheckout() throws VersionException, IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DomainObject getDomainObject(Object consumer, boolean okToUpgrade, boolean okToRecover,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DomainObject getOpenedDomainObject(Object consumer) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DomainObject getReadOnlyDomainObject(Object consumer, int version, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DomainObject getImmutableDomainObject(Object consumer, int version, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void save(TaskMonitor monitor) throws IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean canSave() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean canRecover() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean takeRecoverySnapshot() throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isInWritableProject() {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getLastModifiedTime() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Icon getIcon(boolean disabled) {
		throw new UnsupportedOperationException();
	}

	@Override
	public synchronized boolean isCheckedOut() {
		return isCheckedOut;
	}

	@Override
	public synchronized boolean isCheckedOutExclusive() {
		return false;
	}

	@Override
	public boolean modifiedSinceCheckout() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean canCheckout() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean canCheckin() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean canMerge() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean canAddToRepository() {
		throw new UnsupportedOperationException();
	}

	@Override
	public synchronized void setReadOnly(boolean state) throws IOException {
		isReadOnly = state;
	}

	@Override
	public synchronized boolean isReadOnly() {
		return isReadOnly;
	}

	@Override
	public synchronized boolean isVersioned() {
		return isVersioned;
	}

	@Override
	public boolean isHijacked() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getLatestVersion() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isLatestVersion() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getVersion() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Version[] getVersionHistory() throws IOException {
		throw new UnsupportedOperationException();
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
	public void checkin(CheckinHandler checkinHandler, TaskMonitor monitor)
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
		throw new UnsupportedOperationException();
	}

	@Override
	public ItemCheckoutStatus getCheckoutStatus() throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public synchronized void delete() throws IOException {
		if (isInUse) {
			throw new IOException("File is in Use");
		}
		parent.remove(this);
	}

	@Override
	public void delete(int version) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DomainFile moveTo(DomainFolder newParent) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isLinkingSupported() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DomainFile copyToAsLink(DomainFolder newParent, boolean relative) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DomainFile copyTo(DomainFolder newParent, TaskMonitor monitor)
			throws IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DomainFile copyVersionTo(int version, DomainFolder destFolder, TaskMonitor monitor)
			throws IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public ArrayList<?> getConsumers() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isChanged() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isOpen() {
		return isInUse;
	}

	@Override
	public boolean isBusy() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void packFile(File file, TaskMonitor monitor) throws IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Map<String, String> getMetadata() {
		throw new UnsupportedOperationException();
	}

	@Override
	public long length() throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public String toString() {
		if (parent != null) {
			return parent + "/" + name;
		}
		return name;
	}

	//
	// LinkFileInfo methods
	//

	@Override
	public DomainFile getFile() {
		return this;
	}

	@Override
	public LinkedGhidraFolder getLinkedFolder() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getLinkPath() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getAbsoluteLinkPath() throws IOException {
		throw new UnsupportedOperationException();
	}
}
