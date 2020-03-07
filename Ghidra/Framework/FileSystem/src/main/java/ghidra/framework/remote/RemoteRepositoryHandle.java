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
package ghidra.framework.remote;

import java.io.IOException;
import java.rmi.Remote;
import java.rmi.server.RemoteObjectInvocationHandler;

import db.buffers.ManagedBufferFileHandle;
import ghidra.framework.store.*;
import ghidra.util.InvalidNameException;

/**
 * <code>RepositoryHandle</code> provides access to a remote repository via RMI.
 * <p>
 * Methods from {@link RepositoryHandle} <b>must</b> be re-declared here
 * so they may be properly marshalled for remote invocation via RMI.  
 * This became neccessary with an OpenJDK 11.0.6 change made to 
 * {@link RemoteObjectInvocationHandler}.
 */
public interface RemoteRepositoryHandle extends RepositoryHandle, Remote {
	@Override
	String getName() throws IOException;

	@Override
	User getUser() throws IOException;

	@Override
	User[] getUserList() throws IOException;

	@Override
	boolean anonymousAccessAllowed() throws IOException;

	@Override
	String[] getServerUserList() throws IOException;

	@Override
	void setUserList(User[] users, boolean anonymousAccessAllowed) throws IOException;

	@Override
	String[] getSubfolderList(String folderPath) throws IOException;

	@Override
	int getItemCount() throws IOException;

	@Override
	RepositoryItem[] getItemList(String folderPath) throws IOException;

	@Override
	RepositoryItem getItem(String parentPath, String name) throws IOException;

	@Override
	RepositoryItem getItem(String fileID) throws IOException;

	@Override
	ManagedBufferFileHandle createDatabase(String parentPath, String itemName, String fileID,
			int bufferSize, String contentType, String projectPath)
			throws IOException, InvalidNameException;

	@Override
	ManagedBufferFileHandle openDatabase(String parentPath, String itemName, int version,
			int minChangeDataVer) throws IOException;

	@Override
	ManagedBufferFileHandle openDatabase(String parentPath, String itemName, long checkoutId)
			throws IOException;

	@Override
	Version[] getVersions(String parentPath, String itemName) throws IOException;

	@Override
	void deleteItem(String parentPath, String itemName, int version) throws IOException;

	@Override
	void moveFolder(String oldParentPath, String newParentPath, String oldFolderName,
			String newFolderName) throws InvalidNameException, IOException;

	@Override
	void moveItem(String oldParentPath, String newParentPath, String oldItemName,
			String newItemName) throws InvalidNameException, IOException;

	@Override
	ItemCheckoutStatus checkout(String parentPath, String itemName, CheckoutType checkoutType,
			String projectPath) throws IOException;

	@Override
	void terminateCheckout(String parentPath, String itemName, long checkoutId, boolean notify)
			throws IOException;

	@Override
	ItemCheckoutStatus getCheckout(String parentPath, String itemName, long checkoutId)
			throws IOException;

	@Override
	ItemCheckoutStatus[] getCheckouts(String parentPath, String itemName) throws IOException;

	@Override
	boolean folderExists(String folderPath) throws IOException;

	@Override
	boolean fileExists(String parentPath, String itemName) throws IOException;

	@Override
	long getLength(String parentPath, String itemName) throws IOException;

	@Override
	boolean hasCheckouts(String parentPath, String itemName) throws IOException;

	@Override
	boolean isCheckinActive(String parentPath, String itemName) throws IOException;

	@Override
	void updateCheckoutVersion(String parentPath, String itemName, long checkoutId,
			int checkoutVersion) throws IOException;

	@Override
	RepositoryChangeEvent[] getEvents() throws IOException;

	@Override
	void close() throws IOException;

}
