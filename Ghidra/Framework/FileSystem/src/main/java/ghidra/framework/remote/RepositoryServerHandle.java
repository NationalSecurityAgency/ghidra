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

import ghidra.util.exception.DuplicateFileException;
import ghidra.util.exception.UserAccessException;

/**
 * <code>RepositoryServerHandle</code> provides access to a repository server.
 */
public interface RepositoryServerHandle {

	/**
	 * @return true if server allows anonymous access.
	 * Individual repositories must grant anonymous access separately.
	 * @throws IOException if an IO error occurs
	 */
	boolean anonymousAccessAllowed() throws IOException;

	/**
	 * @return true if user has restricted read-only access to server (e.g., anonymous user)
	 * @throws IOException if an IO error occurs
	 */
	boolean isReadOnly() throws IOException;

	/**
	 * Create a new repository on the server.  The newly created RepositoryHandle will contain 
	 * a unique project ID for the client.
	 * @param name repository name.
	 * This ID will be used to identify and maintain checkout data.
	 * @return handle to new repository.
	 * @throws DuplicateFileException
	 * @throws UserAccessException
	 * @throws IOException if an IO error occurs
	 */
	RepositoryHandle createRepository(String name) throws IOException;

	/**
	 * Get a handle to an existing repository.
	 * @param name repository name.
	 * @return repository handle or null if repository does not exist.
	 * @throws UserAccessException if user does not have permission to access repository
	 * @throws IOException if an IO error occurs
	 */
	RepositoryHandle getRepository(String name) throws IOException;

	/**
	 * Delete a repository.
	 * @param name repository name.
	 * @throws UserAccessException if user does not have permission to delete repository
	 * @throws IOException if an IO error occurs
	 */
	void deleteRepository(String name) throws IOException;

	/**
	 * Returns a list of all repository names which are accessable by the current user.
	 * @throws IOException if an IO error occurs
	 */
	String[] getRepositoryNames() throws IOException;

	/**
	 * Returns current user for which this handle belongs.
	 * @throws IOException if an IO error occurs
	 */
	String getUser() throws IOException;

	/**
	 * Returns a list of all known users.
	 * @throws IOException if an IO error occurs
	 */
	String[] getAllUsers() throws IOException;

	/**
	 * Returns true if the user's password can be changed.
	 * @throws IOException if an IO error occurs
	 */
	boolean canSetPassword() throws IOException;

	/**
	 * Returns the amount of time in milliseconds until the 
	 * user's password will expire.
	 * @return time until expiration or -1 if it will not expire
	 * @throws IOException if an IO error occurs
	 */
	long getPasswordExpiration() throws IOException;

	/**
	 * Set the password for the user.
	 * @param saltedSHA256PasswordHash SHA256 salted password hash
	 * @return true if password changed
	 * @throws IOException if an IO error occurs
	 * @see ghidra.util.HashUtilities#getSaltedHash(String, char[])  HashUtilities.getSaltedHash("SHA-256", char[])
	 */
	boolean setPassword(char[] saltedSHA256PasswordHash) throws IOException;

	/**
	 * Verify that server is alive and connected.
	 * @throws IOException if connection verification fails
	 */
	void connected() throws IOException;

}
