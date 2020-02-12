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

/**
 * <code>RepositoryServerHandle</code> provides access to a remote repository server via RMI.
 * <p>
 * Methods from {@link RepositoryServerHandle} <b>must</b> be re-declared here 
 * so they may be properly marshalled for remote invocation via RMI.  
 * This became neccessary with an OpenJDK 11.0.6 change made to 
 * {@link RemoteObjectInvocationHandler}.
 */
public interface RemoteRepositoryServerHandle extends RepositoryServerHandle, Remote {

	@Override
	boolean anonymousAccessAllowed() throws IOException;

	@Override
	boolean isReadOnly() throws IOException;

	@Override
	RepositoryHandle createRepository(String name) throws IOException;

	@Override
	RepositoryHandle getRepository(String name) throws IOException;

	@Override
	void deleteRepository(String name) throws IOException;

	@Override
	String[] getRepositoryNames() throws IOException;

	@Override
	String getUser() throws IOException;

	@Override
	String[] getAllUsers() throws IOException;

	@Override
	boolean canSetPassword() throws IOException;

	@Override
	long getPasswordExpiration() throws IOException;

	@Override
	boolean setPassword(char[] saltedSHA256PasswordHash) throws IOException;

	@Override
	void connected() throws IOException;

}
