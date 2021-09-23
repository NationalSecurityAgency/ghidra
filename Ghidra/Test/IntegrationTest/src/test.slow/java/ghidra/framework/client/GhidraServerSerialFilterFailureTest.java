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
package ghidra.framework.client;

import static org.junit.Assert.*;

import java.io.File;
import java.io.InvalidClassException;
import java.rmi.RemoteException;
import java.rmi.UnmarshalException;
import java.security.Principal;
import java.util.HashSet;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;

import org.junit.*;
import org.junit.experimental.categories.Category;

import generic.test.category.PortSensitiveCategory;
import ghidra.framework.model.ServerInfo;
import ghidra.framework.remote.GhidraServerHandle;
import ghidra.net.ApplicationKeyManagerFactory;
import ghidra.server.remote.ServerTestUtil;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import utilities.util.FileUtilities;

@Category(PortSensitiveCategory.class)
public class GhidraServerSerialFilterFailureTest extends AbstractGhidraHeadlessIntegrationTest {

	private File serverRoot;

	@Before
	public void setUp() throws Exception {
		System.clearProperty(ApplicationKeyManagerFactory.KEYSTORE_PATH_PROPERTY);
	}

	@After
	public void tearDown() throws Exception {
		closeAllWindows();
		killServer();

		ClientUtil.clearRepositoryAdapter("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT);
	}

	private void killServer() {

		if (serverRoot == null) {
			return;
		}

		ServerTestUtil.disposeServer();

		FileUtilities.deleteDir(serverRoot);
	}

	private void startServer(int authMode, boolean altLoginName, boolean enableSSH,
			boolean enableAnonymous) throws Exception {

		// Create server instance
		serverRoot = new File(getTestDirectoryPath(), "TestServer");

		ServerTestUtil.startServer(serverRoot.getAbsolutePath(),
			ServerTestUtil.GHIDRA_TEST_SERVER_PORT, authMode, altLoginName, enableSSH,
			enableAnonymous);
	}


	static class BogusPrincipal implements Principal, java.io.Serializable {

		private String username;

		public BogusPrincipal(String username) {
			this.username = username;
		}

		@Override
		public String getName() {
			return username;
		}
	}

	private static Subject getBogusUserSubject() {
		String username = ClientUtil.getUserName();
		HashSet<BogusPrincipal> pset = new HashSet<>();
		HashSet<Object> emptySet = new HashSet<>();
		pset.add(new BogusPrincipal(username));
		Subject subj = new Subject(false, pset, emptySet, emptySet);
		return subj;
	}

	@Test
	public void testSerializationFailure() throws Exception {

		ServerTestUtil.setLocalUser("test");
		startServer(-1, false, false, false);

		ServerInfo server = new ServerInfo("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT);
		
		GhidraServerHandle serverHandle = ServerConnectTask.getGhidraServerHandle(server);
		
		try {
			serverHandle.getRepositoryServer(getBogusUserSubject(), new Callback[0]);
			fail("serial filter rejection failed to perform");
		}
		catch (RemoteException e) {
			Throwable cause = e.getCause();
			assertTrue("expected remote unmarshall exception", cause instanceof UnmarshalException);
			cause = cause.getCause();
			assertTrue("expected remote invalid class exceptionn",
				cause instanceof InvalidClassException);
		}
		
	}

}
