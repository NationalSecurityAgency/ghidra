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
package ghidra.server.remote;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import db.buffers.DataBuffer;
import db.buffers.ManagedBufferFileHandle;
import generic.test.AbstractGenericTest;
import generic.test.category.PortSensitiveCategory;
import ghidra.framework.remote.RepositoryHandle;
import ghidra.server.*;
import ghidra.util.Msg;
import utilities.util.FileUtilities;

/**
 * This cannot extend GenericTestCase because GenericTestCase pulls in
 * the AWT stuff, and we don't want to do that here.
 *
 */
@Category(PortSensitiveCategory.class)
public class GhidraServerAWTTest extends AbstractGenericTest {

	public static final long TIME_TO_STAND_UP_SERVER_SECS = 3;

	@Test
	public void testAWTPresence() throws Exception {

		Thread eventReaderThread = null;

		File myTmpDir = new File(getTestDirectoryPath(), "GSAWTT");
		try {
			myTmpDir.mkdir();

			ServerPortFactory.setBasePort(14100); // same as ServerTestUtil port

			// directly instantiate to avoid GhidraServer.main which may
			// invoke System.exit
			GhidraServer server = new GhidraServer(myTmpDir, GhidraServer.AuthMode.NO_AUTH_LOGIN,
				null, true, true, -1, true, false, null);

			// exercise server elements, including a repository and buffer file
			RepositoryManager mgr = (RepositoryManager) getInstanceField("mgr", server);
			UserManager userManager = mgr.getUserManager();
			userManager.addUser("test");

			Repository repo = mgr.createRepository("test", "testRepo");  // bypass authentication
			RepositoryHandle repoHandle = new RepositoryHandleImpl("test", repo);

			// The server will perform a timer-based file handle check once per second in test mode and
			// force disposal of all disconnected handles if a getEvents has not be serviced since the
			// previous check
			eventReaderThread = new Thread(() -> {
				try {
					while (true) {
						repoHandle.getEvents();
						Msg.info(this, "Reading repo events to keep server happy :)");
						Thread.sleep(500);
					}
				}
				catch (Exception e) {
					// ignore
				}
			});
			eventReaderThread.start();

			ManagedBufferFileHandle bf =
				repoHandle.createDatabase("/", "testFile", "123", 2048, "Nada", "NA");
			long checkinID = bf.getCheckinID();
			DataBuffer dbuf = new DataBuffer(2048) { /* access protected constructor */ };
			dbuf.putInt(0, 567);
			bf.close();
			bf.dispose();

			Msg.info(this, "File created");

			// delay before checking
			Thread.sleep(TIME_TO_STAND_UP_SERVER_SECS * 1000);

			assertNotNull("file is missing", repoHandle.getItem("/", "testFile"));

			assertTrue("file checkout is missing", repoHandle.hasCheckouts("/", "testFile"));

			repoHandle.terminateCheckout("/", "testFile", checkinID, false);

			repoHandle.deleteItem("/", "testFile", -1);

			Thread.sleep(TIME_TO_STAND_UP_SERVER_SECS * 1000);

			assertFalse("GhidraServer has started the AWT", ThreadUtils.isAWTThreadPresent());
		}
		finally {
			if (eventReaderThread != null) {
				eventReaderThread.interrupt();
			}
			FileUtilities.deleteDir(myTmpDir);
		}
	}

}
