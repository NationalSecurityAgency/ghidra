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
package ghidra.app.plugin.core.go.ipc;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.*;

import docking.DialogComponentProvider;
import ghidra.app.plugin.core.go.GhidraGoSender;
import ghidra.app.plugin.core.go.dialog.GhidraGoWaitForListenerDialog;
import ghidra.app.plugin.core.go.exception.StopWaitingException;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;

public class GhidraGoIPCTest extends AbstractGhidraHeadedIntegrationTest {
	private GhidraGoSender sender;
	private GhidraGoListener listener;
	private String url = "ghidra://testing/testProject";
	private TestEnv env;

	public GhidraGoIPCTest() throws IOException {
		sender = new GhidraGoSender();
	}

	@Before
	public void setUp() throws IOException {
		env = new TestEnv(); // need this so that Application is initialized

		CheckForFileProcessedRunnable.WAIT_FOR_PROCESSING_DELAY_MS = 1000;
		CheckForFileProcessedRunnable.MAX_WAIT_FOR_PROCESSING_MIN = 1;
		CheckForFileProcessedRunnable.WAIT_FOR_PROCESSING_PERIOD_MS = 10;

		CheckForListenerRunnable.WAIT_FOR_LISTENER_DELAY_MS = 1000;
		CheckForListenerRunnable.MAX_WAIT_FOR_LISTENER_MIN = 1;
		CheckForListenerRunnable.WAIT_FOR_LISTENER_PERIOD_MS = 10;
	}

	@After
	public void tearDown() {
		if (env != null) {
			env.dispose();
		}

		sender.dispose();
		if (listener != null) {
			listener.dispose();
		}

		waitFor(() -> !sender.isGhidraListening());
	}

	public Thread sendExpectingStopWaitingException() {
		Thread t = new Thread(() -> {
			try {
				sender.send(url);
				assertFalse(true); // fail
			}
			catch (StopWaitingException e) {
				// passed
			}
		});
		t.start();
		return t;
	}

	public Thread sendExpectingSuccess() {
		Thread t = new Thread(() -> {
			try {
				sender.send(url);
				// passed
			}
			catch (StopWaitingException e) {
				assertFalse(true); // fail
			}
		});
		t.start();
		return t;
	}

	@Test
	public void testSendingWithNoListener() throws InterruptedException {
		// given no listener is listening and the timeout is 0
		waitFor(() -> !sender.isGhidraListening());
		CheckForListenerRunnable.WAIT_FOR_LISTENER_DELAY_MS = 0;
		CheckForFileProcessedRunnable.WAIT_FOR_PROCESSING_DELAY_MS = 0;

		// then a the wait for listener dialog should appear on send
		Thread t = sendExpectingStopWaitingException();

		DialogComponentProvider dialog =
			waitForDialogComponent(GhidraGoWaitForListenerDialog.class);

		// when Wait is pressed, the dialog should reappear with no timeout
		pressButtonByText(dialog, "Wait");

		// then pressing No when the dialog appears again should stop waiting
		dialog = waitForDialogComponent(GhidraGoWaitForListenerDialog.class);
		pressButtonByText(dialog, "No");

		t.join();
	}

	@Test
	public void testSendingWithListener() throws IOException, InterruptedException {
		// given a listener is listening and processing new urls
		listener = new GhidraGoListener((passedURL) -> {
			Msg.info(this, "Found " + passedURL + " in test");
		});
		waitFor(sender::isGhidraListening);

		// then the sender should not throw an exception when sending a url
		Thread t = sendExpectingSuccess();
		t.join();
	}

	@Test
	public void testInterruptingListener() throws IOException, InterruptedException {
		// given a listener is listening and processing new urls
		listener = new GhidraGoListener((passedURL) -> {
			Msg.info(this, "Found " + passedURL + " in test");
		});
		waitFor(sender::isGhidraListening);

		// then sending a url before disposing the listener should succeed
		Thread t = sendExpectingSuccess();
		t.join();

		// when the listener is disposed
		listener.dispose();

		// given no listener is listening and the timeout is 0
		waitFor(() -> !sender.isGhidraListening());
		CheckForListenerRunnable.WAIT_FOR_LISTENER_DELAY_MS = 0;
		CheckForFileProcessedRunnable.WAIT_FOR_PROCESSING_DELAY_MS = 0;

		// then sending a url should fail
		t = sendExpectingStopWaitingException();
		DialogComponentProvider dialog =
			waitForDialogComponent(GhidraGoWaitForListenerDialog.class);
		pressButtonByText(dialog, "No");
		t.join();
	}
}
