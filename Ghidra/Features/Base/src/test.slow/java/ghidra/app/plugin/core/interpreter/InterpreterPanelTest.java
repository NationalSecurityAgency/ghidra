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
package ghidra.app.plugin.core.interpreter;

import static org.junit.Assert.*;

import java.io.*;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;

import org.apache.commons.lang3.StringUtils;
import org.junit.*;

import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.framework.options.ToolOptions;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.DummyTool;
import resources.Icons;

/**
 * Test the InterpreterPanel/InterpreterConsole's stdIn InputStream handling by 
 * manually creating a JFrame (while a regular Ghidra tool is running)
 * to host the panel in. 
 */
public class InterpreterPanelTest extends AbstractGhidraHeadedIntegrationTest {

	private JFrame frame;
	private InterpreterPanel ip;
	private JTextPane inputTextPane;
	private Document inputDoc;
	private BufferedReader reader;

	@Before
	public void setUp() throws Exception {

		ip = createIP();
		inputTextPane = ip.inputTextPane;
		inputDoc = inputTextPane.getDocument();
		reader = new BufferedReader(new InputStreamReader(ip.getStdin()));
		frame = new JFrame("InterpreterPanel test frame");
		frame.getContentPane().add(ip);
		frame.setSize(400, 400);
		runSwing(() -> frame.setVisible(true));
	}

	@After
	public void tearDown() throws Exception {
		runSwing(() -> {
			frame.setVisible(false);
			frame.dispose();
		});
	}

	@Test(timeout = 20000)
	public void testInputStream_AddRead() throws Exception {
		doBackgroundTriggerTextTest(List.of("test1", "abc123"));
	}

	@Test(timeout = 20000)
	public void testInputStream_ClearResetsStream() throws Exception {
		doBackgroundTriggerTextTest(List.of("test1", "abc123"));
		doSwingMultilinePasteTest(List.of("testLine1", "testLine2", "testLine3"));

		ip.clear();

		doBackgroundTriggerTextTest(List.of("test2", "abc456"));
		doSwingMultilinePasteTest(List.of("testLine4", "testLine5", "testLine6"));
	}

	@Test(timeout = 20000)
	public void testInputStream_CloseStreamBeforeReading() throws Exception {

		ip.getStdin().close();

		assertNull(reader.readLine());	// should always get NULL results because stream is now 'closed'
		assertNull(reader.readLine());	//    "     "

		ip.stdin.addText("test_while_closed\n");	// text added after close shouldn't be preserved
		assertNull(reader.readLine());	// should always get NULL results because stream is now 'closed'
		ip.clear();						// stream should now be open again
		doBackgroundTriggerTextTest(List.of("test2", "abc456"));
	}

	@Test(timeout = 20000)
	public void testInputStream_CloseStreamWhileBlocking() throws Exception {

		AtomicReference<String> result = new AtomicReference<>("Non-null value");
		doBackgroundReadLine(result); // this thread will block on readLine()

		ip.getStdin().close();

		// this will be set to null when readLine() returns
		waitFor(() -> result.get() == null);

		ip.clear();			// stream should now be open again
		doBackgroundTriggerTextTest(List.of("test2", "abc456"));
	}

	@Test(timeout = 20000)
	public void testInputStream_InterruptStreamWhileBlocking() throws Exception {

		AtomicReference<String> result = new AtomicReference<>("Non-null value");
		Thread t = doBackgroundReadLine(result); // this thread will block on readLine()

		t.interrupt();

		// this will be set to null when readLine() returns
		waitFor(() -> result.get() == null);

		ip.clear();			// stream should now be open again
		doBackgroundTriggerTextTest(List.of("test2", "abc456"));
	}

	@Test(timeout = 20000)
	public void testInputStream_ReadSingleBytes() throws IOException {

		doBackgroundPasteTest1AtATime("testvalue\n");

		CountDownLatch startLatch = new CountDownLatch(1);
		closeStreamViaBackgroundThread(startLatch);
		startLatch.countDown();

		assertEquals(-1, ip.getStdin().read());
	}

	@Test(timeout = 20000)
	public void testInputStream_Available() throws IOException {

		assertEquals(0, ip.getStdin().available());

		triggerText(inputTextPane, "testvalue\n");
		waitForSwing();

		assertTrue(ip.getStdin().available() > 0);
	}

	private InterpreterPanel createIP() {
		InterpreterConnection dummyIC = new InterpreterConnection() {
			@Override
			public String getTitle() {
				return "Dummy Title";
			}

			@Override
			public ImageIcon getIcon() {
				return Icons.STOP_ICON;
			}

			@Override
			public List<CodeCompletion> getCompletions(String cmd) {
				return List.of();
			}
		};

		DummyTool tool = new DummyTool() {
			@Override
			public ToolOptions getOptions(String categoryName) {
				return new ToolOptions("Dummy");
			}
		};
		InterpreterPanel result = new InterpreterPanel(tool, dummyIC);
		result.setPrompt("PROMPT:");
		return result;
	}

	private void doSwingMultilinePasteTest(List<String> multiLineTestValues)
			throws IOException {
		// simulates what happens during a paste when multi-line string with
		// "\n"s is pasted.
		runSwingLater(() -> {
			try {
				String multiLineString = StringUtils.join(multiLineTestValues, "\n") + '\n';
				inputDoc.insertString(0, multiLineString, null);
			}
			catch (BadLocationException e) {
				// ignore
			}
		});

		for (String expectedValue : multiLineTestValues) {
			String actualValue = reader.readLine();
			assertEquals(expectedValue, actualValue);
		}
	}

	private void doBackgroundPasteTest1AtATime(String testValue) throws IOException {
		runSwingLater(() -> {
			try {
				inputDoc.insertString(0, testValue, null);
			}
			catch (BadLocationException e) {
				// ignore
			}
		});
		for (int i = 0; i < testValue.length(); i++) {
			char expectedChar = testValue.charAt(i);
			int actualValue = ip.getStdin().read();
			assertEquals(expectedChar, (char) actualValue);
		}
	}

	private void doBackgroundTriggerTextTest(List<String> testValues) throws Exception {

		new Thread(() -> {
			for (String s : testValues) {
				triggerText(inputTextPane, s + "\n");
			}
		}).start();

		for (String expectedValue : testValues) {
			String actualValue = reader.readLine();
			assertEquals(expectedValue, actualValue);
		}
	}

	private Thread doBackgroundReadLine(AtomicReference<String> result)
			throws InterruptedException {

		CountDownLatch startLatch = new CountDownLatch(1);
		Thread t = new Thread(() -> {
			try {
				startLatch.countDown();
				result.set(reader.readLine());
			}
			catch (IOException e) {
				// test will fail
			}
		});
		t.start();

		startLatch.await(2, TimeUnit.SECONDS); // the background thread is now spun-up and ready to read

		// the smallest of sleeps to give the thread a chance to read after the latch was reached
		sleep(10);

		return t;
	}

	private void closeStreamViaBackgroundThread(CountDownLatch startLatch) {

		new Thread(() -> {
			try {
				startLatch.await(2, TimeUnit.SECONDS);

				// the smallest of sleeps to give the thread a chance to read after the latch was reached
				sleep(10);

				ip.getStdin().close();
			}
			catch (InterruptedException | IOException e) {
				// ignore
			}
		}).start();
	}
}
