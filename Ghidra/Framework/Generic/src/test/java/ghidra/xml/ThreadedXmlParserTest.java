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
package ghidra.xml;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.LinkedBlockingQueue;

import javax.swing.SwingUtilities;

import org.junit.Assert;
import org.junit.Test;
import org.xml.sax.*;

import generic.test.AbstractGenericTest;

public class ThreadedXmlParserTest extends AbstractGenericTest {
	private static final String GOOD_XML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<doc>" + "<project name=\"foo\"/>" + "<project name=\"foo\"/>" +
		"<project name=\"foo\"/>" + "<project name=\"foo\"/>" + "<project name=\"foo\"/>" +
		"<project name=\"foo\"/>" + "<project name=\"foo\"/>" + "</doc>";

	private static final String BAD_XML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + "<doc>" +
		"<project name=\"foo\"/>" + "<project name=\"foo\"/" + "<project name=\"foo\"/>" +
		"<project name=\"foo\"/>" + "<project name=\"foo\"/>" + "<project name=\"foo\"/>" +
		"<project name=\"foo\"/>" + "</doc>";

	
	private static final String XXE_XML = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n" +
		"<!DOCTYPE foo [\n" + "    <!ELEMENT foo ANY >\n" +
		"<!ENTITY xxe SYSTEM \"file://@TEMP_FILE@\">]><foo>&xxe; fizzbizz</foo>";
	
	public ThreadedXmlParserTest() {
		super();
	}

	/**
	 * <p>
	 * XML External Entities attacks benefit from an XML feature to build documents dynamically at 
	 * the time of processing.  An XML entity allows inclusion of data dynamically from a given 
	 * resource.  External entities allow an XML document to include data from an external URI. 
	 * Unless configured to do otherwise, external entities force the XML parser to access the 
	 * resource specified by the URI, e.g., a file on the local machine or remote system. 
	 * This behavior exposes the application to XML External Entity (XXE) attacks.
	 * <p>
	 * Normally, a custom Entity Resolver implementing org.xml.sax.EntityResolver should not return null 
	 * as it will then default to the SAX Entity Resolver that allows and resolves external 
	 * entities. 
	 * <p>
	 * This test ensures external entities are ignored whether or not a default SAX Entity Resolver 
	 * is used. Using the ThreadedXmlPullParserImpl constructor which takes an InputStream (rather 
	 * than ResourceFile) will use a default Entity Resolver. The XmlUtilities.createSecureSAXParserFactory 
	 * factory configurations will disable external entities regardless of which Entity Resolver is used.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testXXEXml() throws Exception {
		// Create file with contents
		String fileContents = "foobar";
		File xxeFile = createTempFileForTest();
		Files.write(xxeFile.toPath(), fileContents.getBytes());
		// Place file path in XML ENTITY
		String xxeXml = XXE_XML.replace("@TEMP_FILE@", xxeFile.getPath());

		// This constructor will use a default EntityResolver
		ThreadedXmlPullParserImpl parser =
			new ThreadedXmlPullParserImpl(new ByteArrayInputStream(xxeXml.getBytes()),
				testName.getMethodName(), new TestErrorHandler(), false, 3);

		parser.start("foo");
		XmlElement x1 = parser.next();

		assertFalse("File contents (external entity) should not be in xml.",
			x1.getText().contains(fileContents));
	}

	@Test
	public void testGoodXml() throws Exception {

		ThreadedXmlPullParserImpl parser =
			new ThreadedXmlPullParserImpl(new ByteArrayInputStream(GOOD_XML.getBytes()),
				testName.getMethodName(), new TestErrorHandler(), false, 3);

		parser.start("doc");
		XmlElement projectXml = parser.start("project");
		assertNotNull(projectXml);
		assertEquals("foo", projectXml.getAttribute("name"));
		parser.end(projectXml);
		assertTrue("parser should be running", parser.isParsing());
		while (parser.hasNext()) {
			parser.next();
		}
		assertTrue("parser should be shutdown", !parser.isParsing());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testGoodXmlEarlyExit() throws Exception {

		ThreadedXmlPullParserImpl parser =
			new ThreadedXmlPullParserImpl(new ByteArrayInputStream(GOOD_XML.getBytes()),
				testName.getMethodName(), new TestErrorHandler(), false, 3);

		parser.start("doc");
		XmlElement projectXml = parser.start("project");
		assertNotNull(projectXml);
		assertEquals("foo", projectXml.getAttribute("name"));
		parser.end(projectXml);

		LinkedBlockingQueue<XmlElement> queue =
			(LinkedBlockingQueue<XmlElement>) getInstanceField("queue", parser);

		// wait until queue is filled
		while (queue.size() < 3) {
			Thread.yield();
		}

		assertTrue("parser should be running", parser.isParsing());
		parser.dispose();
		int count = 0;
		while (parser.isParsing()) {
			if (count++ > 20) {
				Assert.fail("parser should have shutdown");
			}
			Thread.sleep(1);
		}
		assertTrue("parser should be shutdown", !parser.isParsing());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testInterruptingParserThreadDoesNotDeadlockClientThread() throws Exception {
		final ThreadedXmlPullParserImpl parser =
			new ThreadedXmlPullParserImpl(new ByteArrayInputStream(GOOD_XML.getBytes()),
				testName.getMethodName(), new TestErrorHandler(), false, 3);

		parser.start("doc");
		XmlElement projectXml = parser.start("project");
		assertNotNull(projectXml);
		assertEquals("foo", projectXml.getAttribute("name"));
		parser.end(projectXml);

		LinkedBlockingQueue<XmlElement> queue =
			(LinkedBlockingQueue<XmlElement>) getInstanceField("queue", parser);

		// wait until queue is filled
		while (queue.size() < 3) {
			Thread.yield();
		}

		ThreadGroup threadGroup = Thread.currentThread().getThreadGroup();
		Thread[] threads = new Thread[threadGroup.activeCount() * 2];
		threadGroup.enumerate(threads);

		Thread parserThread = null;
		for (Thread thread : threads) {
			if (thread.getName().startsWith("XMLParser-")) {
				parserThread = thread;
				break;
			}
		}

		assertNotNull(parserThread);

		// 
		// Empty the queue and make sure that we don't deadlock
		//
		final CyclicBarrier startBarrier = new CyclicBarrier(1);
		final boolean[] container = new boolean[] { false };
		new Thread(() -> {
			try {
				startBarrier.await();
			}
			catch (Throwable e) {
				e.printStackTrace();
			}

			while (parser.hasNext()) {
				parser.next();
			}

			container[0] = true;
		}).start();

		// 
		// Interrupt the thread to make sure that this doesn't destroy the world (or deadlock)
		//
		parserThread.interrupt();

		startBarrier.await();// tell the 

		waitForFinish(container);

	}

	private void waitForFinish(boolean[] container) {
		int numWaits = 0;
		int sleepyTime = 100;
		while (!container[0] && numWaits < 50) {
			numWaits++;
			sleep(sleepyTime);
		}
		if (!container[0]) {
			Assert.fail("Parser did not finished - DEADLOCK!");
		}
	}

	@Test
	public void testBadXml() throws Exception {

		TestErrorHandler errHandler = new TestErrorHandler();
		ThreadedXmlPullParserImpl parser =
			new ThreadedXmlPullParserImpl(new ByteArrayInputStream(BAD_XML.getBytes()),
				testName.getMethodName(), errHandler, false, 3);

		//
		// Depending upon how quickly the parser thread starts, the code below will fail at 
		// either the start() call or the hasNext() call.
		//

		try {
			parser.start("doc");
			assertTrue("parser should be running", parser.isParsing());

			while (parser.hasNext()) {
				parser.next();
			}
			Assert.fail("Did not get expected runtime exception from hasNext()");
		}
		catch (Exception e) {
			// expected
		}
		assertNotNull(errHandler.myException);
		assertTrue("parser should be shutdown", !parser.isParsing());

	}

	@Test
	public void testDisposeInAnotherThread() throws Exception {
		final ThreadedXmlPullParserImpl parser =
			new ThreadedXmlPullParserImpl(new ByteArrayInputStream(GOOD_XML.getBytes()),
				testName.getMethodName(), new TestErrorHandler(), false, 3);

		parser.start("doc");
		XmlElement projectXml = parser.start("project");
		assertNotNull(projectXml);
		assertEquals("foo", projectXml.getAttribute("name"));
		parser.end(projectXml);
		assertTrue("parser should be running", parser.isParsing());
		SwingUtilities.invokeAndWait(() -> parser.dispose());

		int count = 0;
		while (parser.isParsing()) {
			if (count++ > 10) {
				Assert.fail("parser should have shutdown");
			}
			Thread.sleep(1);
		}
		try {
			parser.hasNext();
			Assert.fail("Expected exception");
		}
		catch (Exception e) {
			// expected
		}

	}

	@Test
	public void testMoreJobsThanThreads() throws Exception {
		List<XmlPullParser> parsers = new ArrayList<>();
		for (int i = 0; i < 25; i++) {
			parsers.add(new ThreadedXmlPullParserImpl(new ByteArrayInputStream(GOOD_XML.getBytes()),
				testName.getMethodName(), new TestErrorHandler(), false, 3));
		}
		for (XmlPullParser xmlPullParser : parsers) {
			xmlPullParser.dispose();
		}
	}

	private static class TestErrorHandler implements ErrorHandler {
		public SAXParseException myException;

		@Override
		public void error(SAXParseException exception) throws SAXException {
			myException = exception;
		}

		@Override
		public void fatalError(SAXParseException exception) throws SAXException {
			myException = exception;
		}

		@Override
		public void warning(SAXParseException exception) throws SAXException {
			System.err.println("Warning");
		}
	}
}
