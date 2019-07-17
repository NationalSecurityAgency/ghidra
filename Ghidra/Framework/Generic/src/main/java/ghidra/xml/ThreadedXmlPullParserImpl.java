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

import java.io.*;
import java.util.*;
import java.util.concurrent.*;

import javax.xml.parsers.*;

import org.xml.sax.*;
import org.xml.sax.helpers.DefaultHandler;

import generic.concurrent.GThreadPool;
import generic.jar.ResourceFile;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;

/**
 * Constructs a new XML parser. This is class is designed for reading XML files.
 * It is built on top of a ContentHandler. However, instead of being a "push"
 * pattern, it has been translated into a "pull" pattern. That is, the user of
 * this class can process the elements as needed. As well as skipping elements
 * as needed.
 */
class ThreadedXmlPullParserImpl extends AbstractXmlPullParser {

	// Special XmlElement used to tell pulling thread that the pushing thread is done.
	private final static XmlElement XML_END_TOKEN =
		new XmlElementImpl(false, false, "END TOKEN", -1, null, null, 0, 0);

	private final String name;
	private final LinkedBlockingQueue<XmlElement> queue;
	private Locator locator;
	private final HashMap<String, HashMap<String, String>> processingInstructions = new HashMap<>();

	private final Future<?> parsingTask;

	private XmlElement nextElement;
	private volatile boolean isParsing = false;
	private volatile Exception exception;
	private volatile boolean disposed;

	private GThreadPool threadPool;

	/**
	 * Constructs a new parser using the specified XML file.
	 * 
	 * @param file the input XML file
	 * @param errHandler the XML error handler
	 * @param validate true if the parse should validate against the DTD
	 * @throws SAXException if an XML parse error occurs
	 * @throws IOException if an i/o error occurs
	 */
	ThreadedXmlPullParserImpl(File file, ErrorHandler errHandler, boolean validate, int capacity)
			throws SAXException, IOException {
		this(new ResourceFile(file), errHandler, validate, capacity);
	}

	/**
	 * Constructs a new parser using the specified XML file.
	 * 
	 * @param file the input XML file
	 * @param errHandler the XML error handler
	 * @param validate true if the parse should validate against the DTD
	 * @throws SAXException if an XML parse error occurs
	 * @throws IOException if an i/o error occurs
	 */
	ThreadedXmlPullParserImpl(ResourceFile file, ErrorHandler errHandler, boolean validate,
			int capacity) throws SAXException, IOException {
		this.name = file.getName();
		queue = new LinkedBlockingQueue<>(capacity);
		ContentHandlerRunnable runnable = new ContentHandlerRunnable(file.getParentFile(),
			file.getInputStream(), errHandler, validate);

		threadPool = GThreadPool.getSharedThreadPool("XMLParser");
		parsingTask = threadPool.submit(runnable);
	}

	/**
	 * Constructs a new parser using the specified input stream.
	 * <p>
	 * Note: Only use this method if you know that the XML in the given stream
	 * contains its own internal validation (an internal dtd specification). For
	 * XML files that use an external dtd file you should call
	 * {@link #XmlParser(File, ErrorHandler, boolean)}.
	 * <p>
	 * 
	 * @param input the XML input stream
	 * @param inputName the name of the input stream
	 * @param errHandler the XML error handler
	 * @param validate true if the parse should validate against the DTD
	 * @throws SAXException if an XML parse error occurs
	 * @throws IOException if an i/o error occurs
	 */
	ThreadedXmlPullParserImpl(InputStream input, String inputName, ErrorHandler errHandler,
			boolean validate, int capacity) throws SAXException {
		this.name = inputName;
		queue = new LinkedBlockingQueue<>(capacity);
		ContentHandlerRunnable runnable =
			new ContentHandlerRunnable(null, input, errHandler, validate);

		threadPool = GThreadPool.getSharedThreadPool("XMLParser");
		parsingTask = threadPool.submit(runnable);
	}

	private void checkForException() {
		if (exception != null) {
			throw new RuntimeException(exception);
		}
		if (disposed) {
			throw new RuntimeException("Xml Parser was disposed!");
		}
	}

	/**
	 * Returns the value of the attribute of the processing instruction. For
	 * example, <code>&lt;?program_dtd version="1"?&gt;</code>
	 * 
	 * @param piName the name of the processing instruction
	 * @param attribute the name of the attribute
	 * @return the value of the attribute of the processing instruction
	 */
	@Override
	public String getProcessingInstruction(String piName, String attribute) {
		hasNext(); // make sure we have read up to the first element
		Map<String, String> map = processingInstructions.get(piName.toUpperCase());
		if (map == null) {
			return null;
		}
		return map.get(attribute.toUpperCase());
	}

	/**
	 * Returns true if the parser has more elements to read.
	 * 
	 * @return true if the parser has more elements to read
	 */
	@Override
	public boolean hasNext() {
		nextElement = waitForNextElement(nextElement);
		return nextElement != XML_END_TOKEN;
	}

	private XmlElement waitForNextElement(XmlElement element) {
		checkForException();

		while (element == null) {
			try {
				element = queue.poll(10, TimeUnit.SECONDS);
			}
			catch (InterruptedException e) {
				// try again, checking exit conditions.
			}
			checkForException();
		}

		return element;
	}

	/**
	 * Returns the next element to be read, but does not increment the iterator.
	 * 
	 * @return the next element to be read, but does not increment the iterator
	 */
	@Override
	public XmlElement peek() {
		if (hasNext()) {
			return nextElement;
		}
		return null;
	}

	/**
	 * Returns the next element to be read and increments the iterator.
	 * 
	 * @return the next element to be read and increments the iterator
	 */
	@Override
	public XmlElement next() {
		if (hasNext()) {
			XmlElement elementToReturn = nextElement;
			nextElement = null;
			return elementToReturn;
		}
		return null;
	}

	/**
	 * Disposes this XML parser. No more elements may be read after dispose is
	 * called.
	 */
	@Override
	public void dispose() {
		disposed = true;
		parsingTask.cancel(true);
//		Msg.debug(this, id + "Disposed");
	}

	private class ContentHandlerRunnable implements Runnable {
		private InputStream input;
		private DefaultContentHandlerWrapper contentHandler;
		private SAXParser saxParser;
		private ResourceFile resolveDir;

		ContentHandlerRunnable(ResourceFile parent, InputStream input, ErrorHandler errHandler,
				boolean validate) throws SAXException {
			this.resolveDir = parent;
			this.input = input;
			this.contentHandler = new DefaultContentHandlerWrapper(errHandler);

			try {
				SAXParserFactory saxParserFactory = XmlUtilities.createSecureSAXParserFactory(true);
				saxParserFactory.setFeature("http://xml.org/sax/features/namespaces", false);
				saxParserFactory.setFeature("http://xml.org/sax/features/validation", validate);
				saxParser = saxParserFactory.newSAXParser();
				saxParser.getXMLReader().setEntityResolver((publicId, systemId) -> {
					if (resolveDir == null) {
						return null;
					}
					ResourceFile resolvedFile =
						new ResourceFile(resolveDir, new File(systemId).getName());
					InputSource inputSource = new InputSource();
					inputSource.setPublicId(publicId);
					inputSource.setSystemId(resolvedFile.toURI().toString());
					return inputSource;
				});
			}
			catch (ParserConfigurationException e) {
				Msg.error(this, e.getMessage());
				throw new SAXException(e);
			}
		}

		@Override
		public void run() {
			isParsing = true;

			Thread thread = Thread.currentThread();
			String originalThreadName = thread.getName();
			try {
				thread.setName(originalThreadName + " - " + name);

				InputSource inputSource = new InputSource(input);

				// set the handlers individually instead of passing to the SaxParser convenience
				// parse() method that takes a DefaultHandler.  Otherwise, the DefaultHandler
				// will replace the XMLEntityResolver that we set up in our constructor.

				XMLReader reader = saxParser.getXMLReader();
				reader.setContentHandler(contentHandler);
				reader.setErrorHandler(contentHandler);
				reader.setDTDHandler(contentHandler);
				reader.parse(inputSource);
			}
			catch (Exception e) {
				// Note: we added this log message here to print the exception to the log.  The
				//       rationale is that, due to the threaded nature of this parser, this
				//       exception may not be discovered by clients (for example, if the client
				//       is done reading elements before the exception is encountered by this
				//       thread).  By logging it here, we can inspect the logs for ill-formatted
				//       XML content that is not manifesting a bug.   If this causes undue 
				//       noise, then we can make this a trace() call.
				//Msg.debug(this, "Exception parsing XML", e);
				ThreadedXmlPullParserImpl.this.exception = e;
			}
			finally {
				isParsing = false;
				thread.setName(originalThreadName);
				closeQueue();
			}

			try {
				input.close();
			}
			catch (IOException e) {
				// we tried
			}
		}
	}

	private void closeQueue() {
		addElement(XML_END_TOKEN); // tells pulling/client thread that we are done!
	}

	private void addElement(XmlElement element) {
		while (!disposed) {
			try {
				queue.put(element);
				return;
			}
			catch (InterruptedException e) {
				// may have received an interrupt from previous client
				// if the interrupt was intended for us, our dispose flag will be set.
			}
		}
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public boolean isPullingContent() {
		return false;
	}

	@Override
	public void setPullingContent(boolean pullingContent) {
		if (pullingContent) {
			throw new RuntimeException("this impl can't inject content");
		}
	}

	// for testing
	boolean isParsing() {
		return isParsing;
	}

	private class DefaultContentHandlerWrapper extends DefaultHandler {
		private StringBuilder textBuf = new StringBuilder();
		private final ErrorHandler errorHandler;

		public DefaultContentHandlerWrapper(ErrorHandler errorHandler) {
			this.errorHandler = errorHandler;
		}

		@Override
		public InputSource resolveEntity(String publicId, String systemId)
				throws SAXException, IOException {
			return null;
		}

		@Override
		public void error(SAXParseException e) throws SAXException {
			if (errorHandler == null) {
				return;
			}
			errorHandler.error(e);
		}

		@Override
		public void fatalError(SAXParseException e) throws SAXException {
			if (errorHandler == null) {
				return;
			}
			errorHandler.fatalError(e);
		}

		@Override
		public void warning(SAXParseException e) throws SAXException {
			if (errorHandler == null) {
				return;
			}
			errorHandler.warning(e);
		}

		@Override
		public void characters(char[] ch, int start, int length) throws SAXException {
			textBuf.append(ch, start, length);
		}

		@Override
		public void setDocumentLocator(Locator locator) {
			ThreadedXmlPullParserImpl.this.locator = locator;
		}

		@Override
		public void processingInstruction(String target, String data) throws SAXException {
			target = target.toUpperCase();
			HashMap<String, String> map = processingInstructions.get(target);
			if (map == null) {
				map = new HashMap<>();
				processingInstructions.put(target, map);
			}
			StringTokenizer st = new StringTokenizer(data);
			while (st.hasMoreTokens()) {
				parseAttributeValue(map, st.nextToken());
			}
		}

		private void parseAttributeValue(HashMap<String, String> map, String attrValuePair) {
			int ix = attrValuePair.indexOf('=');
			if (ix < 1 || ix == (attrValuePair.length() - 1)) {
				return;
			}
			String attr = attrValuePair.substring(0, ix);
			String value = attrValuePair.substring(++ix);
			if (value.startsWith("\"") && value.endsWith("\"")) {
				value = value.substring(1, value.length() - 1);
			}
			map.put(attr.toUpperCase(), value.toUpperCase());
		}

		@Override
		public void endElement(String namespaceURI, String localName, String qName)
				throws SAXException {
			addElement(new XmlElementImpl(false, true, qName, level, null, textBuf.toString(),
				locator.getColumnNumber(), locator.getLineNumber()));
			textBuf = new StringBuilder();
			--level;
		}

		private int level = -1;

		@Override
		public void startElement(String namespaceURI, String localName, String qName,
				Attributes atts) throws SAXException {
			++level;
			// NOTE: must clear the string buffer
			// because all white space between nested start tags
			// will be appended to the buffer
			textBuf.setLength(0);
			LinkedHashMap<String, String> attrMap = new LinkedHashMap<>();
			final int length = atts.getLength();
			for (int ii = 0; ii < length; ++ii) {
				attrMap.put(atts.getQName(ii), atts.getValue(ii));
			}
			addElement(new XmlElementImpl(true, false, qName, level, attrMap, null,
				locator.getColumnNumber(), locator.getLineNumber()));
		}
	}

}
