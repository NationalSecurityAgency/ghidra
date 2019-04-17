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

import javax.xml.parsers.*;

import org.xml.sax.*;
import org.xml.sax.helpers.DefaultHandler;

import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;

public class NonThreadedXmlPullParserImpl extends AbstractXmlPullParser {
	private LinkedList<XmlElement> queue = new LinkedList<XmlElement>();
	private Locator locator;
	private HashMap<String, HashMap<String, String>> processingInstructions =
		new HashMap<String, HashMap<String, String>>();

	private String name;

	public NonThreadedXmlPullParserImpl(File file, ErrorHandler errHandler, boolean validate)
			throws SAXException, IOException {
		this.name = file.getName();
		try (InputStream is = new FileInputStream(file)) {
			fillQueue(file.getCanonicalPath(), file.getName(), is, errHandler, true, validate,
				false);
		}  // fill Queueu should close the stream, but this guarantees it.
	}

	public NonThreadedXmlPullParserImpl(String input, String inputName, ErrorHandler errHandler,
			boolean validate) throws SAXException {
		this.name = inputName;
		try {
			fillQueue(null, inputName, new ByteArrayInputStream(input.getBytes()), errHandler,
				false, validate, false);
		}
		catch (IOException e) {
			throw new SAXException(e);
		}
	}

	public NonThreadedXmlPullParserImpl(InputStream input, String inputName,
			ErrorHandler errHandler, boolean validate) throws SAXException, IOException {
		this.name = inputName;
		fillQueue(null, inputName, input, errHandler, false, validate, false);
	}

	@Deprecated
	NonThreadedXmlPullParserImpl(File file, ErrorHandler errHandler, boolean validate,
			boolean reallyCreateNoncompliantDeprecated) throws SAXException, IOException {
		this.name = file.getName();
		try (InputStream is = new FileInputStream(file)) {
			fillQueue(file.getCanonicalPath(), file.getName(), is, errHandler, true, validate,
				reallyCreateNoncompliantDeprecated);
		}  // fill Queueu should close the stream, but this guarantees it.
	}

	@Deprecated
	NonThreadedXmlPullParserImpl(String input, String inputName, ErrorHandler errHandler,
			boolean validate, boolean reallyCreateNoncompliantDeprecated) throws SAXException {
		this.name = inputName;
		try {
			fillQueue(null, inputName, new ByteArrayInputStream(input.getBytes()), errHandler,
				false, validate, reallyCreateNoncompliantDeprecated);
		}
		catch (IOException e) {
			throw new SAXException(e);
		}
	}

	@Deprecated
	NonThreadedXmlPullParserImpl(InputStream input, String inputName, ErrorHandler errHandler,
			boolean validate, boolean reallyCreateNoncompliantDeprecated)
			throws SAXException, IOException {
		this.name = inputName;
		fillQueue(null, inputName, input, errHandler, false, validate,
			reallyCreateNoncompliantDeprecated);
	}

	private void fillQueue(String filepath, String inputName, InputStream input,
			ErrorHandler errHandler, boolean closeStream, boolean validate,
			boolean reallyCreateNoncompliantDeprecated) throws SAXException, IOException {
		DefaultContentHandlerWrapper contentHandler =
			new DefaultContentHandlerWrapper(errHandler, reallyCreateNoncompliantDeprecated);
		try {
			SAXParserFactory saxParserFactory = XmlUtilities.createSecureSAXParserFactory(false);
			saxParserFactory.setFeature("http://xml.org/sax/features/namespaces", false);
			saxParserFactory.setFeature("http://xml.org/sax/features/validation", validate);
			SAXParser saxParser = saxParserFactory.newSAXParser();
			InputSource inputSource = new InputSource(input);

			// Java needs this path in order to resolve external dtd
			// documents (to
			// make them relative to the document being parsed);
			// otherwise, Java resolves
			// external documents relative to the current working
			// directory.
			inputSource.setSystemId(filepath);
			saxParser.parse(inputSource, contentHandler);

		}
		catch (ParserConfigurationException e) {
			Msg.error(this, e.getMessage());
			throw new SAXException(e);
		}
		finally {
			if (closeStream) {
				try {
					input.close();
				}
				catch (IOException e) {
					// we tried
				}
			}
		}
	}

	@Override
	public void dispose() {
		// nothing to do
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getProcessingInstruction(String piName, String attribute) {
		Map<String, String> map = processingInstructions.get(piName.toUpperCase());
		if (map == null) {
			return null;
		}
		return map.get(attribute.toUpperCase());
	}

	@Override
	public boolean hasNext() {
		return !queue.isEmpty();
	}

	@Override
	public boolean isPullingContent() {
		return false;
	}

	@Override
	public XmlElement next() {
		if (hasNext()) {
			return queue.removeFirst();
		}
		return null;
	}

	@Override
	public XmlElement peek() {
		if (hasNext()) {
			return queue.getFirst();
		}
		return null;
	}

	@Override
	public void setPullingContent(boolean pullingContent) {
		if (pullingContent) {
			throw new RuntimeException("this impl can't inject content");
		}
	}

	class DefaultContentHandlerWrapper extends DefaultHandler {
		private StringBuilder textBuf = new StringBuilder();
		private final ErrorHandler errorHandler;
		private final boolean reallyCreateNoncompliantDeprecated;

		public DefaultContentHandlerWrapper(ErrorHandler errorHandler,
				boolean reallyCreateNoncompliantDeprecated) {
			this.errorHandler = errorHandler;
			this.reallyCreateNoncompliantDeprecated = reallyCreateNoncompliantDeprecated;
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
			NonThreadedXmlPullParserImpl.this.locator = locator;
		}

		@Override
		public void processingInstruction(String target, String data) throws SAXException {
			target = target.toUpperCase();
			HashMap<String, String> map = processingInstructions.get(target);
			if (map == null) {
				map = new HashMap<String, String>();
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
			if (reallyCreateNoncompliantDeprecated) {
				qName = qName.toUpperCase();
			}
			queue.add(new XmlElementImpl(false, true, qName, level, null, textBuf.toString(),
				locator.getColumnNumber(), locator.getLineNumber()));
			textBuf = new StringBuilder();
			--level;
		}

		private int level = -1;

		@Override
		public void startElement(String namespaceURI, String localName, String qName,
				Attributes atts) throws SAXException {
			if (reallyCreateNoncompliantDeprecated) {
				qName = qName.toUpperCase();
			}
			++level;
			// NOTE: must clear the string buffer
			// because all white space between nested start tags
			// will be appended to the buffer
			textBuf.setLength(0);
			LinkedHashMap<String, String> attrMap = new LinkedHashMap<String, String>();
			final int length = atts.getLength();
			for (int ii = 0; ii < length; ++ii) {
				attrMap.put(atts.getQName(ii), atts.getValue(ii));
			}
			queue.add(new XmlElementImpl(true, false, qName, level, attrMap, null,
				locator.getColumnNumber(), locator.getLineNumber()));
		}
	}
}
