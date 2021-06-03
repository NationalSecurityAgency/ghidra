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

import generic.jar.ResourceFile;

import java.io.*;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;

public class XmlPullParserFactory {
	public static void setCreateTracingParsers(XmlTracer xmlTracer) {
		throw new UnsupportedOperationException(
			"XmlTracer not supported right now...instrument ThreadedXmlPullParserImpl to continue...");
	}

	/**
	 * Constructs a new parser using the specified stream and name.
	 * 
	 * @param input
	 *            the input XML stream
	 * @param inputName
	 *            the name of the stream
	 * @param errHandler
	 *            the XML error handler
	 * @param validate
	 *            true if the parse should validate against the DTD
	 * @throws SAXException
	 *             if an XML parse error occurs
	 * @throws IOException 
	 */
	public static XmlPullParser create(InputStream input, String inputName,
			ErrorHandler errHandler, boolean validate) throws SAXException, IOException {
		return new ThreadedXmlPullParserImpl(input, inputName, errHandler, validate, 1000);
	}

	/**
	 * Constructs a new parser using the specified XML file.
	 * 
	 * @param file
	 *            the input XML file
	 * @param errHandler
	 *            the XML error handler
	 * @param validate
	 *            true if the parse should validate against the DTD
	 * @throws SAXException
	 *             if an XML parse error occurs
	 * @throws IOException
	 *             if an i/o error occurs
	 */
	public static XmlPullParser create(File file, ErrorHandler errHandler, boolean validate)
			throws SAXException, IOException {
		return new ThreadedXmlPullParserImpl(file, errHandler, validate, 1000);
	}

	/**
	 * Constructs a new parser using the specified XML file.
	 * 
	 * @param file
	 *            the input XML file
	 * @param errHandler
	 *            the XML error handler
	 * @param validate
	 *            true if the parse should validate against the DTD
	 * @throws SAXException
	 *             if an XML parse error occurs
	 * @throws IOException
	 *             if an i/o error occurs
	 */
	public static XmlPullParser create(ResourceFile file, ErrorHandler errHandler, boolean validate)
			throws SAXException, IOException {
		return new ThreadedXmlPullParserImpl(file, errHandler, validate, 1000);
	}

	/**
	 * Constructs a new parser using the specified XML file.
	 * 
	 * @param input
	 *            A string that contains the XML input data
	 * @param inputName 
	 *            A descriptive name for the XML process (this will appear as the thread name)
	 * @param errHandler
	 *            the XML error handler
	 * @param validate
	 *            true if the parse should validate against the DTD
	 * @throws SAXException
	 *             if an XML parse error occurs
	 */
	public static XmlPullParser create(String input, String inputName, ErrorHandler errHandler,
			boolean validate) throws SAXException {
		return new ThreadedXmlPullParserImpl(new ByteArrayInputStream(input.getBytes()), inputName,
			errHandler, validate, 1000);
	}
}
