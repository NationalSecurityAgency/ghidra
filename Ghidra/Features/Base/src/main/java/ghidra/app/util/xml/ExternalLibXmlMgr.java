/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.xml;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlAttributes;
import ghidra.util.xml.XmlWriter;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

import java.io.IOException;

/**
 * XML for external library table for resolved external references.
 */
class ExternalLibXmlMgr {
	private MessageLog log;
	private ExternalManager extManager;

	ExternalLibXmlMgr(Program program, MessageLog log) {
		this.log = log;
		extManager = program.getExternalManager();
	}

	/**
	 * Process the entry point section of the XML file.
	 * @param parser xml reader
	 * @param monitor monitor that can be canceled
	 */
	void read(XmlPullParser parser, TaskMonitor monitor) throws CancelledException {
		final XmlElement start = parser.start("EXT_LIBRARY_TABLE");
		while (parser.peek().isStart()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			final XmlElement element = parser.start("EXT_LIBRARY");
			try {
				processExternalLib(element, parser);
			}
			catch (Exception e) {
				log.appendException(e);
			}
			finally {
				parser.end(element);
			}
		}
		parser.end(start);
	}

	/**
	 * Write out the XML for the external library table.
	 * @param writer writer for XML
	 * @param monitor monitor that can be canceled
	 * should be written
	 * @throws IOException
	 */
	void write(XmlWriter writer, TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Writing EXTERNAL LIBRARIES ...");
		writer.startElement("EXT_LIBRARY_TABLE");
		String[] externalNames = extManager.getExternalLibraryNames();
		for (int i = 0; i < externalNames.length; ++i) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			String path = extManager.getExternalLibraryPath(externalNames[i]);
			if (path == null) {
				path = "";
			}
			XmlAttributes attrs = new XmlAttributes();
			attrs.addAttribute("NAME", externalNames[i]);
			attrs.addAttribute("PATH", path);
			writer.startElement("EXT_LIBRARY", attrs);
			writer.endElement("EXT_LIBRARY");
		}
		writer.endElement("EXT_LIBRARY_TABLE");
	}

	private void processExternalLib(XmlElement element, XmlPullParser parser)
			throws InvalidInputException {

		String progName = element.getAttribute("NAME");
		String progPath = element.getAttribute("PATH");
		// check to make sure that we do not clear any
		// external refs that have already
		// been resolved
		String currPath = extManager.getExternalLibraryPath(progName);
		if (progPath == null || progPath.isEmpty()) {
			return; // nothing to change
		}

		if (currPath != null && !currPath.isEmpty()) {
			return; // already has a value--don't override it
		}

		extManager.setExternalPath(progName, progPath, true);
	}

}
