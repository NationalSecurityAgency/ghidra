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
package ghidra.app.util.bin.format.pdb;

import java.util.ArrayList;
import java.util.List;

import org.xml.sax.SAXParseException;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

class ApplyTypeDefs {

	private PdbParser pdbParser;
	private MessageLog log;
	private List<XmlElement> todo = new ArrayList<>();

	// NOTE: PDB does not appear to contain typedefs of typedefs.  Such definitions do not convey
	// so we are saved from having dependency ordering issues for typedef elements.

	/**
	 * Construct a PDB XML typedef parser.  This will retain all typedef elements for subsequent
	 * parsing.  The full parse will not be completed until the {@link #buildTypeDefs(TaskMonitor)} 
	 * method is invoked after all types and classes have been cached.
	 * @param pdbParser PDB parser object
	 * @param xmlParser XML parser positioned immediately after datatypes or classes element
	 * @param monitor task progress monitor
	 * @param log message log used during construction and subsequent method invocations
	 * @throws CancelledException if monitor is cancelled
	 * @throws SAXParseException PDB XML parse failure
	 */
	ApplyTypeDefs(PdbParser pdbParser, XmlPullParser xmlParser, TaskMonitor monitor, MessageLog log)
			throws CancelledException, SAXParseException {
		this.pdbParser = pdbParser;
		this.log = log;

		// Build todo list (unable to process until after all other types are cached)
		preProcessTypedefList(xmlParser, monitor);
	}

	private void preProcessTypedefList(XmlPullParser xmlParser, TaskMonitor monitor)
			throws CancelledException {
		monitor.setMessage("Pre-processing typedefs...");

		while (xmlParser.hasNext()) {
			monitor.checkCanceled();
			XmlElement elem = xmlParser.next();
			if (elem.isStart()) {
				todo.add(elem);
			}
			if (elem.isEnd() && elem.getName().equals("typedefs")) {
				break;
			}
		}
	}

	/**
	 * Perform parsing and caching of typedefs 
	 * @param monitor task monitor
	 * @throws CancelledException if task cancelled
	 */
	void buildTypeDefs(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Applying typedefs...");
		// NOTE: PDB does not appear to contain typedefs of typedefs.  Such definitions do not convey
		// so we are saved from having dependency ordering issues for typedef elements.
		for (XmlElement elem : todo) {
			monitor.checkCanceled();

			String datatypeName =
				SymbolUtilities.replaceInvalidChars(elem.getAttribute("name"), false);
			String baseDatatypeName =
				SymbolUtilities.replaceInvalidChars(elem.getAttribute("basetype"), false);

			if (datatypeName.equals(baseDatatypeName)) {
				continue;
			}
			if ("Function".equals(baseDatatypeName)) {
				continue;//TODO is this actually a global function
			}

			WrappedDataType baseDataType = pdbParser.findDataType(baseDatatypeName);
			if (baseDataType == null) {
				log.appendMsg("PDB",
					"Failed to resolve typedef: " + datatypeName + " -> " + baseDatatypeName);
				continue;
			}
			if (baseDataType.isZeroLengthArray()) {
				log.appendMsg("PDB",
					"Zero length array not supported for typedef: " + datatypeName);
				continue;
			}

			TypedefDataType typedef =
				pdbParser.createTypeDef(datatypeName, baseDataType.getDataType());
			pdbParser.cacheDataType(datatypeName, typedef); // cache with namespace-based name
		}
	}

}
