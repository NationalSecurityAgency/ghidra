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

import java.util.*;

import org.xml.sax.SAXParseException;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.*;

public class ApplyDataTypes {

	private PdbParserNEW pdbParser;
	private boolean isClasses;
	private MessageLog log;
	private List<XmlTreeNode> todo = new ArrayList<>();

	/**
	 * Construct a PDB XML datatype or class parser.  This will pre-process each datatype element and cache
	 * a properly sized composite for subsequent type reference.  The full parse will not be completed
	 * until the {@link #applyTo(TaskMonitor)} method is invoked after all types and classes have been
	 * pre-processed or applied.
	 * @param pdbParser PDB parser object
	 * @param xmlParser XML parser positioned immediately after datatypes or classes element
	 * @param isClasses true if processing classes, false if composite datatypes
	 * @param monitor task progress monitor
	 * @param log message log used during construction and subsequent method invocations
	 * @throws CancelledException if monitor is cancelled
	 * @throws SAXParseException PDB XML parse failure
	 */
	ApplyDataTypes(PdbParserNEW pdbParser, XmlPullParser xmlParser, boolean isClasses,
			TaskMonitor monitor, MessageLog log) throws CancelledException, SAXParseException {
		this.pdbParser = pdbParser;
		this.isClasses = isClasses;
		this.log = log;

		// Build todo list and cache preliminary composite definitions
		preProcessDataTypeList(xmlParser, monitor);
	}

	void dispose() {
		todo.clear();
	}

	/**
	 * Perform parsing and caching of composite types 
	 * @param monitor task monitor
	 * @throws CancelledException if task cancelled
	 */
	void buildDataTypes(TaskMonitor monitor) throws CancelledException {

		monitor.setMessage("Building PDB datatypes... ");

		for (XmlTreeNode node : todo) {
			monitor.checkCanceled();

			XmlElement elem = node.getStartElement();
			String name = SymbolUtilities.replaceInvalidChars(elem.getAttribute("name"), false);

			String kind = isClasses ? PdbParserNEW.STRUCTURE_KIND : elem.getAttribute("kind");
			int length = XmlUtilities.parseInt(elem.getAttribute("length"));

			// namespace qualified name used for cache lookups
			DataType cachedDataType = pdbParser.getCachedDataType(name);
			if (!(cachedDataType instanceof Composite) ||
				!cachedDataType.getCategoryPath().equals(pdbParser.getCategory(name, true)) ||
				!pdbParser.isCorrectKind(cachedDataType, kind)) {
				log.appendMsg("Error: Conflicting data type name: " + name);
				continue;
			}
			Composite composite = (Composite) cachedDataType;
			PdbUtil.clearComponents(composite);

			if (!CompositeMember.applyDataTypeMembers(pdbParser, composite, length, node,
				monitor)) {
				PdbUtil.clearComponents(composite);
			}

			// Do not adjust size of defined structure contains flex array at specified offset
			boolean hasFlexibleArray = false;
			if (composite instanceof Structure) {
				hasFlexibleArray = ((Structure) composite).hasFlexibleArrayComponent();
			}

			if (!isClasses && !hasFlexibleArray) {
				PdbUtil.ensureSize(length, composite, log);
			}
		}
	}

	/**
	 * check to see if this data type is actually a class
	 */
	private boolean isDataTypeClass(XmlTreeNode node, TaskMonitor monitor)
			throws CancelledException {
		if (!node.getStartElement().getName().equals("datatype")) {
			return false;
		}
		for (int i = 0; i < node.getChildCount(); ++i) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			XmlTreeNode childNode = node.getChildAt(i);
			XmlElement child = childNode.getStartElement();
			String datatype = child.getAttribute("datatype");
			if ("Function".equals(datatype)) {
				return true;
			}
		}
		return false;
	}

	private void preProcessDataTypeList(XmlPullParser xmlParser, TaskMonitor monitor)
			throws SAXParseException, CancelledException {

		monitor.setMessage("Pre-processing PDB datatypes...");

		String elementType = isClasses ? "classes" : "datatypes";

		Map<String, XmlTreeNode> todoNames = new HashMap<>();
		while (xmlParser.hasNext()) {
			monitor.checkCanceled();
			XmlElement elem = xmlParser.peek();
			if (elem.isEnd() && elem.getName().equals(elementType)) {
				xmlParser.next();
				break;
			}
			String name = SymbolUtilities.replaceInvalidChars(elem.getAttribute("name"), false);
			XmlTreeNode node = new XmlTreeNode(xmlParser);
			if (todoNames.containsKey(name)) {
				XmlTreeNode todoNode = todoNames.get(name);
				if (elem.toString().equals(todoNode.getStartElement().toString())) {
					//TODO log.appendMsg("Duplicate data type defined in PDB: "+name);
				}
				else {
					//TODO log.appendMsg("Data type re-definition ignored: "+name);
				}
			}
			else {
				if (isClasses || isDataTypeClass(node, monitor)) {
					pdbParser.predefineClass(name);
				}
				todoNames.put(name, node);

				String kind = isClasses ? PdbParserNEW.STRUCTURE_KIND : elem.getAttribute("kind");

				if (pdbParser.getCachedDataType(name) != null) {
					log.appendMsg(
						"Error: Data type name collision - unable to define " + kind + ": " + name);
					continue;
				}

				todo.add(node);

				// NOTE: currently composite may grow if zero-length array used
				// since we must currently allocate one element since 0-length array 
				// not yet supported.
				Composite composite = pdbParser.createComposite(kind, name);
				if (composite == null) {
					log.appendMsg("Unsupported datatype kind (" + kind + "): " + name);
					continue;
				}
				if (!isClasses) {
					int length = XmlUtilities.parseInt(elem.getAttribute("length"));
					PdbUtil.ensureSize(length, composite, log);
				}
				pdbParser.cacheDataType(name, composite);
			}
		}
		todoNames.clear();//release memory...
		todoNames = null;
	}

}
