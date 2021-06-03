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

import ghidra.app.util.SymbolPath;
import ghidra.app.util.bin.format.pdb.PdbParser.PdbXmlMember;
import ghidra.app.util.importer.MessageLog;
import ghidra.graph.*;
import ghidra.graph.algo.GraphNavigator;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class ApplyDataTypes {

	private PdbParser pdbParser;
	private MessageLog log;
	private HashMap<String, CompositeDefinition> compositeQueue = new HashMap<>();

	/**
	 * Construct a PDB XML datatype or class parser.  The {@link #preProcessDataTypeList(XmlPullParser, boolean, TaskMonitor)}
	 * method must be used to injest member elements from the pull parser to populate the set of type to be parsed. 
	 * The full parse will not be completed until the {@link #applyTo(TaskMonitor)} method is invoked after all types 
	 * and classes have been pre-processed or applied.
	 * @param pdbParser PDB parser object
	 * @param xmlParser XML parser positioned immediately after datatypes or classes element
	 * @param isClasses true if processing classes, false if composite datatypes
	 * @param log message log used during construction and subsequent method invocations
	 * @throws CancelledException if monitor is cancelled
	 * @throws SAXParseException PDB XML parse failure
	 */
	ApplyDataTypes(PdbParser pdbParser, MessageLog log)
			throws CancelledException, SAXParseException {
		this.pdbParser = pdbParser;
		this.log = log;
	}

	void dispose() {
		compositeQueue.clear();
	}

	private List<CompositeDefinition> getCompositeDefinitionsInPostDependencyOrder(
			TaskMonitor monitor) {

		GDirectedGraph<CompositeDefinition, GEdge<CompositeDefinition>> graph =
			GraphFactory.createDirectedGraph();
		for (CompositeDefinition compositeDefinition : compositeQueue.values()) {
			graph.addVertex(compositeDefinition);
			for (PdbMember m : compositeDefinition.memberList) {
				String name = m.memberDataTypeName;
				int index = name.indexOf('[');
				if (index > 0) {
					name = name.substring(0, index).trim();
				}
				CompositeDefinition child = compositeQueue.get(name);
				if (child != null) {
					graph.addEdge(new DefaultGEdge<>(compositeDefinition, child));
				}
			}
		}

// FIXME:		GraphAlgorithms.findCircuits(graph, monitor);

		List<CompositeDefinition> verticesInPostOrder =
			GraphAlgorithms.getVerticesInPostOrder(graph, GraphNavigator.topDownNavigator());

		return verticesInPostOrder;
	}

	/**
	 * Perform parsing and caching of composite types 
	 * @param monitor task monitor
	 * @throws CancelledException if task cancelled
	 */
	void buildDataTypes(TaskMonitor monitor) throws CancelledException {

		monitor.setMessage("Order PDB datatypes... ");

		List<CompositeDefinition> verticesInPostOrder =
			getCompositeDefinitionsInPostDependencyOrder(monitor);

		monitor.setMessage("Building PDB datatypes... ");

		for (CompositeDefinition compositeDefinition : verticesInPostOrder) {
			monitor.checkCanceled();

			// namespace qualified name used for cache lookups
			DataType cachedDataType = pdbParser.getCachedDataType(compositeDefinition.name);
			SymbolPath symbolPath = new SymbolPath(compositeDefinition.name);
			if (!(cachedDataType instanceof Composite) ||
				!cachedDataType.getCategoryPath().equals(
					pdbParser.getCategory(symbolPath.getParent(), true)) ||
				!pdbParser.isCorrectKind(cachedDataType, compositeDefinition.kind)) {
				log.appendMsg("PDB", "Conflicting data type name: " + compositeDefinition.name);
				continue;
			}
			Composite composite = (Composite) cachedDataType;
			PdbUtil.clearComponents(composite);

			if (!DefaultCompositeMember.applyDataTypeMembers(composite, compositeDefinition.isClass,
				compositeDefinition.length, getNormalMembersOnly(compositeDefinition),
				msg -> Msg.warn(this, msg), monitor)) {
				PdbUtil.clearComponents(composite);
			}

		}
	}

	private List<PdbXmlMember> getNormalMembersOnly(CompositeDefinition compositeDefinition) {
		if (compositeDefinition.hasNormalMembersOnly) {
			return compositeDefinition.memberList;
		}
		ArrayList<PdbXmlMember> list = new ArrayList<>();
		for (PdbXmlMember m : compositeDefinition.memberList) {
			if (m.kind == PdbKind.MEMBER) {
				list.add(m);
			}
		}
		return list;
	}

	void preProcessDataTypeList(XmlPullParser xmlParser, boolean isClasses, TaskMonitor monitor)
			throws CancelledException {

		monitor.setMessage("Pre-processing PDB datatypes...");

		String elementType = isClasses ? "classes" : "datatypes";

		while (xmlParser.hasNext()) {
			monitor.checkCanceled();
			XmlElement elem = xmlParser.peek();
			if (elem.isEnd() && elem.getName().equals(elementType)) {
				xmlParser.next();
				break;
			}

			CompositeDefinition compositeDefinition = new CompositeDefinition(xmlParser);

			if (!compositeQueue.containsKey(compositeDefinition.name)) {
				// could be problematic if duplicate names represent two different composites
				if (compositeDefinition.isClass) {
					pdbParser.predefineClass(compositeDefinition.name);
				}
				compositeQueue.put(compositeDefinition.name, compositeDefinition);

				if (pdbParser.getCachedDataType(compositeDefinition.name) != null) {
					log.appendMsg("PDB", "Data type name collision - unable to define " +
						compositeDefinition.kind.getCamelName() + ": " + compositeDefinition.name);
					continue;
				}

//				/** Can this be avoided if using dependency ordering ??
				// NOTE: currently composite may grow if zero-length array used
				// since we must currently allocate one element since 0-length array 
				// not yet supported.
				Composite composite =
					pdbParser.createComposite(compositeDefinition.kind, compositeDefinition.name);
				if (composite == null) {
					log.appendMsg("PDB", "Unsupported datatype kind (" + compositeDefinition.kind +
						"): " + compositeDefinition.name);
					continue;
				}
//								if (!isClasses) {
//									int length = XmlUtilities.parseInt(elem.getAttribute("length"));
//									PdbUtil.ensureSize(length, composite, log);
//								}
				pdbParser.cacheDataType(compositeDefinition.name, composite);
//				**/
			}
		}
	}

	private class CompositeDefinition {
		final boolean isClass;
		final PdbKind kind;
		final String name;
		final int length;
		final List<PdbXmlMember> memberList = new ArrayList<>();
		final boolean hasNormalMembersOnly;

		CompositeDefinition(XmlPullParser parser) {
			XmlElement startElement = parser.start();
			name = SymbolUtilities.replaceInvalidChars(startElement.getAttribute("name"), false);
			length = XmlUtilities.parseInt(startElement.getAttribute("length"));
			String kindStr = startElement.getAttribute("kind");
			boolean membersOnly = true;
			XmlElement element = parser.peek();
			while (element != null && element.isStart()) {
				element = parser.start("member");
				PdbXmlMember pdbXmlMember = pdbParser.getPdbXmlMember(element);
				memberList.add(pdbXmlMember);
				membersOnly &= (pdbXmlMember.kind == PdbKind.MEMBER);
				parser.end(element);
				element = parser.peek();
			}
			parser.end(startElement);
			this.hasNormalMembersOnly = membersOnly;
			this.isClass = "class".equals(startElement.getName()) || isInferredClass(kindStr);
			this.kind = isClass ? PdbKind.STRUCTURE : PdbKind.parse(kindStr);
		}

		private boolean isInferredClass(String kindStr) {

			for (PdbXmlMember m : memberList) {
				if (m.kind == PdbKind.MEMBER) {
					continue;
				}
				if ("void *".equals(m.memberDataTypeName)) {
					return true;
				}
				if ("Function".equals(m.memberDataTypeName)) { // ??
					return true;
				}
			}
			return false;
		}

		@Override
		public int hashCode() {
			return name.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			CompositeDefinition other = (CompositeDefinition) obj;
			return isClass == other.isClass && kind == other.kind && length == other.length &&
				SystemUtilities.isEqual(name, other.name);
		}

	}

}
