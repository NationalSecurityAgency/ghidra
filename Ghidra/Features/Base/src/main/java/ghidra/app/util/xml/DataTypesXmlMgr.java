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
package ghidra.app.util.xml;

import java.io.File;
import java.io.IOException;
import java.util.*;

import org.xml.sax.SAXParseException;

import ghidra.app.util.importer.MessageLog;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.*;
import ghidra.xml.*;

/**
 * This manager is responsible for reading and writing datatypes in XML.
 */
public class DataTypesXmlMgr {
	private final static int DEFAULT_SIZE = 1;

	private static HashMap<String, DataType> foreignTypedefs = new HashMap<>();
	static {
		foreignTypedefs.put("ascii", CharDataType.dataType);
		foreignTypedefs.put("string1", PascalString255DataType.dataType);
		foreignTypedefs.put("string2", PascalStringDataType.dataType);
		// string4 - pascal string with 4-byte length prefix
		foreignTypedefs.put("unicode2", PascalUnicodeDataType.dataType);
		// unicode4 - pascal unicode string with 4-byte length prefix
		foreignTypedefs.put("tbyte", LongDoubleDataType.dataType); // 10-byte float
		// oword - 16-byte value
		// packed real
		foreignTypedefs.put("3byte", UnsignedInteger3DataType.dataType);
	}

	private DataTypeManager dataManager;
	private DtParser dtParser;
	private MessageLog log;
	private int defaultEnumSize = IntegerDataType.dataType.getLength();

	/**
	 * Constructs a new data types XML manager.
	 * @param dataManager the data type manager to read from or write to
	 * @param log the message log for recording datatype warnings
	 */
	public DataTypesXmlMgr(DataTypeManager dataManager, MessageLog log) {
		this.dataManager = dataManager;
		this.log = log;
	}

	/**
	 * Reads the datatypes encoded in XML from the specified XML parser and recreates
	 * them in a datatype manager.
	 * @param parser the XML parser
	 * @param monitor the task monitor
	 * @throws SAXParseException if an XML parse error occurs
	 * @throws CancelledException if the user cancels the read operation
	 */
	public void read(XmlPullParser parser, TaskMonitor monitor)
			throws SAXParseException, CancelledException {
		ArrayList<XmlTreeNode> todo = new ArrayList<>();
		XmlElement element = parser.next();

		BuiltInDataTypeManager builtInMgr = BuiltInDataTypeManager.getDataTypeManager();
		try {
			dtParser = new DtParser(dataManager);
			while (true) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				element = parser.peek();
				if (element.isEnd() && element.getName().equals("DATATYPES")) {
					parser.next();
					break;
				}
				XmlTreeNode root = new XmlTreeNode(parser);
				if (!process(root, true)) {
					todo.add(root);
				}
			}

			while (true) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				boolean processed = false;
				Iterator<XmlTreeNode> it = todo.iterator();
				while (it.hasNext()) {
					XmlTreeNode node = it.next();
					if (process(node, false)) {
						it.remove();
						processed = true;
					}
				}
				if (!processed) {
					break;
				}
			}
		}
		finally {
			builtInMgr.close();
			dtParser = null;
		}

		Iterator<XmlTreeNode> it = todo.iterator();
		while (it.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			logError(it.next());
		}
	}

	private void logError(XmlTreeNode node) {
		XmlElement element = node.getStartElement();
		String tagName = element.getName();
		String name = element.getAttribute("NAME");
		if (name == null) {
			name = "";
		}
		logError(node, tagName + ": " + name);
	}

	private void logError(XmlTreeNode node, String parentName) {
		XmlElement element = node.getStartElement();
		String dataTypeName = element.getAttribute("DATATYPE");
		if (dataTypeName == null) {
			dataTypeName = element.getAttribute("DATATYPE_NAME");//support older versions of XML
		}
		log.appendMsg(element.getLineNumber(),
			"Couldn't create DataType: " + dataTypeName + " in " + parentName);
		Iterator<XmlTreeNode> it = node.getChildren();
		while (it.hasNext()) {
			logError(it.next(), parentName);
		}
	}

	private boolean process(XmlTreeNode root, boolean firstPass) {
		XmlElement element = root.getStartElement();
		String name = element.getName();

		try {
			if (name.equals("STRUCTURE")) {
				return processStructure(root, firstPass);
			}
			else if (name.equals("UNION")) {
				return processUnion(root, firstPass);
			}
			else if (name.equals("FUNCTION_DEF")) {
				return processFunctionDef(root, firstPass);
			}
			else if (name.equals("ENUM")) {
				return processEnum(root);
			}
			else if (name.equals("TYPE_DEF")) {
				return processTypeDef(root, firstPass);
			}
			log.appendMsg("Unrecognized datatype tag: " + name);
		}
		catch (Exception e) {
			log.appendException(e);
		}
		return true;
	}

	private boolean processFunctionDef(XmlTreeNode root, boolean firstPass) {
		boolean processedAll = true;
		XmlElement element = root.getStartElement();
		String name = element.getAttribute("NAME");
		CategoryPath path = getCategoryPath(element);
		FunctionDefinition fd = null;

		if (firstPass) {
			fd = new FunctionDefinitionDataType(path, name);
			fd = (FunctionDefinition) dataManager.addDataType(fd, null);
			if (!name.equals(fd.getName())) {
				element.setAttribute("NAME", fd.getName());
			}
		}
		else {
			fd = (FunctionDefinition) dataManager.getDataType(path, name);
		}

		XmlTreeNode node = root.getChild("RETURN_TYPE");
		if (node != null) {
			DataType returnType = findDataType(node.getStartElement());
			if (returnType != null) {
				fd.setReturnType(returnType);
				root.deleteChildNode(node);
			}
			else {
				processedAll = false;
			}
		}

		Iterator<XmlTreeNode> it = root.getChildren("PARAMETER");
		while (it.hasNext()) {
			node = it.next();
			String comment = getRegularComment(node);
			element = node.getStartElement();
			DataType dt = findDataType(element);
			if (dt != null) {
				int ordinal = XmlUtilities.parseInt(element.getAttribute("ORDINAL"));
				name = element.getAttribute("NAME");
				int size = dt.getLength();
				if (size == 0) {
					return false;
				}
				if (size < 0) {
					size = element.hasAttribute("SIZE")
							? XmlUtilities.parseInt(element.getAttribute("SIZE"))
							: 4;
				}
				fd.replaceArgument(ordinal, name, dt, comment, SourceType.USER_DEFINED);
				it.remove();
			}
			else {
				processedAll = false;
			}
		}
		return processedAll;
	}

	private boolean processEnum(XmlTreeNode root) {
		XmlElement element = root.getStartElement();
		String name = element.getAttribute("NAME");
		String enuumComment = getRegularComment(root);
		CategoryPath cp = getCategoryPath(element);
		int size = XmlUtilities.parseInt(element.getAttribute("SIZE"), defaultEnumSize);

		EnumDataType enuum = new EnumDataType(cp, name, size);

		Iterator<XmlTreeNode> it = root.getChildren("ENUM_ENTRY");
		while (it.hasNext()) {
			XmlTreeNode node = it.next();
			XmlElement childElement = node.getStartElement();
			String entryName = childElement.getAttribute("NAME");
			long entryValue = XmlUtilities.parseLong(childElement.getAttribute("VALUE"));
			String comment = childElement.getAttribute("COMMENT");
			enuum.add(entryName, entryValue, comment);
		}
		enuum.setDescription(enuumComment);
		dataManager.addDataType(enuum, null);
		return true;
	}

	private boolean processTypeDef(XmlTreeNode root, boolean firstPass) {
		XmlElement element = root.getStartElement();
		String name = element.getAttribute("NAME");
		CategoryPath cp = getCategoryPath(element);

		DataType dt = findDataType(element);
		if (dt == null) {
			return false;		// typeDef'd datatype not resolved yet
		}

		int dtSize = dt.getLength();
		int size =
			element.hasAttribute("SIZE") ? XmlUtilities.parseInt(element.getAttribute("SIZE")) : -1;
		if (size != -1 && size != dtSize) {
			log.appendMsg("SIZE=" + element.getAttribute("SIZE") + " specified on type-def " +
				name + " does not agree with length of datatype " + dt.getDisplayName() + " (" +
				dtSize + ")");
		}

		TypeDef td = new TypedefDataType(cp, name, dt);
		try {
			td.setCategoryPath(cp);
		}
		catch (DuplicateNameException e) {
			log.appendMsg("Unable to place typedef '" + name + "' in category '" + cp + "'");
		}

		dataManager.addDataType(td, null);
		return true;
	}

	private boolean processStructure(XmlTreeNode root, boolean firstPass) {
		XmlElement element = root.getStartElement();
		String name = element.getAttribute("NAME");
		CategoryPath path = getCategoryPath(element);
		Structure struct = null;
		boolean isVariableLength = false;
		if (element.hasAttribute("VARIABLE_LENGTH")) {
			isVariableLength = XmlUtilities.parseBoolean(element.getAttribute("VARIABLE_LENGTH"));
		}
		if (firstPass) {
			int size = DEFAULT_SIZE;
			if (element.hasAttribute("SIZE")) {
				size = XmlUtilities.parseInt(element.getAttribute("SIZE"));
			}
			String comment = getRegularComment(root);
			struct = new StructureDataType(path, name, size);
			if (comment != null) {
				struct.setDescription(comment);
			}
			struct = (Structure) dataManager.addDataType(struct, null);
			if (!struct.getName().equals(name)) {
				element.setAttribute("NAME", struct.getName());
			}
		}
		else {
			struct = (Structure) dataManager.getDataType(path, name);
		}
		return processStructMembers(root, struct, firstPass, isVariableLength);
	}

	private boolean processUnion(XmlTreeNode root, boolean firstPass) {
		XmlElement element = root.getStartElement();
		String name = element.getAttribute("NAME");
		CategoryPath path = getCategoryPath(element);
		Union union = null;
		if (firstPass) {
			String comment = getRegularComment(root);
			union = new UnionDataType(path, name);
			if (comment != null) {
				union.setDescription(comment);
			}
			union = (Union) dataManager.addDataType(union, null);
			if (!union.getName().equals(name)) {
				element.setAttribute("NAME", union.getName());
			}
		}
		else {
			union = (Union) dataManager.getDataType(path, name);
		}
		return processUnionMembers(root, union, firstPass);
	}

	private String getRegularComment(XmlTreeNode root) {
		XmlTreeNode node = root.getChild("REGULAR_CMT");
		if (node != null) {
			return node.getEndElement().getText();
		}
		return null;
	}

	private boolean processStructMembers(XmlTreeNode root, Structure struct, boolean firstPass,
			boolean isVariableLength) {
		boolean processedAll = true;
		Iterator<XmlTreeNode> iter = root.getChildren("MEMBER");
		while (iter.hasNext()) {
			XmlTreeNode child = iter.next();
			XmlElement childElem = child.getStartElement();
			int offset = XmlUtilities.parseInt(childElem.getAttribute("OFFSET"));
			DataType memberDT = findDataType(childElem);
			if (memberDT != null) {
				if (memberDT instanceof TerminatedStringDataType) {
					// TerminatedCStringDataType no longer allowed in composites
					memberDT = new StringDataType();
				}
				else if (memberDT instanceof TerminatedUnicodeDataType) {
					// TerminatedUnicodeStringDataType no longer allowed in composites
					memberDT = new UnicodeDataType();
				}
				if (memberDT.getLength() == 0) {
					return false;
				}
				String memberName = childElem.getAttribute("NAME");
				String memberComment = getRegularComment(child);
				int dtSize = memberDT.getLength();
				int size = childElem.hasAttribute("SIZE")
						? XmlUtilities.parseInt(childElem.getAttribute("SIZE"))
						: -1;
				if (dtSize <= 0) {
					dtSize = size;
					if (dtSize < 0) {
						log.appendMsg("No SIZE specified for member at offset " + offset +
							" of structure " + struct.getDisplayName());
						dtSize = DEFAULT_SIZE;
					}
				}

				// NOTE: Size consistency checking was removed since some types are filled-out
				// lazily and may not have there ultimate size at this point.

				DataTypeComponent member = null;
				if (isVariableLength && offset >= struct.getLength()) {
					member = struct.add(memberDT, dtSize, memberName, memberComment);
				}
				else {
					member =
						struct.replaceAtOffset(offset, memberDT, dtSize, memberName, memberComment);
				}
				processSettings(child, member.getDefaultSettings());

				iter.remove();
			}
			else {
				processedAll = false;
			}
		}
		return processedAll;
	}

	private void processSettings(XmlTreeNode parent, Settings settings) {
		XmlTreeNode node = parent.getChild("DISPLAY_SETTINGS");
		if (node != null) {
			DisplaySettingsHandler.readSettings(node.getStartElement(), settings);
		}
	}

	private boolean processUnionMembers(XmlTreeNode root, Union union, boolean firstPass) {
		boolean processedAll = true;
		Iterator<XmlTreeNode> iter = root.getChildren("MEMBER");
		while (iter.hasNext()) {
			XmlTreeNode child = iter.next();
			XmlElement childElem = child.getStartElement();
			DataType memberDT = findDataType(childElem);
			if (memberDT != null) {
				String memberName = childElem.getAttribute("NAME");
				String memberComment = getRegularComment(child);
				int dtSize = memberDT.getLength();
				int size = childElem.hasAttribute("SIZE")
						? XmlUtilities.parseInt(childElem.getAttribute("SIZE"))
						: -1;
				if (dtSize <= 0) {
					dtSize = size;
					if (dtSize < 0) {
						log.appendMsg("No SIZE specified for member datatype " +
							memberDT.getDisplayName() + " of union " + union.getDisplayName());
						dtSize = DEFAULT_SIZE;
					}
				}
				else if (size != -1 && size != dtSize) {
					log.appendMsg("SIZE=" + childElem.getAttribute("SIZE") +
						" specified for member datatype " + memberDT.getDisplayName() +
						" of union " + union.getDisplayName() +
						" does not agree with length of datatype (" + dtSize + ")");
				}
				union.add(memberDT, dtSize, memberName, memberComment);
				iter.remove();
			}
			else {
				processedAll = false;
			}
		}
		return processedAll;
	}

	private CategoryPath getCategoryPath(XmlElement element) {
		String nameSpace = element.getAttribute("NAMESPACE");
		CategoryPath cp = nameSpace == null ? CategoryPath.ROOT : new CategoryPath(nameSpace);
		return cp;
	}

	private DataType findDataType(XmlElement element) {
		String dtName = element.getAttribute("DATATYPE");
		if (dtName == null) {
			dtName = element.getAttribute("DATATYPE_NAME");//support older versions of XML
		}
		CategoryPath cp = new CategoryPath(element.getAttribute("DATATYPE_NAMESPACE"));
		int size =
			element.hasAttribute("SIZE") ? XmlUtilities.parseInt(element.getAttribute("SIZE")) : -1;
		DataType dt = dtParser.parseDataType(dtName, cp, size);
		if (dt == null && addForeignTypedefIfNeeded(dtName)) {
			dt = dtParser.parseDataType(dtName, cp, size);
		}
		return dt;

	}

	private boolean addForeignTypedefIfNeeded(String dtName) {
		int ptrIndex = dtName.indexOf('*');
		int index = dtName.indexOf('[');
		String baseName = dtName.trim();
		if (index < 0 || index > ptrIndex) {
			index = ptrIndex;
		}
		if (index > 0) {
			baseName = dtName.substring(0, index).trim();
		}
		DataType ourType = foreignTypedefs.get(baseName);
		if (ourType != null && dataManager.getDataType("/" + baseName) == null) {
			TypedefDataType newTypedef = new TypedefDataType(baseName, ourType);
			dataManager.resolve(newTypedef, null);
			return true;
		}
		return false;
	}

	/**
	 * Writes datatypes into XML using the specified XML writer.
	 * @param writer the XML writer
	 * @param monitor the task monitor
	 * @throws CancelledException if the user cancels the write operation
	 */
	public void write(XmlWriter writer, TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Writing DATA TYPES ...");

		writer.startElement("DATATYPES");

		Iterator<?> it = dataManager.getAllDataTypes();
		while (it.hasNext()) {
			writeDataType(writer, (DataType) it.next());
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
		}
		writer.endElement("DATATYPES");
	}

	private void writeDataType(XmlWriter writer, DataType dt) {
		if (dt instanceof Structure) {
			writeStructure(writer, (Structure) dt);
		}
		else if (dt instanceof Union) {
			writeUnion(writer, (Union) dt);
		}
		else if (dt instanceof TypeDef) {
			writeTypeDef(writer, (TypeDef) dt);
		}
		else if (dt instanceof FunctionDefinition) {
			writeFunctionDefinition(writer, (FunctionDefinition) dt);
		}
		else if (dt instanceof Enum) {
			writeEnum(writer, (Enum) dt);
		}
	}

	private void writeEnum(XmlWriter writer, Enum enuum) {
		XmlAttributes attrs = new XmlAttributes();
		attrs.addAttribute("NAME", enuum.getDisplayName());
		attrs.addAttribute("NAMESPACE", enuum.getCategoryPath().getPath());
		attrs.addAttribute("SIZE", enuum.getLength(), true);
		writer.startElement("ENUM", attrs);
		writeRegularComment(writer, enuum.getDescription());

		String[] names = enuum.getNames();
		for (String name : names) {
			attrs = new XmlAttributes();
			attrs.addAttribute("NAME", name);
			attrs.addAttribute("VALUE", enuum.getValue(name), true);
			attrs.addAttribute("COMMENT", enuum.getComment(name));
			writer.startElement("ENUM_ENTRY", attrs);
			writer.endElement("ENUM_ENTRY");
		}

		writer.endElement("ENUM");
	}

	private void writeFunctionDefinition(XmlWriter writer, FunctionDefinition func) {
		XmlAttributes attrs = new XmlAttributes();
		attrs.addAttribute("NAME", func.getName());
		attrs.addAttribute("NAMESPACE", func.getCategoryPath().getPath());
		writer.startElement("FUNCTION_DEF", attrs);

		writeRegularComment(writer, func.getDescription());

		DataType rt = func.getReturnType();
		if (rt != null && rt != DataType.DEFAULT) {
			attrs = new XmlAttributes();
			attrs.addAttribute("DATATYPE", rt.getDisplayName());
			attrs.addAttribute("DATATYPE_NAMESPACE", rt.getCategoryPath().getPath());
			attrs.addAttribute("SIZE", rt.getLength(), true);
			writer.startElement("RETURN_TYPE", attrs);
			writer.endElement("RETURN_TYPE");
		}

		ParameterDefinition[] vars = func.getArguments();
		for (int i = 0; i < vars.length; i++) {
			writerParameter(writer, vars[i], i);
		}

		writer.endElement("FUNCTION_DEF");
	}

	private void writerParameter(XmlWriter writer, ParameterDefinition var, int ordinal) {
		XmlAttributes attrs = new XmlAttributes();
		attrs.addAttribute("ORDINAL", ordinal, true);
		DataType dt = var.getDataType();
		if (dt != null) {
			attrs.addAttribute("DATATYPE", dt.getDisplayName());
			attrs.addAttribute("DATATYPE_NAMESPACE", dt.getCategoryPath().getPath());
			attrs.addAttribute("NAME", var.getName());
			attrs.addAttribute("SIZE", var.getLength(), true);
			writer.startElement("PARAMETER", attrs);
			writeRegularComment(writer, var.getComment());
			writer.endElement("PARAMETER");
		}
		else {
			Msg.error(this, "Parameter data type not found " + var);
		}
	}

	private void writeRegularComment(XmlWriter writer, String comment) {
		if (comment != null && comment.length() > 0) {
			writer.writeElement("REGULAR_CMT", null, comment);
		}
	}

	private void writeTypeDef(XmlWriter writer, TypeDef def) {
		XmlAttributes attrs = new XmlAttributes();
		attrs.addAttribute("NAME", def.getName());
		attrs.addAttribute("NAMESPACE", def.getCategoryPath().getPath());
		DataType dt = def.getDataType();
		attrs.addAttribute("DATATYPE", dt.getDisplayName());
		attrs.addAttribute("DATATYPE_NAMESPACE", dt.getCategoryPath().getPath());
		writer.startElement("TYPE_DEF", attrs);
		writer.endElement("TYPE_DEF");
	}

	private void writeStructure(XmlWriter writer, Structure struct) {
		XmlAttributes attrs = new XmlAttributes();
		attrs.addAttribute("NAME", struct.getDisplayName());
		attrs.addAttribute("NAMESPACE", struct.getCategoryPath().getPath());
		attrs.addAttribute("SIZE", struct.isZeroLength() ? 0 : struct.getLength(), true);
		writer.startElement("STRUCTURE", attrs);
		writeRegularComment(writer, struct.getDescription());
		DataTypeComponent[] members = struct.getComponents();
		for (DataTypeComponent member : members) {
			writerMember(writer, member);
		}
		writer.endElement("STRUCTURE");
	}

	private void writeUnion(XmlWriter writer, Union union) {
		XmlAttributes attrs = new XmlAttributes();
		attrs.addAttribute("NAME", union.getDisplayName());
		attrs.addAttribute("NAMESPACE", union.getCategoryPath().getPath());
		attrs.addAttribute("SIZE", union.isZeroLength() ? 0 : union.getLength(), true);
		writer.startElement("UNION", attrs);
		writeRegularComment(writer, union.getDescription());
		DataTypeComponent[] members = union.getComponents();
		for (DataTypeComponent member : members) {
			writerMember(writer, member);
		}
		writer.endElement("UNION");
	}

	private void writerMember(XmlWriter writer, DataTypeComponent member) {
		XmlAttributes attrs = new XmlAttributes();
		// TODO: how should we output bitfields (packed/non-packed)
		// TODO: multiple components at same offset (e.g., zero-length arrays) could throw-off IDA XML import
		attrs.addAttribute("OFFSET", member.getOffset(), true);
		attrs.addAttribute("DATATYPE", member.getDataType().getDisplayName());
		attrs.addAttribute("DATATYPE_NAMESPACE", member.getDataType().getCategoryPath().getPath());
		if (member.getFieldName() != null) {
			attrs.addAttribute("NAME", member.getFieldName());
		}
		attrs.addAttribute("SIZE", member.getLength(), true);
		writer.startElement("MEMBER", attrs);
		writeRegularComment(writer, member.getComment());
		DisplaySettingsHandler.writeSettings(writer, member.getDefaultSettings());
		writer.endElement("MEMBER");
	}

	/**
	 * Output data types in XML format for debugging purposes.
	 * NOTE: There is no support for reading the XML produced by this method.
	 * @param dataManager the data type manager
	 * @param outputFilename name of the output file
	 * @throws IOException if there was a problem writing to the file
	 */
	public static void writeAsXMLForDebug(DataTypeManager dataManager, String outputFilename)
			throws IOException {
		if (!outputFilename.endsWith(".xml")) {
			outputFilename = outputFilename + ".xml";
		}
		File file = new File(outputFilename);

		XmlWriter writer = new XmlWriter(file, "PROGRAM.DTD");

		MessageLog log = new MessageLog();
		DataTypesXmlMgr mgr = new DataTypesXmlMgr(dataManager, log);
		try {
			mgr.write(writer, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			// can't happen with dummy monitor
		}

		writer.close();
	}
}
