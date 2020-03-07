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

import java.awt.Color;
import java.util.*;

import javax.swing.ImageIcon;

import ghidra.app.cmd.function.*;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.XmlProgramUtilities;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.*;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;
import resources.ResourceManager;

class FunctionsXmlMgr {
	public final static String LIB_BOOKMARK_CATEGORY = "Library Identification";
	public final static String FID_BOOKMARK_CATEGORY = "Function ID Analyzer";
	private static final Set<String> LIBRARY_BOOKMARK_CATEGORY_STRINGS = new HashSet<>();
	static {
		LIBRARY_BOOKMARK_CATEGORY_STRINGS.add(LIB_BOOKMARK_CATEGORY);
		LIBRARY_BOOKMARK_CATEGORY_STRINGS.add(FID_BOOKMARK_CATEGORY);
	}

	private Program program;
	private Listing listing;
	private DtParser dtParser;
	private AddressFactory factory;
	private MessageLog log;

	FunctionsXmlMgr(Program program, MessageLog log) {
		this.program = program;
		this.listing = program.getListing();
		this.factory = program.getAddressFactory();
		this.log = log;
	}

	/**
	 * Parses a list of {@link Function function} definitions from xml and creates then, adding them to the current
	 * {@link Program program}.
	 * <p>
	 * Information from a TYPEINFO_COMMENT is used in preference to information from RETURN_TYPE and STACK_FRAME/STACK_VARs that
	 * are tagged as parameters.
	 * <p>
	 * DTD for the FUNCTION element:
	 * <pre><code>
	 * &lt;!ELEMENT FUNCTION (RETURN_TYPE?, ADDRESS_RANGE*, REGULAR_CMT?, REPEATABLE_CMT?, TYPEINFO_CMT?, STACK_FRAME?, REGISTER_VAR*)&gt;
	 * </code></pre>
	 * <p>
	 * @param parser the parser
	 * @param overwriteConflicts true to overwrite any conflicts
	 * @param ignoreStackFrames true to ignore stack frames
	 * @param monitor the task monitor
	 * @throws AddressFormatException if any address is not parsable 
	 * @throws CancelledException if the operation is cancelled through the monitor
	 */
	void read(XmlPullParser parser, boolean overwriteConflicts, boolean ignoreStackFrames,
			TaskMonitor monitor) throws AddressFormatException, CancelledException {
		final XmlElement element = parser.start("FUNCTIONS");
		AddressSet functions = new AddressSet();

		DataTypeManager dataManager = listing.getDataTypeManager();
		BuiltInDataTypeManager builtInMgr = BuiltInDataTypeManager.getDataTypeManager();

		try {
			dtParser = new DtParser(dataManager);

			while (parser.peek().isStart()) {
				monitor.checkCanceled();

				final XmlElement functionElement = parser.start("FUNCTION");

				String entryPointStr = functionElement.getAttribute("ENTRY_POINT");
				if (entryPointStr == null) {
					throw new RuntimeException("No entry point provided.");
				}
				Address entryPoint = XmlProgramUtilities.parseAddress(factory, entryPointStr);
				if (entryPoint == null) {
					throw new AddressFormatException(
						"Incompatible Function Entry Point Address: " + entryPointStr);
				}

				try {

					SymbolPath namespacePath = null;
					String name = functionElement.getAttribute("NAME");
					if (name != null) {
						SymbolPath symbolPath = new SymbolPath(name);
						name = symbolPath.getName();
						namespacePath = symbolPath.getParent();
					}

					AddressSet body = new AddressSet(entryPoint, entryPoint);

					if (functionElement.hasAttribute("LIBRARY_FUNCTION")) {
						boolean isLibFunc = XmlUtilities.parseBoolean(
							functionElement.getAttribute("LIBRARY_FUNCTION"));
						if (isLibFunc) {
							BookmarkManager bm = program.getBookmarkManager();
							BookmarkType bt = bm.getBookmarkType("IMPORTED");
							if (bt == null) {
								ImageIcon icon =
									ResourceManager.loadImage("images/imported_bookmark.gif");
								bt = bm.defineType("IMPORTED", icon, Color.DARK_GRAY, 0);
							}
							bm.setBookmark(entryPoint, "IMPORTED", LIB_BOOKMARK_CATEGORY,
								"Library function");
						}
					}

					DataType returnType = readReturnType(parser, name);
					readAddressRange(parser, body);
					CreateFunctionCmd cmd =
						new CreateFunctionCmd(null, entryPoint, body, SourceType.USER_DEFINED);
					if (!cmd.applyTo(program)) {
						Msg.error(this, "Failed to create function at " + entryPoint + ": " +
							cmd.getStatusMsg());
						parser.discardSubTree(functionElement);
						continue;
					}

					Function func = cmd.getFunction();
					if (name != null && !SymbolUtilities.isReservedDynamicLabelName(name,
						program.getAddressFactory())) {
						try {
							Symbol symbol = func.getSymbol();
							Namespace namespace =
								NamespaceUtils.getFunctionNamespaceAt(program, namespacePath,
									entryPoint);
							if (namespace == null) {
								namespace = program.getGlobalNamespace();
							}
							symbol.setNameAndNamespace(name, namespace, SourceType.USER_DEFINED);
						}
						catch (DuplicateNameException e) {//name may already be set if symbols were loaded...
						}
					}

					String regularComment = getElementText(parser, "REGULAR_CMT");
					func.setComment(regularComment);
					String repeatableComment = getElementText(parser, "REPEATABLE_CMT");
					func.setRepeatableComment(repeatableComment);
					String typeInfoComment = getElementText(parser, "TYPEINFO_CMT");
					List<Variable> stackParams = new ArrayList<>();
					List<Variable> stackVariables = new ArrayList<>();
					if (!ignoreStackFrames) {
						readStackFrame(parser, func, overwriteConflicts, stackVariables,
							stackParams);
					}
					else {
						while (parser.peek().isStart() &&
							parser.peek().getName().equals("STACK_FRAME")) {
							parser.discardSubTree("STACK_FRAME");
						}
					}
					List<Variable> registerParams = new ArrayList<>();
					readRegisterVars(parser, func, registerParams);

					if (typeInfoComment == null) {
						if (returnType != null) {
							func.setReturnType(returnType, SourceType.IMPORTED);
						}

						// Always set to custom storage to preserve all storage specified in XML
						func.setCustomVariableStorage(true);

						try {
							List<Variable> allParams = new ArrayList<>();
							allParams.addAll(registerParams);
							allParams.addAll(stackParams);

							func.replaceParameters(allParams, FunctionUpdateType.CUSTOM_STORAGE,
								true, SourceType.IMPORTED);
						}
						catch (DuplicateNameException e) {
							log.appendMsg("Could not set name of a parameter in function: " +
								funcDesc(func) + ": " + e.getMessage());
						}
						catch (InvalidInputException iie) {
							log.appendMsg("Bad parameter definition in function: " +
								funcDesc(func) + ": " + iie.getMessage());
						}
					}
					else {
						tryToParseTypeInfoComment(monitor, func, typeInfoComment);
					}
					addLocalVars(func, stackVariables, overwriteConflicts);

					functions.addRange(entryPoint, entryPoint);
					parser.end(functionElement);
				}
				catch (Exception e) {
					parser.discardSubTree(functionElement);
					log.appendException(e);
				}
			}
		}
		finally {
			builtInMgr.close();
			dtParser = null;
		}
		parser.end(element);
		FunctionPurgeAnalysisCmd purgeAnalysisCmd = new FunctionPurgeAnalysisCmd(functions);
		purgeAnalysisCmd.applyTo(program, monitor);
		FunctionStackAnalysisCmd stackAnalysisCmd = new FunctionStackAnalysisCmd(functions, true);
		stackAnalysisCmd.applyTo(program, monitor);
	}

	private void tryToParseTypeInfoComment(TaskMonitor monitor, Function func,
			String typeInfoComment) {
		try {
			FunctionDefinitionDataType funcDef = CParserUtils.parseSignature(
				(DataTypeManagerService) null, program, typeInfoComment, false);
			if (funcDef == null) {
				log.appendMsg("Unable to parse function definition: " + typeInfoComment);
				return;
			}

			ApplyFunctionSignatureCmd afsCmd = new ApplyFunctionSignatureCmd(func.getEntryPoint(),
				funcDef, SourceType.IMPORTED, false, false);
			if (!afsCmd.applyTo(program, monitor)) {
				// TODO: continue trying to add local vars after failing to update the function signature?
				log.appendMsg("Failed to update function " + funcDesc(func) + " with signature \"" +
					typeInfoComment + "\"");
			}
		}
		// catch all errors so that import will continue
		catch (Throwable pe) {
			log.appendMsg("Unable to parse function definition: " + typeInfoComment);
		}
	}

	private void addLocalVars(Function function, List<Variable> variables,
			boolean overwriteConflicts) throws InvalidInputException {
		for (Variable v : variables) {

			VariableUtilities.checkVariableConflict(function, v, v.getVariableStorage(),
				overwriteConflicts);

			try {
				String name = v.getName();
				boolean isDefaultVariableName = (name == null) ||
					SymbolUtilities.getDefaultLocalName(program, v.getStackOffset(), 0)
							.equals(
								name);

				SourceType sourceType =
					isDefaultVariableName ? SourceType.DEFAULT : SourceType.USER_DEFINED;

				function.addLocalVariable(v, sourceType);
			}
			catch (DuplicateNameException e) {
				log.appendMsg("Could not add local variable to function " + funcDesc(function) +
					": " + v.getName() + ": " + e.getMessage());
			}
		}
	}

	private static String funcDesc(Function func) {
		return func.getName() + "[" + func.getEntryPoint().toString() + "]";
	}

	private DataType findDataType(XmlElement element) {
		String dtName = element.getAttribute("DATATYPE");
		if (dtName == null) {
			return DataType.DEFAULT;
		}
		CategoryPath cp = new CategoryPath(element.getAttribute("DATATYPE_NAMESPACE"));
		int size =
			element.hasAttribute("SIZE") ? XmlUtilities.parseInt(element.getAttribute("SIZE")) : -1;
		return dtParser.parseDataType(dtName, cp, size);
	}

	/*
	 * Returns the text embedded in an optional xml element.  If the next element in the stream is not
	 * the "expectedElementName", the xml parser stream is unchanged
	 */
	private String getElementText(XmlPullParser parser, String expectedElementName) {
		String result = null;
		XmlElement element = parser.peek();
		if (element.getName().equals(expectedElementName)) {
			element = parser.next();
			element = parser.next();
			result = element.getText();
		}
		return result;
	}

	private DataType readReturnType(XmlPullParser parser, String funcName) {
		XmlElement element = parser.peek();
		if (element.getName().equals("RETURN_TYPE")) {
			element = parser.next();

			DataType dt = findDataType(element);
			if (dt == null) {
				log.appendMsg("Unable to locate return type [" + element.getAttribute("DATATYPE") +
					"] for function [" + funcName + "]");
			}

			element = parser.next();
			return dt;
		}
		return null;
	}

	private void readAddressRange(XmlPullParser parser, AddressSet set)
			throws AddressFormatException, AddressOutOfBoundsException {

		XmlElement element = parser.peek();
		while (element.getName().equals("ADDRESS_RANGE")) {
			element = parser.next();

			String startStr = element.getAttribute("START");
			String endStr = element.getAttribute("END");

			Address start = XmlProgramUtilities.parseAddress(factory, startStr);
			Address end = XmlProgramUtilities.parseAddress(factory, endStr);

			try {
				if (start == null || end == null) {
					throw new AddressFormatException(
						"Incompatible Function Address Range: [" + startStr + "," + endStr + "]");
				}
				set.addRange(start, end);
			}
			finally {
				element = parser.next();//consume the end addr range tag...
			}

			element = parser.peek();
		}
	}

	private void readStackFrame(XmlPullParser parser, Function func, boolean overwriteConflicts,
			List<Variable> stackVariables, List<Variable> stackParams) {
		XmlElement element = parser.peek();
		if (element.getName().equals("STACK_FRAME")) {
			element = parser.next();

			StackFrame frame = func.getStackFrame();

			if (element.hasAttribute("LOCAL_VAR_SIZE")) {
				frame.setLocalSize(XmlUtilities.parseInt(element.getAttribute("LOCAL_VAR_SIZE")));
			}
//			if (element.hasAttribute("PARAM_OFFSET")) {
//				frame.setParameterOffset(XmlUtilities.parseInt(element.getAttribute("PARAM_OFFSET")));
//			}
			//int registerSaveSize = 0;
			//if (element.hasAttribute("REGISTER_SAVE_SIZE")) {
			//	registerSaveSize = XmlUtilities.parseInt(element.getAttribute("REGISTER_SAVE_SIZE"));
			//}
			if (element.hasAttribute("RETURN_ADDR_SIZE")) {
				frame.setReturnAddressOffset(
					XmlUtilities.parseInt(element.getAttribute("RETURN_ADDR_SIZE")));
			}
			if (element.hasAttribute("BYTES_PURGED")) {
				func.setStackPurgeSize(XmlUtilities.parseInt(element.getAttribute("BYTES_PURGED")));
			}

			readStackVariables(parser, func, overwriteConflicts, stackVariables, stackParams);

			element = parser.next();
		}
	}

	private void readStackVariables(XmlPullParser parser, Function function,
			boolean overwriteConflicts, List<Variable> stackVariables, List<Variable> stackParams) {

		XmlElement element = parser.peek();
		while (element.getName().equals("STACK_VAR")) {
			element = parser.next();
			String stackPtrStringValue = element.getAttribute("STACK_PTR_OFFSET");
			if (stackPtrStringValue == null) {
				stackPtrStringValue = element.getAttribute("OFFSET");
			}
			int offset =
				stackPtrStringValue == null ? 0 : XmlUtilities.parseInt(stackPtrStringValue);

			String sizeStringValue = element.getAttribute("SIZE");
			int size = 1;
			if (stackPtrStringValue != null) {
				size = XmlUtilities.parseInt(sizeStringValue);
			}

			boolean isParameter = function.getStackFrame().isParameterOffset(offset);

			String originalName = element.getAttribute("NAME");

			DataType dt = findDataType(element);
			if (dt == null) {
				dt = Undefined.getUndefinedDataType(size);
			}

			String name = originalName;
			if (name != null) {
				name = getUniqueVarName(function, name, offset);
			}

			try {
				String regularComment = getElementText(parser, "REGULAR_CMT");

				Variable var = new LocalVariableImpl(name, dt, offset, program);

				VariableUtilities.checkVariableConflict(function, var, var.getVariableStorage(),
					overwriteConflicts);

				if (isParameter) {
					var = new ParameterImpl(name, dt, offset, program);
					stackParams.add(var);
				}
				else {
					var = new LocalVariableImpl(name, dt, offset, program);
					stackVariables.add(var);
				}
				var.setComment(regularComment);
			}
			catch (InvalidInputException e) {
				log.appendException(e);
			}

			element = parser.peek();
			getElementText(parser, "REPEATABLE_CMT");

			element = parser.next();
			element = parser.peek();
		}
	}

	private String getUniqueVarName(Function function, String name, int offset) {
		Symbol s = program.getSymbolTable().getVariableSymbol(name, function);
		if (s == null) {
			return name;
		}
		SymbolType st = s.getSymbolType();
		if (st == SymbolType.LOCAL_VAR || st == SymbolType.PARAMETER) {
			Variable v = (Variable) s.getObject();
			if (v.isStackVariable() && offset == v.getStackOffset()) {
				return name;
			}
		}
		return name + "_" + offset;
	}

	private void readRegisterVars(XmlPullParser parser, Function func,
			List<Variable> registerParams) {
		XmlElement element = parser.peek();
		while (element.getName().equals("REGISTER_VAR")) {
			element = parser.next();
			try {
				String name = element.getAttribute("NAME");
				String registerName = element.getAttribute("REGISTER");

				DataType dt = findDataType(element);
				String comment = getElementText(parser, "REGULAR_CMT");

				ProgramContext context = program.getProgramContext();
				Register register = context.getRegister(registerName);

				if (dt != null && dt.getLength() > register.getMinimumByteSize()) {
					log.appendMsg("Data type [" + element.getAttribute("DATATYPE") +
						"] too large for register [" + registerName + "]");
					dt = null;
				}

				Variable registerParam = new ParameterImpl(name, dt, register, program);
				registerParam.setComment(comment);
				registerParams.add(registerParam);
			}
			catch (InvalidInputException e) {
				log.appendException(e);
			}
			catch (IllegalArgumentException e) {
				log.appendException(e);
			}

			element = parser.next();
			element = parser.peek();
		}
	}

	void write(XmlWriter writer, AddressSetView addrs, TaskMonitor monitor)
			throws CancelledException {
		monitor.setMessage("Writing FUNCTIONS ...");
		writer.startElement("FUNCTIONS");

		FunctionIterator fIter = listing.getFunctions(addrs, true);
		while (fIter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			Function func = fIter.next();
			writeFunction(writer, func);
		}

		writer.endElement("FUNCTIONS");
	}

	private void writeFunction(XmlWriter writer, Function func) {
		XmlAttributes attrs = new XmlAttributes();
		attrs.addAttribute("ENTRY_POINT", XmlProgramUtilities.toString(func.getEntryPoint()));
		attrs.addAttribute("NAME", getName(func));
		attrs.addAttribute("LIBRARY_FUNCTION", isLibrary(func) ? "y" : "n");

		writer.startElement("FUNCTION", attrs);

		writeReturnType(writer, func);
		writeAddressRange(writer, func);
		writeRegularComment(writer, func.getComment());
		writeRepeatableComment(writer, func.getRepeatableComment());
		if (func.getSignatureSource() != SourceType.DEFAULT) {
			writeTypeInfoComment(writer, func);
		}
		writeStackFrame(writer, func);
		writeRegisterVars(writer, func);

		writer.endElement("FUNCTION");
	}

	private void writeTypeInfoComment(XmlWriter writer, Function func) {
		writer.writeElement("TYPEINFO_CMT", null, func.getPrototypeString(true, true));
	}

	private boolean isLibrary(Function func) {
		BookmarkManager bm = program.getBookmarkManager();
		Bookmark[] bookmarks = bm.getBookmarks(func.getEntryPoint());
		for (Bookmark b : bookmarks) {
			if (LIBRARY_BOOKMARK_CATEGORY_STRINGS.contains(b.getCategory())) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Returns the name of function qualified with
	 * any namespace information.
	 * For example, "User32.dll::SomeClass::printf".
	 */
	private String getName(Function function) {
		StringBuffer nameBuff = new StringBuffer(function.getName());
		Namespace ns = function.getParentNamespace();
		while (ns != program.getGlobalNamespace()) {
			nameBuff.insert(0, ns.getName() + "::");
			ns = ns.getParentNamespace();
		}
		return nameBuff.toString();
	}

	private void writeReturnType(XmlWriter writer, Function func) {
		DataType rt = func.getReturnType();
		if (rt != null && rt != DataType.DEFAULT) {
			XmlAttributes attrs = new XmlAttributes();
			attrs.addAttribute("DATATYPE", rt.getDisplayName());
			attrs.addAttribute("DATATYPE_NAMESPACE", rt.getCategoryPath().getPath());
			attrs.addAttribute("SIZE", rt.getLength(), true);
			writer.writeElement("RETURN_TYPE", attrs);
		}
	}

	private void writeAddressRange(XmlWriter writer, Function func) {
		AddressSetView body = func.getBody();
		AddressRangeIterator iter = body.getAddressRanges();
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			XmlAttributes attrs = new XmlAttributes();
			attrs.addAttribute("START", XmlProgramUtilities.toString(range.getMinAddress()));
			attrs.addAttribute("END", XmlProgramUtilities.toString(range.getMaxAddress()));
			writer.writeElement("ADDRESS_RANGE", attrs);
		}
	}

	private void writeRegularComment(XmlWriter writer, String comment) {
		if (comment != null && comment.length() > 0) {
			writer.writeElement("REGULAR_CMT", null, comment);
		}
	}

	private void writeRepeatableComment(XmlWriter writer, String comment) {
		if (comment != null && comment.length() > 0) {
			writer.writeElement("REPEATABLE_CMT", null, comment);
		}
	}

	private void writeStackFrame(XmlWriter writer, Function func) {
		StackFrame frame = func.getStackFrame();

		XmlAttributes attrs = new XmlAttributes();
		attrs.addAttribute("LOCAL_VAR_SIZE", frame.getLocalSize(), true);
		attrs.addAttribute("PARAM_OFFSET", frame.getParameterOffset(), true);
//		attrs.addAttribute("REGISTER_SAVE_SIZE", -1);
		attrs.addAttribute("RETURN_ADDR_SIZE", frame.getReturnAddressOffset(), true);

		int size = func.getStackPurgeSize();
		if (size != Function.UNKNOWN_STACK_DEPTH_CHANGE &&
			size != Function.INVALID_STACK_DEPTH_CHANGE) {
			attrs.addAttribute("BYTES_PURGED", size);
		}

		writer.startElement("STACK_FRAME", attrs);

		Variable[] vars = frame.getStackVariables();
		for (Variable var : vars) {
			writeStackVariable(writer, var);
		}

		writer.endElement("STACK_FRAME");
	}

	private void writeStackVariable(XmlWriter writer, Variable var) {
		XmlAttributes attrs = new XmlAttributes();
		attrs.addAttribute("STACK_PTR_OFFSET", var.getStackOffset(), true);
		attrs.addAttribute("NAME", var.getName());
		DataType dt = var.getDataType();
		attrs.addAttribute("DATATYPE", dt.getDisplayName());
		attrs.addAttribute("DATATYPE_NAMESPACE", dt.getCategoryPath().getPath());

		//write the stack variable length, not the datatype length
		attrs.addAttribute("SIZE", var.getLength(), true);

		String comment = var.getComment();
		if (comment == null || comment.length() == 0) {
			writer.writeElement("STACK_VAR", attrs);
		}
		else {
			writer.startElement("STACK_VAR", attrs);
			writeRegularComment(writer, comment);
			writer.endElement("STACK_VAR");
		}
	}

	private void writeRegisterVars(XmlWriter writer, Function func) {
		Parameter[] regs = getRegisterParameters(func);
		for (Parameter reg : regs) {
			XmlAttributes attrs = new XmlAttributes();
			attrs.addAttribute("NAME", reg.getName());
			attrs.addAttribute("REGISTER", reg.getRegister().getName());
			attrs.addAttribute("DATATYPE", reg.getDataType().getDisplayName());
			attrs.addAttribute("DATATYPE_NAMESPACE", reg.getDataType().getCategoryPath().getPath());

			String comment = reg.getComment();
			if (comment == null || comment.length() == 0) {
				writer.writeElement("REGISTER_VAR", attrs);
			}
			else {
				writer.startElement("REGISTER_VAR", attrs);
				writeRegularComment(writer, comment);
				writer.endElement("REGISTER_VAR");
			}
		}
	}

	private Parameter[] getRegisterParameters(Function function) {

		ArrayList<Parameter> list = new ArrayList<Parameter>();
		Parameter[] params = function.getParameters();
		for (Parameter param : params) {
			if (param.isRegisterVariable()) {
				list.add(param);
			}
		}
		Parameter[] r = new Parameter[list.size()];
		return list.toArray(r);
	}

}
