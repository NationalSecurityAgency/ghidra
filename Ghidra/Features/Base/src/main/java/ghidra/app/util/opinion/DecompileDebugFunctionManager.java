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
package ghidra.app.util.opinion;

import static ghidra.program.model.pcode.AttributeId.*;

import java.util.ArrayList;
import java.util.Map;

import ghidra.framework.store.LockException;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.pcode.AddressXML;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * Manage the parsing and population of function objects. All functions are loaded the same way, 
 * even if it's only referenced by the "central function" (the function that was in the decompiler 
 * pane when the Decompile Debug (@DecompileDebug.java) feature was used).
 */
public class DecompileDebugFunctionManager {

	Program prog;
	TaskMonitor monitor;
	DecompileDebugDataTypeManager dataTypeManager;

	/**
	 * Each function requires a program, task monitor and the program's Data Type Manager in order
	 * to be generated.
	 * 
	 * @param prog Program 
	 * @param monitor TaskMonitor
	 * @param dataTypeManager Program's DataTypeManager
	 */
	public DecompileDebugFunctionManager(Program prog, TaskMonitor monitor,
			DecompileDebugDataTypeManager dataTypeManager) {
		this.prog = prog;
		this.monitor = monitor;
		this.dataTypeManager = dataTypeManager;
	}

	/**
	 * Setup functions from within the {@code <symbollist>} tag.
	 * Functions referenced by the central function are loaded the same except we do not 
	 * (currently) have the memory/program context for them. Thus, they will show up in the Listing
	 * with a red "X". 
	 * NOTE: This is the expected functionality. 
	 * 
	 * @param parser XmlPullParser
	 * @param scopeMap {@code Map<String, Namespace>} used for getting parent namespace 
	 * @param log XmlMessageLog
	 */
	public void parseFunctionSignature(XmlPullParser parser, Map<Long, Namespace> scopeMap,
			XmlMessageLog log) {
		XmlElement functionElement = parser.start("function");
		String functionName = functionElement.getAttribute(ATTRIB_NAME.name());
		boolean noReturn = functionElement.hasAttribute(ATTRIB_NORETURN.name());

		Function createdFunction = null;
		XmlElement localdb = null;
		Address functionAddr = null;
		while (parser.peek().isStart()) {
			String tagName = parser.peek().getName();
			switch (tagName) {
				case "addr":
					try {
						XmlElement addressTag = parser.start("addr");
						functionAddr =
							AddressXML.restoreXml(addressTag, prog.getCompilerSpec())
									.getFirstAddress();
						parser.end(addressTag);
						break;
					}
					catch (XmlParseException e) {
						log.appendException(e);
					}
				case "scope":

					XmlElement scopeElement = parser.start("scope");
					String scopeName = scopeElement.getAttribute(ATTRIB_NAME.name());

					Namespace functionNamespace =
						getParentNamespace(parser, scopeMap, scopeName);

					createdFunction =
						setFunctionNamespaceAndStorage(functionName, functionAddr,
							functionNamespace,
							log);
					createdFunction.setNoReturn(noReturn);
					handleScopeSubtags(createdFunction, parser, log);

					parser.end(scopeElement);
					parser.end(localdb);

					break;
				case "prototype":
					XmlElement prototypeElement = parser.start("prototype");
					try {
						createdFunction
								.setCallingConvention(prototypeElement.getAttribute("model"));
						createdFunction.setReturnType(retrieveReturnType(parser, log),
							SourceType.IMPORTED);

						if (parser.peek().isStart("inject")) {
							parser.start("inject");
							String callFixup = parser.end().getText();
							createdFunction.setCallFixup(callFixup);
							log.appendMsg("Found an inject tag on the function: " +
								createdFunction.getName());
						}
					}
					catch (InvalidInputException e) {
						log.appendException(e);
					}

					while (!parser.peek().isEnd()) {
						log.appendMsg(parser.getLineNumber(), "Level " + parser.getCurrentLevel() +
							" tag not currently supported: " + parser.peek().getName());
						parser.discardSubTree();
					}
					parser.end(prototypeElement);
					break;
				case "localdb":
					localdb = parser.start("localdb");  // this is a wrapper, it ends after the scope tag
					break;
				default:
					log.appendMsg(parser.getLineNumber(), "Level " + parser.getCurrentLevel() +
						" tag not currently supported: " + parser.peek().getName());
					parser.discardSubTree();
			}
		}
		parser.end(functionElement);
	}

	/**
	 * Parse the <parent> subtag under <scope> and generate the function's Namespace.
	 * 
	 * @param parser XmlPullParser
	 * @param scopeMap Map<String, Namespace> used for looking up parent Namespace based on ID from <parent> tag
	 * @param scopeName String from <scope> tag
	 * 
	 * @return Namespace generated namespace 
	 */
	private Namespace getParentNamespace(XmlPullParser parser, Map<Long, Namespace> scopeMap,
			String scopeName) {
		XmlElement parentTag = parser.start("parent");
		Long parentId = SpecXmlUtils.decodeLong(parentTag.getAttribute(ATTRIB_ID.name()));
		Namespace parentNamespace = scopeMap.get(parentId);
		parser.end(parentTag);
		return parentNamespace;
	}

	/**
	 * Step through the <scope> subtags, including:
	 * - <parent>
	 * - <rangelist>
	 * - <symbollist>
	 * 
	 * NOTE: A populated <rangelist> is not currently supported. 
	 * 
	 * @param createdFunction Function
	 * @param parser XmlPullParser
	 * @param log XmlMessageLog
	 */
	private void handleScopeSubtags(Function createdFunction,
			XmlPullParser parser, XmlMessageLog log) {

		while (parser.peek().isStart()) {
			String tagName = parser.peek().getName();
			switch (tagName) {
				case "rangelist":
					log.appendMsg(parser.getLineNumber(), "Level " + parser.getCurrentLevel() +
						" tag not currently supported: " + tagName);
					parser.discardSubTree(); // we currently do not support a populated rangelist
					break;
				case "symbollist":
					XmlElement symbollistElement = parser.start("symbollist");
					findFunctionVariables(parser, createdFunction, log);
					parser.end(symbollistElement);
					break;
				default:
					log.appendMsg(parser.getLineNumber(), "Level " + parser.getCurrentLevel() +
						" tag not currently supported: " + tagName);
					parser.discardSubTree();
			}
		}
	}

	/**
	 * Parse and retrieve the return type from the program's data type manager.
	 * 
	 * @param parser XmlPullParser
	 * @param log XmlMessageLog
	 * 
	 * @return DataType return type
	 */
	private DataType retrieveReturnType(XmlPullParser parser, XmlMessageLog log) {
		XmlElement returnElement = parser.start("returnsym");
		XmlElement addrElement = parser.start("addr");
		//Address address = AddressXML.restoreXml(addrElement, prog.getCompilerSpec()).getFirstAddress();
		parser.end(addrElement);

		DataType returnType = dataTypeManager.parseDataTypeTag(parser, log);
		parser.end(returnElement);
		return returnType;
	}

	/**
	 * Parse and load parameter and local variables for the given function by 
	 * cycling through the <mapsym> tags within the symbollist
	 * 
	 * NOTE: populated <rangelist> tags within a mapsym tag are not currently supported.
	 * 
	 * NOTE: Keep a list of parameters and modify the function only once 
	 * (ie. 1 call to updateFunction()) after all variables have been parsed.
	 * 
	 * @param parser XmlPullParser
	 * @param createdFunction Function 
	 * @param log XmlMessageLog
	 */
	private void findFunctionVariables(XmlPullParser parser, Function createdFunction,
			XmlMessageLog log) {

		ArrayList<ParameterImpl> paramList = new ArrayList<ParameterImpl>();
		try {
			while (parser.peek().isStart()) {
				XmlElement mapsymElement = parser.start("mapsym");
				XmlElement symbolElement = parser.start("symbol");
				boolean isParam = SpecXmlUtils.decodeInt(symbolElement.getAttribute("cat")) == 0;
				String varName = symbolElement.getAttribute(ATTRIB_NAME.name());
				DataType varType = dataTypeManager.parseDataTypeTag(parser, log);
				parser.end(symbolElement);
				XmlElement addrElement = parser.start("addr");

				if (isParam) {
					Address address = AddressXML.restoreXml(addrElement, prog.getCompilerSpec())
							.getFirstAddress();
					ParameterImpl param = new ParameterImpl(varName, varType,
						address, prog);
					paramList.add(param);
				}
				else {
					int offset = (int) AddressXML.restoreXml(addrElement, prog.getCompilerSpec())
							.getOffset();
					LocalVariableImpl lvar =
						new LocalVariableImpl(varName, varType, offset, prog, SourceType.IMPORTED);
					createdFunction.addLocalVariable(lvar, SourceType.IMPORTED);
				}
				parser.end(addrElement);
				while (parser.peek().isStart()) {
					log.appendMsg(parser.getLineNumber(), "Level " + parser.getCurrentLevel() +
						" tag not currently supported: " + parser.peek().getName());
					parser.discardSubTree();
				}
				parser.end(mapsymElement);
				createdFunction.updateFunction(null, null, paramList,
					FunctionUpdateType.CUSTOM_STORAGE,
					true, SourceType.IMPORTED); // calling convention & return variable are updated later

			}
		}
		catch (NumberFormatException | InvalidInputException
				| DuplicateNameException | XmlParseException e) {
			log.appendException(e);
		}
	}

	/**
	 * Set the Name and Namespace / custom variable storage on the function symbol after the 
	 * initial function signature has been created. 
	 * 	  
	 * @param functionName name
	 * @param functionAddr address offset 
	 * @param namespace Namespace parent namespace
	 * @param log XmlMessageLog
	 * 
	 * @return generated Function
	 */
	private Function setFunctionNamespaceAndStorage(String functionName, Address functionAddr,
			Namespace namespace, XmlMessageLog log) {

		Function createdFunction = createFunction(functionName, functionAddr, namespace, log);
		try {
			createdFunction.setCustomVariableStorage(true);
			Memory memory = prog.getMemory();
			if (!memory.contains(functionAddr)) { // main function block has already been generated
				memory.createInitializedBlock(functionName, functionAddr, 1, (byte) 0, monitor,
					false);
			}
		}
		catch (LockException | IllegalArgumentException
				| MemoryConflictException | AddressOverflowException | CancelledException e) {
			log.appendException(e);
		}
		return createdFunction;
	}

	/**
	 *  Create Function object for populating later using the program's function manager. 
	 *  The central function is the one processed first.
	 *  
	 * @param functionName String
	 * @param functionAddr Address
	 * @param namespace Namespace parent namespace
	 * @param log XmlMessageLog
	 * @return generated function
	 */
	private Function createFunction(String functionName, Address functionAddr,
			Namespace namespace, XmlMessageLog log) {

		FunctionManager funcM = prog.getFunctionManager();
		Function generatedFunction = null;
		try {
			generatedFunction = funcM.createFunction(functionName, namespace, functionAddr,
				new AddressSet(functionAddr, functionAddr), SourceType.IMPORTED);
		}
		catch (InvalidInputException | OverlappingFunctionException e) {
			log.appendException(e);
		}

		return generatedFunction;
	}

}
