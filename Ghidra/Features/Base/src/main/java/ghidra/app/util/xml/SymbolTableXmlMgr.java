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

import java.io.IOException;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.XmlProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.*;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * XML manager for the Symbol Table.
 *
 */
class SymbolTableXmlMgr {

	private Program program;
	private SymbolTable symbolTable;
	private MessageLog log;
	private AddressFactory factory;
	private boolean overwritePrimary;

	private boolean secondPassRequired = false;

	SymbolTableXmlMgr(Program program, MessageLog log) {
		this.program = program;
		this.log = log;
		symbolTable = program.getSymbolTable();
		factory = program.getAddressFactory();
	}

	/**
	 * Following the use of read on the SYMBOL_TABLE element, this method should be invoked
	 * to determine if a second pass is required to process local.
	 * @return true if a second pass is required
	 */
	boolean isSecondPassRequired() {
		return secondPassRequired;
	}

	/**
	 * Process the symbol table section of the XML file.
	 * @param parser xml reader
	 * @param isOverwritePrimary true means to overwrite the primary symbol
	 * if one already exists
	 * @param monitor monitor that can be canceled
	 */
	void read(XmlPullParser parser, boolean isOverwritePrimary, TaskMonitor monitor)
			throws CancelledException {
		read(parser, isOverwritePrimary, 1, monitor);
	}

	/**
	 * Process the symbol table section of the XML file.
	 * @param parser xml reader
	 * @param isOverwritePrimary true means to overwrite the primary symbol
	 * if one already exists
	 * @param monitor monitor that can be canceled
	 */
	void readPass2(XmlPullParser parser, boolean isOverwritePrimary, TaskMonitor monitor)
			throws CancelledException {
		read(parser, isOverwritePrimary, 2, monitor);
	}

	private void read(XmlPullParser parser, boolean isOverwritePrimary, int passNumber,
			TaskMonitor monitor) throws CancelledException {

		this.overwritePrimary = isOverwritePrimary;

		final XmlElement symbolTableElement = parser.start("SYMBOL_TABLE");

		while (parser.peek().isStart()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			XmlElement symbolElement = parser.start("SYMBOL");
			processSymbol(symbolElement, parser, passNumber);
			parser.end(symbolElement);
		}
		parser.end(symbolTableElement);
	}

	/**
	 * Write out the XML for the symbol table.
	 * @param writer writer for XML
	 * @param monitor monitor that can be canceled
	 * should be written
	 * @throws IOException
	 */
	void write(XmlWriter writer, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		monitor.setMessage("Writing SYMBOL TABLE ...");

		writer.startElement("SYMBOL_TABLE");

		SymbolIterator iter = symbolTable.getSymbolIterator();
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}

			Symbol symbol = iter.next();
			SymbolType symbolType = symbol.getSymbolType();
			if (symbol.getSource() == SourceType.DEFAULT) {
				continue;
			}

			if (symbolType != SymbolType.LABEL && symbolType != SymbolType.FUNCTION) {
				continue;
			}

			Address addr = symbol.getAddress();
			if (set == null || set.contains(addr)) {
				XmlAttributes attrs = new XmlAttributes();
				attrs.addAttribute("ADDRESS", XmlProgramUtilities.toString(addr));
				attrs.addAttribute("NAME", symbol.getName());
				attrs.addAttribute("NAMESPACE", getNamespace(symbol));
				String type = checkGlobal(symbol) ? "global" : "local";
				attrs.addAttribute("TYPE", type);
				SourceType source = symbol.getSource();
				attrs.addAttribute("SOURCE_TYPE", source.toString());
				attrs.addAttribute("PRIMARY", symbol.isPrimary() ? "y" : "n");

				writer.startElement("SYMBOL", attrs);
				writer.endElement("SYMBOL");
			}
		}
		writer.endElement("SYMBOL_TABLE");
	}

	private boolean checkGlobal(Symbol symbol) {
		if (symbol.isGlobal()) {
			return true;
		}
		Namespace parent = symbol.getParentNamespace();
		return !(parent.getSymbol() instanceof FunctionSymbol);
	}

	/**
	 * Returns the name of symbol qualified with
	 * any namespace information.
	 * For example, "User32.dll::SomeClass::printf".
	 */
	private String getNamespace(Symbol symbol) {
		StringBuffer buffer = new StringBuffer();
		Namespace namespace = symbol.getParentNamespace();
		while (namespace != program.getGlobalNamespace()) {
			buffer.insert(0, namespace.getName() + "::");
			namespace = namespace.getParentNamespace();
		}
		return buffer.toString();
	}

	private void processSymbol(XmlElement element, XmlPullParser parser, int passNumber) {
		try {
			String type = element.getAttribute("TYPE");
			boolean isLocal = (type != null) && type.equalsIgnoreCase("local");

			String name = element.getAttribute("NAME");
			boolean isDefaultFunctionName =
				name != null && (name.startsWith("FUN_") || name.startsWith("thunk_"));

			// Handle locals during pass-2 and all others during pass-1
			if (isLocal || isDefaultFunctionName) {
				if (passNumber != 2) {
					secondPassRequired = true;
					return;
				}
			}
			else if (passNumber == 2) {
				return;
			}

			String addrStr = element.getAttribute("ADDRESS");
			String namespace = element.getAttribute("NAMESPACE");
			if (namespace != null && namespace.endsWith("::")) {
				namespace = namespace.substring(namespace.length() - 2);
			}
			String primary = element.getAttribute("PRIMARY");
			String sourceTypeString = element.getAttribute("SOURCE_TYPE");

			boolean isPrimary = (primary == null) || primary.equalsIgnoreCase("y");

			SourceType sourceType = SourceType.USER_DEFINED;
			try {
				if (sourceTypeString != null) {
					sourceType = SourceType.valueOf(sourceTypeString);
				}
			}
			catch (IllegalArgumentException iae) {
				log.appendMsg("Unknown SourceType: " + sourceTypeString);
			}

			Address addr = XmlProgramUtilities.parseAddress(factory, addrStr);
			if (addr == null) {
				throw new XmlAttributeException("Incompatible Symbol Address: " + addrStr);
			}
			if (name == null) {
				throw new XmlAttributeException(
					"Missing required symbol name for address: " + addrStr);
			}

			Namespace localNamespace = symbolTable.getNamespace(addr);
			Namespace scope = program.getGlobalNamespace(); // default to global scope
			if (isLocal) {
				scope = localNamespace;
			}
			else if (localNamespace != null &&
				localNamespace.getName().equalsIgnoreCase(namespace)) {
				scope = localNamespace;
			}
			else if (namespace != null && namespace.length() != 0) {
				if (program.getGlobalNamespace().equals(localNamespace)) {
					scope = NamespaceUtils.createNamespaceHierarchy(namespace,
						program.getGlobalNamespace(), program, sourceType);
				}
				else {
					name = namespace + name;
				}
			}

			Symbol s = symbolTable.getPrimarySymbol(addr);
			if (name.startsWith("thunk_")) {
				if (s == null || s.getSymbolType() != SymbolType.FUNCTION) {
					log.appendMsg("Thunk symbol ignored at non-function location: " + addr);
					return;
				}
				Function f = (Function) s.getObject();
				if (!f.isThunk()) {
					String thunkedName = name.substring(6);
					Symbol symbol = SymbolUtilities.getExpectedLabelOrFunctionSymbol(program,
						thunkedName, err -> log.error(null, err));
					if (symbol == null || symbol.getSymbolType() != SymbolType.FUNCTION) {
						log.appendMsg(
							"Failed to establish thunk function for function at: " + addr);
						return;
					}
					f.setThunkedFunction((Function) symbol.getObject());
				}
			}
			else if (s != null &&
				!(s.getName().equals(name) && !scope.equals(s.getParentNamespace()))) {
				s = symbolTable.getSymbol(name, addr, scope);
			}

			if (s == null) {
				s = SymbolUtilities.createPreferredLabelOrFunctionSymbol(program, addr, scope, name,
					sourceType);
			}

			if (isPrimary && overwritePrimary) {
				s.setPrimary();
			}
			if (sourceType != SourceType.DEFAULT) {
				s.setSource(sourceType);
			}
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}
}
