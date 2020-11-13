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

import java.io.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import org.jdom.*;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;
import org.xml.sax.*;

import generic.jar.ResourceFile;
import ghidra.app.util.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.GenericXMLOutputter;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.*;
import util.CollectionUtils;

class LibrarySymbolTable {

	private static final SimpleDateFormat TIMESTAMP_FORMAT =
		new SimpleDateFormat("EEE MMM dd hh:mm:ss zzz yyyy");

	private static final int NONE = 0;
	private static final int LIBRARY = 1;
	private static final int EXPORTS = 2;
	private static final int ORDINAL = 3;

	private String tableName;
	private int size;
	private String path;
	private String date;
	private String version;
	private int tempPurge;
	private String fowardLibrary = null;
	private String fowardSymbol = null;
	private HashMap<String, LibraryExportedSymbol> symMap = new HashMap<>();
	private ArrayList<LibraryExportedSymbol> exportList = new ArrayList<>();
	private HashMap<Integer, LibraryExportedSymbol> ordMap = new HashMap<>();
	private Set<String> forwards = new HashSet<>();

	/**
	 * Construct an empty library symbol table
	 * @param tableName symbol table name (generally same as associated library name)
	 * @param size the architecture size of the DLL (e.g., 32 or 64).
	 */
	LibrarySymbolTable(String tableName, int size) {
		this.tableName = tableName.toLowerCase();
		this.size = size;
		this.version = "unknown";
		tempPurge = size <= 32 ? -1 : 0; // assume 0 purge for 64-bit
	}

	/**
	 * Construct library symbol table from an existing symbol exports file in XML format
	 * @param libraryFile existing symbol exports file
	 * @param size the architecture size of the DLL (e.g., 32 or 64).
	 * @throws IOException thrown if file IO error occurs
	 */
	LibrarySymbolTable(ResourceFile libraryFile, int size) throws IOException {
		read(libraryFile, size);
	}

	/**
	 * Construct a library symbol table based upon a specified library in the 
	 * form of a {@link Program} object.
	 * @param library library program
	 * @param monitor task monitor
	 * @throws CancelledException thrown if task cancelled
	 */
	LibrarySymbolTable(Program library, TaskMonitor monitor) throws CancelledException {

		tableName = new File(library.getExecutablePath()).getName().toLowerCase();
		size = library.getLanguage().getLanguageDescription().getSize();

		LibraryHints hints = LibraryHints.getLibraryHints(tableName, size);

		SymbolTable symTab = library.getSymbolTable();

		// go through all the symbols looking for Ordinal_#
		//    get the number and name for the symbol
		SymbolIterator iter = symTab.getSymbolIterator(SymbolUtilities.ORDINAL_PREFIX + "*", true);
		while (iter.hasNext()) {
			monitor.checkCanceled();
			Symbol sym = iter.next();
			int ordinal = SymbolUtilities.getOrdinalValue(sym.getName());
			if (ordinal == -1) {
				throw new RuntimeException("Should never happen!");
			}
			Address symAddr = sym.getAddress();
			String realName = sym.getName();
			Symbol primary = symTab.getPrimarySymbol(symAddr);
			if (primary != null) {
				realName = primary.getName();
			}

			// assumes that Ordinal_# name comes right before the actual name
			Symbol symbolsAt[] = symTab.getSymbols(symAddr);
			for (int i = 0; i < symbolsAt.length; i++) {
				if (symbolsAt[i].getName().equals(sym.getName())) {
					if (i + 1 < symbolsAt.length) {
						realName = symbolsAt[i + 1].getName();
						break;
					}
				}
			}

			fowardLibrary = null;
			fowardSymbol = null;
			tempPurge = -1;
			String comment = "";

			Attribute cmtAttr = hints.getAttributeHint(ordinal, realName, "COMMENT");
			if (cmtAttr != null) {
				comment = cmtAttr.getValue();
			}

			Function func = library.getFunctionManager().getFunctionAt(symAddr);
			if (func != null) {
				tempPurge = func.getStackPurgeSize();
			}
			if (tempPurge == -1 || tempPurge > 128 || tempPurge < -128) {
				Data data = library.getListing().getDefinedDataAt(symAddr);
				if (data != null) {
					Reference[] refs = library.getReferenceManager().getReferencesFrom(symAddr);
					if (refs != null && refs.length > 0 && refs[0].isExternalReference()) {
						ExternalReference exRef = (ExternalReference) refs[0];
						fowardLibrary = exRef.getLibraryName();
						fowardSymbol = exRef.getLabel();
					}
				}

				if (fowardLibrary == null || fowardLibrary.length() <= 0) {
					MemoryBlock block = library.getMemory().getBlock(symAddr);
					if (block != null && block.isExecute()) {
						pseudoDisassemble(library, symAddr);
					}
				}
			}

			boolean noReturn = false;
			Attribute noReturnHint = hints.getAttributeHint(ordinal, realName, "NO_RETURN");
			if (noReturnHint != null && "y".equals(noReturnHint.getValue())) {
				noReturn = true;
			}

			if (fowardLibrary != null && fowardLibrary.length() > 0) {
				forwards.add(fowardLibrary);
			}

			LibraryExportedSymbol expSym = new LibraryExportedSymbol(tableName, size, ordinal,
				realName, fowardLibrary, fowardSymbol, tempPurge, noReturn, comment);

			// add to export list in order
			exportList.add(expSym);
			ordMap.put(Integer.valueOf(ordinal), expSym);
			symMap.put(realName, expSym);
		}
	}

	String getCacheKey() {
		return LibrarySymbolTable.getCacheKey(tableName, size);
	}

	static String getCacheKey(String dllName, int size) {
		return LibraryLookupTable.stripPossibleExtensionFromFilename(dllName).toLowerCase() + ":" +
			size;
	}

	private void pseudoDisassemble(Program library, Address addr) {
		// Pseudo Disassemble to get the purge
		PseudoDisassembler pdis = new PseudoDisassembler(library);
		pdis.followSubFlows(addr, 4000, new PseudoFlowProcessor() {
			@Override
			public boolean followFlows(PseudoInstruction instr) {
				return true;
			}

			@Override
			public boolean process(PseudoInstruction instr) {
				if (instr == null) {
					return false;
				}
				FlowType ftype = instr.getFlowType();
				if (ftype.isTerminal()) {
					if (instr.getMnemonicString().compareToIgnoreCase("ret") == 0) {
						tempPurge = 0;
						Scalar scalar = instr.getScalar(0);
						if (scalar != null) {
							tempPurge = (int) scalar.getSignedValue();
							fowardLibrary = null;
							fowardSymbol = null;
							return false;
						}
					}
				}
				if (ftype.isJump() && ftype.isComputed()) {
					Reference[] refs = instr.getReferencesFrom();
					if (refs.length > 0) {
						Data data = instr.getProgram().getListing().getDefinedDataAt(
							refs[0].getToAddress());
						if (data != null) {
							refs = instr.getProgram().getReferenceManager().getReferencesFrom(
								data.getMinAddress());
							if (refs != null && refs.length > 0 && refs[0].isExternalReference()) {
								ExternalReference exRef = (ExternalReference) refs[0];
								fowardLibrary = exRef.getLibraryName();
								fowardSymbol = exRef.getLabel();
							}
						}
					}
				}
				return true;
			}
		});
	}

	/**
	 * Parse a ordinal exports file produced by Microsoft DUMPBIN /EXPORTS &lt;DLL&gt;
	 * It is expected to start parsing lines following the table header containing the 'ordinal' header.
	 * Each ordinal mapping line is expected to have the format, starting with ordinal number and
	 * ending with symbol name:
	 *   &lt;ordinal&gt; &lt;other-column-data&gt; &lt;name&gt;
	 * The name column contains the symbol name followed by an optional demangled form.  If the name starts with 
	 * [NONAME] this will be stripped.
	 * @param ordinalExportsFile file path to ordinal mapping file produced by DUMPBIN /EXPORTS
	 * @param addMissingOrdinals if true new entries will be created for ordinal mappings
	 * not already existing within this symbol table, otherwise only those which already
	 * exist will be updated with a name if specified by mapping file.
	 */
	public void applyOrdinalFile(ResourceFile ordinalExportsFile, boolean addMissingOrdinals) {
		try (BufferedReader in =
			new BufferedReader(new InputStreamReader(ordinalExportsFile.getInputStream()))) {

			int ordinalColumnEndIndex = -1;
			int nameColumnStartIndex = -1;

			int mode = NONE;
			String inString;
			while ((inString = in.readLine()) != null) {

				if (mode == NONE && inString.trim().startsWith("ordinal")) {
					// rely on column header labels to establish ordinal and name column start/end 
					int ordinalColumnStartIndex = inString.indexOf("ordinal");
					if (ordinalColumnStartIndex < 0) {
						continue;
					}
					ordinalColumnEndIndex = ordinalColumnStartIndex + 7;

					nameColumnStartIndex = inString.indexOf("name");
					if (nameColumnStartIndex < 1) {
						Msg.error(this,
							"Failed to parse ordinal symbol file: " + ordinalExportsFile);
						break;
					}
					mode = ORDINAL;
					continue;
				}

				if (mode != ORDINAL) {
					continue;
				}

				inString = stripComment(inString);
				if (inString.length() < nameColumnStartIndex) {
					continue;
				}

				// parse ordinal from first token on line, if bad parse, then done
				String ordinalStr = inString.substring(0, ordinalColumnEndIndex).trim();
				int ordinal;
				try {
					ordinal = Integer.parseInt(ordinalStr);
				}
				catch (NumberFormatException exc) {
					// done parsing
					break;
				}

				String nameStr = inString.substring(nameColumnStartIndex).trim();
				if (nameStr.length() == 0) {
					break; // unexpected
				}

				// if [NONAME] present strip-off and use next field as name (i.e., mangled name)
				if (nameStr.startsWith("[NONAME]")) {
					nameStr = nameStr.substring(8).trim();
				}

				int index = nameStr.indexOf(' ');
				if (index > 0) {
					nameStr = nameStr.substring(0, index);
				}

				if (nameStr.length() == 0) {
					continue; // skip if no name
				}

				LibraryExportedSymbol sym = ordMap.get(Integer.valueOf(ordinal));
				if (sym != null) {
					symMap.remove(sym.getName());
					sym.setName(nameStr);
				}
				else if (addMissingOrdinals) {
					sym = new LibraryExportedSymbol(tableName, size, ordinal, nameStr, null, null,
						tempPurge, false, null);
					symMap.put(nameStr, sym);
					ordMap.put(ordinal, sym);
				}
			}
		}
		catch (FileNotFoundException e) {
			return;
		}
		catch (IOException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	private String stripComment(String str) {
		int index = str.indexOf(';');
		return index < 0 ? str : str.substring(0, index);
	}

	List<String> getForwards() {
		return new ArrayList<>(forwards);
	}

	/**
	 * Returns the symbol for the specified ordinal.
	 * 
	 * @param ordinal the ordinal value of the desired symbol
	 * @return the symbol for the specified ordinal, or null if one does not
	 *         exist.
	 */
	LibraryExportedSymbol getSymbol(int ordinal) {
		return ordMap.get(ordinal);
	}

	/**
	 * Returns the symbol for the specified name
	 * 
	 * @param symbol the name of the desired symbol
	 * @return symbol map entry or null if not found
	 */
	LibraryExportedSymbol getSymbol(String symbol) {
		return symMap.get(symbol);
	}

	/**
	 * Returns a string describing the version of this library. For example,
	 * "5.100.2566".
	 * 
	 * @return a string describing the version of this library
	 */
	String getVersion() {
		return version;
	}

	String getPath() {
		return path;
	}

	String getDate() {
		return date;
	}

	private void read(ResourceFile file, int size) throws IOException {
		this.size = size;
		symMap = new HashMap<>();
		exportList = new ArrayList<>();

		InputStream is = file.getInputStream();
		SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);

		try {
			Document doc = sax.build(is);

			Element root = doc.getRootElement();
			tableName = root.getAttributeValue("NAME");
			if (tableName == null) {
				throw new IOException("Missing NAME attribute: " + file);
			}
			tableName = tableName.toLowerCase();

			path = root.getAttributeValue("PATH");
			date = root.getAttributeValue("DATE");
			version = root.getAttributeValue("VERSION");

			List<Element> children = CollectionUtils.asList(root.getChildren(), Element.class);
			Iterator<Element> iter = children.iterator();
			while (iter.hasNext()) {
				Element export = iter.next();
				int ordinal = Integer.parseInt(export.getAttributeValue("ORDINAL"));
				String name = export.getAttributeValue("NAME");
				int purge = Integer.parseInt(export.getAttributeValue("PURGE"));
				String comment = export.getAttributeValue("COMMENT");
				String fowardLibName = export.getAttributeValue("FOWARDLIBRARY");
				String fowardSymName = export.getAttributeValue("FOWARDSYMBOL");

				String noReturnStr = export.getAttributeValue("NO_RETURN");
				boolean noReturn = noReturnStr != null && "y".equals(noReturnStr);

				if (fowardLibName != null && fowardLibName.length() > 0 &&
					!fowardLibName.equals(tableName)) {
					forwards.add(fowardLibName);
				}

				LibraryExportedSymbol sym = new LibraryExportedSymbol(tableName, size, ordinal,
					name, fowardLibName, fowardSymName, purge, noReturn, comment);

				exportList.add(sym);
				symMap.put(name, sym);
				ordMap.put(new Integer(ordinal), sym);
			}
		}
		catch (JDOMException e) {
			throw new IOException(e);
		}

		is.close();

		//// read in the formatted data
		//FileReader fr = new FileReader(file);
		//BufferedReader br = new BufferedReader(fr);
		//
		//try{
		//    Pattern p = Pattern.compile("(.*)\\t(.*)\\t(.*)\\t(.*)$");
		//
		//    String inline;
		//    while ((inline = br.readLine()) != null) {
		//        Matcher m = p.matcher(inline);
		//        if (m.matches()) {
		//            int ord = Integer.parseInt(m.group(1));
		//            String funcName = m.group(2);
		//            int purge = Integer.parseInt(m.group(3));
		//            String comment = m.group(4);
		//
		//            LibraryExportedSymbol sym = new LibraryExportedSymbol(tableName, ord, funcName, purge, comment);
		//            exportList.add(sym);
		//            symMap.put(funcName, sym);
		//            ordMap.put(new Integer(ord), sym);
		//        }
		//    }
		//}
		//finally {
		//    fr.close();
		//}
	}

	void write(File output, File input, String lversion) throws IOException {
		Element root = new Element("LIBRARY");

		root.setAttribute("NAME", tableName);
		root.setAttribute("PATH", input.getAbsolutePath());
		long lastModifiedSeconds = (input.lastModified() / 1000) * 1000; // file time in seconds
		root.setAttribute("DATE", TIMESTAMP_FORMAT.format(new Date(lastModifiedSeconds)));
		root.setAttribute("VERSION", lversion);

		Iterator<LibraryExportedSymbol> iter = exportList.iterator();
		while (iter.hasNext()) {
			LibraryExportedSymbol sym = iter.next();

			Element export = new Element("EXPORT");

			export.setAttribute("ORDINAL", sym.getOrdinal() + "");
			export.setAttribute("NAME", sym.getName() == null ? "" : sym.getName());
			export.setAttribute("PURGE", sym.getPurge() + "");
			export.setAttribute("COMMENT", sym.getComment() == null ? "" : sym.getComment());

			if (sym.hasNoReturn()) {
				export.setAttribute("NO_RETURN", "y");
			}

			if (sym.isFowardEntry()) {
				export.setAttribute("FOWARDLIBRARY",
					sym.getFowardLibraryName() == null ? "" : sym.getFowardLibraryName());
				export.setAttribute("FOWARDSYMBOL",
					sym.getFowardSymbolName() == null ? "" : sym.getFowardSymbolName());
			}
			root.addContent(export);
		}

		FileOutputStream fos = new FileOutputStream(output);
		try {
			Document doc = new Document(root);

			XMLOutputter xmlout = new GenericXMLOutputter();
			xmlout.output(doc, fos);
		}
		finally {
			fos.close();
		}

		//StringBuffer buffer = new StringBuffer();
		//Iterator iter = exportList.iterator();
		//while (iter.hasNext()) {
		//    LibraryExportedSymbol sym = (LibraryExportedSymbol) iter.next();
		//
		//    buffer.append(sym.getOrdinal());
		//    buffer.append("\t");
		//    buffer.append(sym.getName());
		//    buffer.append("\t");
		//    buffer.append(sym.getPurge());
		//    buffer.append("\t");
		//    buffer.append(sym.getComment());
		//    buffer.append("\n");
		//}
		//PrintWriter writer = new PrintWriter(new FileOutputStream(file));
		//try {
		//    writer.println(buffer.toString());
		//}
		//finally {
		//    writer.flush();
		//    writer.close();
		//}
	}

	void setVersion(String version) {
		this.version = version;
	}

	/**
	 * Check an existing exports file to verify that it corresponds to the
	 * specified libraryFile.
	 * 
	 * @param exportsFile existing exports file
	 * @param libraryFile library file
	 * @return true if exports file corresponds to library file
	 * @throws ParseException if timestamp fails to parse
	 * @throws SAXException if exports file has XML failure
	 * @throws IOException if unable to read exports file
	 */
	static boolean hasFileAndPathAndTimeStampMatch(ResourceFile exportsFile, File libraryFile)
			throws ParseException, SAXException, IOException {
		if (exportsFile == null || !exportsFile.exists()) {
			return false;
		}
		// TODO: should consider checking version instead of last modified
		XmlPullParser parser = XmlPullParserFactory.create(exportsFile, ERROR_HANDLER, false);
		try {
			XmlElement start = parser.start("LIBRARY");
			String path = start.getAttribute("PATH");
			String dateString = start.getAttribute("DATE");
			Date date = TIMESTAMP_FORMAT.parse(dateString);
			long lastModifiedSeconds = (libraryFile.lastModified() / 1000) * 1000; // file time in seconds
			return date.equals(new Date(lastModifiedSeconds)) &&
				path.equalsIgnoreCase(libraryFile.getAbsolutePath());
		}
		finally {
			parser.dispose();
		}
	}

	private static final ErrorHandler ERROR_HANDLER = new ErrorHandler() {
		@Override
		public void error(SAXParseException exception) throws SAXException {
			Msg.warn(LibraryLookupTable.class, "error", exception);
		}

		@Override
		public void fatalError(SAXParseException exception) throws SAXException {
			Msg.warn(LibraryLookupTable.class, "fatal error", exception);
		}

		@Override
		public void warning(SAXParseException exception) throws SAXException {
			Msg.warn(LibraryLookupTable.class, "warning", exception);
		}
	};
}
