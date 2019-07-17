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
import java.text.SimpleDateFormat;
import java.util.Date;

import org.xml.sax.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.database.module.TreeManager;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlAttributes;
import ghidra.util.xml.XmlWriter;
import ghidra.xml.*;

/**
 * The manager responsible for reading and writing a program in XML.
 */
public class ProgramXmlMgr {

	private static final String PROGRAM_DTD = "program_dtd";

	private int dtdVersion;
	private ProgramInfo info;
	private File file;

	/**
	 * Constructs a new program XML manager using the specified file.
	 * The file should be an XML file.
	 * @param file the XML file
	 */
	public ProgramXmlMgr(File file) {
		this.file = file;

	}

	/**
	 * Constructs a new program XML manager using the specified {@link ByteProvider}.
	 * <p>
	 * If {@link ByteProvider} has a {@link FSRL} and it is a simple local filepath,
	 * convert that to a normal local java.io.File instance instead of using the
	 * {@link ByteProvider}'s File property which is probably located in the
	 * {@link FileSystemService} filecache directory, which will break the ability
	 * to find the *.bytes file associated with this .xml file.
	 * <p>
	 * This workaround will not help xml files that are truly embedded in a GFileSystem
	 * (ie. in a .zip file).
	 *
	 * @param bp
	 */
	public ProgramXmlMgr(ByteProvider bp) {
		this.file = (bp.getFSRL() != null && bp.getFSRL().getNestingDepth() == 1)
				? new File(bp.getFSRL().getPath())
				: bp.getFile();
	}

	/**
	 * Returns the program info from the underlying file. T``his method
	 * does not make sense to invoke if a write is being performed
	 * to a new file.
	 * @return the program info
	 * @throws SAXException if an XML error occurs
	 * @throws IOException if an I/O error occurs
	 */
	public ProgramInfo getProgramInfo() throws SAXException, IOException {
		if (info != null) {
			return info;
		}

		info = new ProgramInfo();

		XmlPullParser parser =
			XmlPullParserFactory.create(file, new MyErrorHandler(new MessageLog()), false);

		boolean isFileValid = false;

		String ver = parser.getProcessingInstruction(PROGRAM_DTD, "VERSION");
		if (ver != null) {
			try {
				dtdVersion = Integer.parseInt(ver);
			}
			catch (NumberFormatException e) {
				Msg.debug(this, "Unable to parse DTD: " + ver);
			}
		}

		while (parser.hasNext()) {
			XmlElement element = parser.next();
			String name = element.getName();
			if (name.equals("PROGRAM") && element.isStart()) {
				isFileValid = true;

				info.programName = element.getAttribute("NAME");
				info.exePath = element.getAttribute("EXE_PATH");
				info.exeFormat = element.getAttribute("EXE_FORMAT");
				info.imageBase = element.getAttribute("IMAGE_BASE");
			}
			else if (name.equals("INFO_SOURCE") && element.isStart()) {
				info.user = element.getAttribute("USER");
				info.setTool(element.getAttribute("TOOL"));
				info.timestamp = element.getAttribute("TIMESTAMP");
				info.version = element.getAttribute("VERSION");

				if (isOldXml() && info.isGhidra()) {
					info.programName = element.getAttribute("FILE");
				}
			}
			else if (name.equals("PROCESSOR") && element.isStart()) {
				String languageString = element.getAttribute("LANGUAGE_PROVIDER");
				LanguageCompilerSpecPair pair =
					OldLanguageMappingService.processXmlLanguageString(languageString);
				if (pair != null) {
					info.languageID = pair.languageID;
					info.compilerSpecID = pair.compilerSpecID;
				}
				else {
					info.setCompilerSpecID(getForCompilerTag(parser));
				}
				info.processorName = element.getAttribute("NAME");
				info.family = element.getAttribute("FAMILY");
				info.addressModel = element.getAttribute("ADDRESS_MODEL");
				info.endian = element.getAttribute("ENDIAN");

				break;
			}
		}

		parser.dispose();

		if (!isFileValid) {
			info = null;
		}

		return info;
	}

	private String getForCompilerTag(XmlPullParser parser) {
		String returnValue = null;
		while (parser.hasNext()) {
			XmlElement element = parser.next();
			String name = element.getName();
			if (name.equals("COMPILER") && element.isStart()) {
				returnValue = element.getAttribute("NAME");
				break;
			}
		}
		return returnValue;
	}

	/**
	 * Reads from the underlying XML file and populates the specified program.
	 * @param program the program to load the XML into
	 * @param monitor the task monitor
	 * @param options the XML options, which features to load and to ignore
	 * @return the message log containing any warning/error messages
	 * @throws SAXException if an XML error occurs
	 * @throws IOException if an I/O occurs
	 * @throws AddressFormatException if an invalid address is specified in the XML
	 */
	public MessageLog read(Program program, TaskMonitor monitor, XmlProgramOptions options)
			throws SAXException, IOException, AddressFormatException {

		if (getProgramInfo() == null) {
			throw new SAXException("Unsupported XML Format!");
		}

		if (!options.isAddToProgram()) {
			Memory memory = program.getMemory();
			MemoryBlock[] blocks = memory.getBlocks();
			for (MemoryBlock block : blocks) {
				try {
					memory.removeBlock(block, monitor);
				}
				catch (LockException e) {
					throw new RuntimeException(e);//should never happen...
				}
			}
			Listing listing = program.getListing();
			String[] treeNames = listing.getTreeNames();
			for (String treeName : treeNames) {
				listing.removeTree(treeName);
			}
		}

		//check to see if this happens to be a file
		//that was created with a bleeding-edge build
		//of 2.1 before it's official release.

		if (isOldXml()) {
			MessageLog log = new MessageLog();
			log.appendMsg("File is old 2.0 XML which is no longer supported!");
			return log;
		}

		XmlMessageLog log = new XmlMessageLog();
		MyErrorHandler errHandler = new MyErrorHandler(log);
		XmlPullParser parser = XmlPullParserFactory.create(file, errHandler, false);
		log.setParser(parser);

		if (!options.isAddToProgram()) {
			program.setExecutableFormat(getStandardName(info.exeFormat));
			program.setExecutablePath(info.exePath);

			try {
				SimpleDateFormat format = new SimpleDateFormat("EEE MMM dd HH:mm:ss ZZZ yyyy");
				Date creationDate = format.parse(info.timestamp);
				Options pl = program.getOptions(Program.PROGRAM_INFO);
				pl.setDate(Program.DATE_CREATED, creationDate);
			}
			catch (Exception e) {
				Options pl = program.getOptions(Program.PROGRAM_INFO);
				pl.setDate(Program.DATE_CREATED, Program.JANUARY_1_1970);
			}
		}

		boolean secondPassRequired = false;
		final XmlElement programStart = parser.start("PROGRAM");
		try {
			while (parser.hasNext() && parser.peek().isStart() && !monitor.isCancelled()) {
				XmlElement element = parser.peek();
				String name = element.getName();

				if (options.isData() && name.equals("DATATYPES")) {
					monitor.setMessage("Processing DATA TYPES ...");
					DataTypesXmlMgr mgr =
						new DataTypesXmlMgr(program.getListing().getDataTypeManager(), log);
					mgr.read(parser, monitor);
				}
				else if (options.isMemoryBlocks() && name.equals("MEMORY_MAP")) {
					monitor.setMessage("Processing MEMORY MAP ...");
					MemoryMapXmlMgr mgr = new MemoryMapXmlMgr(program, log);
					mgr.read(parser, options.isOverwriteMemoryConflicts(), monitor,
						file.getParent());
				}
				else if (options.isRegisters() && name.equals("REGISTER_VALUES")) {
					monitor.setMessage("Processing REGISTER VALUES ...");
					RegisterValuesXmlMgr mgr = new RegisterValuesXmlMgr(program, log);
					mgr.read(parser, monitor);
				}
				else if (options.isInstructions() && name.equals("CODE")) {
					monitor.setMessage("Processing CODE ...");
					CodeXmlMgr mgr = new CodeXmlMgr(program, log);
					mgr.read(parser, monitor);
				}
				else if (options.isData() && name.equals("DATA")) {
					monitor.setMessage("Processing DATA ...");
					DefinedDataXmlMgr mgr = new DefinedDataXmlMgr(program, log);
					mgr.read(parser, options.isOverwriteDataConflicts(), monitor);
				}
				else if (options.isEquates() && name.equals("EQUATES")) {
					monitor.setMessage("Processing EQUATES ...");
					EquatesXmlMgr mgr = new EquatesXmlMgr(program, log);
					mgr.read(parser, monitor);
				}
				else if (options.isComments() && name.equals("COMMENTS")) {
					monitor.setMessage("Processing COMMENTS ...");
					CommentsXmlMgr mgr = new CommentsXmlMgr(program, log);
					mgr.read(parser, monitor);
				}
				else if (options.isProperties() && name.equals("PROPERTIES")) {
					monitor.setMessage("Processing PROPERTIES ...");
					PropertiesXmlMgr mgr = new PropertiesXmlMgr(program, log);
					mgr.read(parser, options.isOverwritePropertyConflicts(), monitor);
				}
				else if (options.isBookmarks() && name.equals("BOOKMARKS")) {
					monitor.setMessage("Processing BOOKMARKS ...");
					BookmarksXmlMgr mgr = new BookmarksXmlMgr(program, log);
					mgr.read(parser, options.isOverwriteBookmarkConflicts(), monitor);
				}
				else if (options.isTrees() && name.equals("PROGRAM_TREES")) {
					monitor.setMessage("Processing PROGRAM TREES ...");
					ProgramTreeXmlMgr mgr = new ProgramTreeXmlMgr(program, log);
					mgr.read(parser, monitor, options.isAddToProgram());
				}
				else if (options.isEntryPoints() && name.equals("PROGRAM_ENTRY_POINTS")) {
					monitor.setMessage("Processing PROGRAM ENTRY POINTS ...");
					ExtEntryPointXmlMgr mgr = new ExtEntryPointXmlMgr(program, log);
					mgr.read(parser, monitor);
				}
				else if (options.isRelocationTable() && name.equals("RELOCATION_TABLE")) {
					monitor.setMessage("Processing RELOCATION TABLE ...");
					RelocationTableXmlMgr mgr = new RelocationTableXmlMgr(program, log);
					mgr.read(parser, monitor);
				}
				else if (options.isSymbols() && name.equals("SYMBOL_TABLE")) {
					monitor.setMessage("Processing SYMBOL TABLE ...");
					SymbolTableXmlMgr mgr = new SymbolTableXmlMgr(program, log);
					mgr.read(parser, options.isOverwriteSymbolConflicts(), monitor);
					secondPassRequired = mgr.isSecondPassRequired();
				}
				else if (options.isFunctions() && name.equals("FUNCTIONS")) {
					monitor.setMessage("Processing FUNCTIONS ...");
					FunctionsXmlMgr mgr = new FunctionsXmlMgr(program, log);
					mgr.read(parser,
						!options.isAddToProgram() || options.isOverwriteSymbolConflicts(), false,
						monitor);
				}
				else if (options.isReferences() && name.equals("MARKUP")) {
					monitor.setMessage("Processing MARKUP ...");
					MarkupXmlMgr mgr = new MarkupXmlMgr(program, log);
					mgr.read(parser, options.isOverwriteReferenceConflicts(),
						options.isExternalLibraries(), options.isFunctions(),
						info.shouldProcessStack(), monitor);
				}
				else if (options.isExternalLibraries() && name.equals("EXT_LIBRARY_TABLE")) {
					monitor.setMessage("Processing EXT LIBRARY TABLE ...");
					ExternalLibXmlMgr mgr = new ExternalLibXmlMgr(program, log);
					mgr.read(parser, monitor);
				}
				else {
					monitor.setMessage("Skipping over " + name + " ...");
					parser.discardSubTree(name);
				}
			}
			parser.end(programStart);
		}
		catch (CancelledException e) {
			throw new IOException("XML Read Cancelled");
		}
		finally {
			parser.dispose();
		}

		if (secondPassRequired) {
			parser = XmlPullParserFactory.create(file, errHandler, false);
			log.setParser(parser);
			try {
				while (parser.hasNext() && !monitor.isCancelled()) {
					XmlElement element = parser.peek();
					String name = element.getName();
					if (name.equals("PROGRAM")) {
						parser.next();
					}
					else if (options.isSymbols() && name.equals("SYMBOL_TABLE")) {
						monitor.setMessage("Re-processing SYMBOL TABLE ...");
						SymbolTableXmlMgr mgr = new SymbolTableXmlMgr(program, log);
						mgr.readPass2(parser, options.isOverwriteSymbolConflicts(), monitor);
					}
					else {
						monitor.setMessage("Skipping over " + name + " ...");
						parser.discardSubTree(name);
					}
				}
			}
			catch (CancelledException e) {
				throw new IOException("XML Read Cancelled");
			}
			finally {
				parser.dispose();
			}
		}

		createDefaultTree(program, options);

		//if instructions were imported, then remove the "needs analyzed" property
		if (options.isInstructions()) {
			GhidraProgramUtilities.setAnalyzedFlag(program, true);
		}

		return log;
	}

	/**
	 * Converts from a generic format name to standard Ghidra names;
	 *
	 * @param name
	 *            the generic format name
	 * @return the equivalent Ghidra name
	 */
	public static String getStandardName(String name) {
		if (name == null) {
			return "Unknown";
		}
		else if (name.toLowerCase().indexOf("portable executable") >= 0 &&
			name.toLowerCase().indexOf("(pe)") >= 0) {
			return PeLoader.PE_NAME;
		}
		else if (name.toLowerCase().indexOf("(elf)") != -1) {
			return ElfLoader.ELF_NAME;
		}
		else if (name.toLowerCase().indexOf("dos executable") >= 0) {
			return MzLoader.MZ_NAME;
		}
		else if (name.toLowerCase().indexOf("new executable") >= 0) {
			return NeLoader.NE_NAME;
		}
		return name;
	}

	private boolean isOldXml() {
		return dtdVersion < 1 && !"2.1 Dev".equals(info.version);
	}

	private void createDefaultTree(Program program, XmlProgramOptions options) {

		if (options.isAddToProgram()) {
			return;
		}

		Listing listing = program.getListing();
		if (listing.getTreeNames().length == 0) {
			try {
				listing.createRootModule(TreeManager.DEFAULT_TREE_NAME);
			}
			catch (DuplicateNameException e) {
				// shouldn't happen since we checked the tree names above
				Msg.debug(this, "Unable to create default module", e);
			}
		}

	}

	/**
	 * Writes the specified program in XML into the underlying file.
	 * @param program the program to write into XML
	 * @param addrSet an address set to limit areas of program that written, or null for entire program
	 * @param monitor the task monitor
	 * @param options the XML options to limit what is and is not written out
	 * @return the message log containing any warning/error messages
	 * @throws IOException if an I/O occurs
	 * @throws CancelledException if the user cancels the read
	 */
	public MessageLog write(Program program, AddressSetView addrSet, TaskMonitor monitor,
			XmlProgramOptions options) throws IOException, CancelledException {

		MessageLog log = new MessageLog();

		XmlWriter writer = new XmlWriter(file, "PROGRAM.DTD");

		try {
			XmlAttributes attrs = new XmlAttributes();
			attrs.addAttribute("NAME", program.getDomainFile().getName());
			attrs.addAttribute("EXE_PATH", program.getExecutablePath());
			attrs.addAttribute("EXE_FORMAT", program.getExecutableFormat());
			attrs.addAttribute("IMAGE_BASE", program.getImageBase().toString());

			writer.startElement("PROGRAM", attrs);
			writeProgramElements(program, addrSet, writer, monitor, log, options);
			writer.endElement("PROGRAM");
		}
		finally {
			writer.close();
		}

		return log;
	}

	private void writeProgramElements(Program program, AddressSetView addrSet, XmlWriter writer,
			TaskMonitor monitor, MessageLog log, XmlProgramOptions options)
			throws IOException, CancelledException {

		//description
		writeInfoSource(writer, monitor);
		writeProcessor(program, writer, monitor);
		//compiler
		if (options.isData()) {
			DataTypesXmlMgr mgr =
				new DataTypesXmlMgr(program.getListing().getDataTypeManager(), log);
			mgr.write(writer, monitor);
		}
		if (options.isMemoryBlocks()) {
			MemoryMapXmlMgr mgr = new MemoryMapXmlMgr(program, log);
			mgr.write(writer, addrSet, monitor, options.isMemoryContents(), file);
		}
		if (options.isRegisters()) {
			RegisterValuesXmlMgr mgr = new RegisterValuesXmlMgr(program, log);
			mgr.write(writer, addrSet, monitor);
		}
		if (options.isInstructions()) {
			CodeXmlMgr mgr = new CodeXmlMgr(program, log);
			mgr.write(writer, addrSet, monitor);
		}
		if (options.isData()) {
			DefinedDataXmlMgr mgr = new DefinedDataXmlMgr(program, log);
			mgr.write(writer, addrSet, monitor);
		}
		if (options.isEquates()) {
			EquatesXmlMgr mgr = new EquatesXmlMgr(program, log);
			mgr.write(writer, addrSet, monitor);
		}
		if (options.isComments()) {
			CommentsXmlMgr mgr = new CommentsXmlMgr(program, log);
			mgr.write(writer, addrSet, monitor);
		}
		if (options.isProperties()) {
			PropertiesXmlMgr mgr = new PropertiesXmlMgr(program, log);
			mgr.write(writer, addrSet, monitor);
		}
		if (options.isBookmarks()) {
			BookmarksXmlMgr mgr = new BookmarksXmlMgr(program, log);
			mgr.write(writer, addrSet, monitor);
		}
		if (options.isTrees()) {
			ProgramTreeXmlMgr mgr = new ProgramTreeXmlMgr(program, log);
			mgr.write(writer, addrSet, monitor);
		}
		if (options.isEntryPoints()) {
			ExtEntryPointXmlMgr mgr = new ExtEntryPointXmlMgr(program, log);
			mgr.write(writer, addrSet, monitor);
		}
		if (options.isRelocationTable()) {
			RelocationTableXmlMgr mgr = new RelocationTableXmlMgr(program, log);
			mgr.write(writer, monitor);
		}
		if (options.isSymbols()) {
			SymbolTableXmlMgr mgr = new SymbolTableXmlMgr(program, log);
			mgr.write(writer, addrSet, monitor);
		}
		if (options.isFunctions()) {
			FunctionsXmlMgr mgr = new FunctionsXmlMgr(program, log);
			mgr.write(writer, addrSet, monitor);
		}
		if (options.isReferences()) {
			MarkupXmlMgr mgr = new MarkupXmlMgr(program, log);
			mgr.write(writer, addrSet, monitor);
		}
		if (options.isExternalLibraries()) {
			ExternalLibXmlMgr mgr = new ExternalLibXmlMgr(program, log);
			mgr.write(writer, monitor);
		}
	}

	private void writeInfoSource(XmlWriter writer, TaskMonitor monitor) {
		monitor.setMessage("Writing INFO SOURCE ...");

		XmlAttributes attrs = new XmlAttributes();
		String user = SystemUtilities.getUserName();
		if (user != null) {
			attrs.addAttribute("USER", user);
		}
		attrs.addAttribute("TOOL", "Ghidra " + Application.getApplicationVersion());
		attrs.addAttribute("TIMESTAMP", new Date().toString());

		writer.startElement("INFO_SOURCE", attrs);
		writer.endElement("INFO_SOURCE");
	}

	private void writeProcessor(Program program, XmlWriter writer, TaskMonitor monitor) {
		monitor.setMessage("Writing PROCESSOR ...");

		XmlAttributes attrs = new XmlAttributes();
		Language language = program.getLanguage();
		CompilerSpec compilerSpec = program.getCompilerSpec();

		attrs.addAttribute("NAME", language.getProcessor().toString());
		attrs.addAttribute("LANGUAGE_PROVIDER", language.getLanguageID().getIdAsString() + ":" +
			compilerSpec.getCompilerSpecID().getIdAsString());
		attrs.addAttribute("ENDIAN", language.isBigEndian() ? "big" : "little");

		writer.startElement("PROCESSOR", attrs);
		writer.endElement("PROCESSOR");
	}
}

class MyErrorHandler implements ErrorHandler {
	private MessageLog log;

	MyErrorHandler(MessageLog log) {
		this.log = log;
	}

	/**
	 * @see org.xml.sax.ErrorHandler#error(org.xml.sax.SAXParseException)
	 */
	@Override
	public void error(SAXParseException exception) throws SAXException {
		log.appendMsg(exception.getMessage());
	}

	/**
	 * @see org.xml.sax.ErrorHandler#fatalError(org.xml.sax.SAXParseException)
	 */
	@Override
	public void fatalError(SAXParseException exception) throws SAXException {
		log.appendMsg(exception.getMessage());
	}

	/**
	 * @see org.xml.sax.ErrorHandler#warning(org.xml.sax.SAXParseException)
	 */
	@Override
	public void warning(SAXParseException exception) throws SAXException {
		log.appendMsg(exception.getMessage());
	}
}
