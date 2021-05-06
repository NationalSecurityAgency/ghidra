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
package ghidra.app.plugin.processors.sleigh;

import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.antlr.runtime.RecognitionException;
import org.jdom.JDOMException;
import org.xml.sax.*;

import generic.jar.ResourceFile;
import generic.stl.Pair;
import ghidra.app.plugin.processors.generic.MemoryBlockDefinition;
import ghidra.app.plugin.processors.sleigh.expression.ContextField;
import ghidra.app.plugin.processors.sleigh.expression.PatternValue;
import ghidra.app.plugin.processors.sleigh.symbol.*;
import ghidra.framework.Application;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.slgh_compile.SleighCompileLauncher;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.DefaultProgramContext;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.AddressLabelInfo;
import ghidra.program.model.util.ProcessorSymbolType;
import ghidra.sleigh.grammar.SleighPreprocessor;
import ghidra.sleigh.grammar.SourceFileIndexer;
import ghidra.util.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;
import utilities.util.FileResolutionResult;
import utilities.util.FileUtilities;

public class SleighLanguage implements Language {

	/**
	 * SLA_FORMAT_VERSION will be incremented whenever the format of the .sla
	 * files change.
	 * <p>
	 * Version 3: January 2021: added source file information for each constructor. <br>
	 * Version 2: April 2019: Changed numbering of Overlay spaces.<br>
	 * Version 1: Initial version.<br>
	 */
	public static final int SLA_FORMAT_VERSION = SleighBase.SLA_FORMAT_VERSION;
	private Map<CompilerSpecID, SleighCompilerSpecDescription> compilerSpecDescriptions;
	private HashMap<CompilerSpecID, BasicCompilerSpec> compilerSpecs;
	private List<InjectPayloadSleigh> additionalInject = null;
	private AddressFactory addressFactory;
	private AddressSpace defaultDataSpace;
	private RegisterBuilder registerBuilder;
	private MemoryBlockDefinition[] defaultMemoryBlocks;
	private Register programCounter;
	private List<AddressLabelInfo> defaultSymbols;
	private long uniqueBase;				// First free offset within the unique space
	private int uniqueAllocateMask = 0;			// Number of bytes between allocations within the unique space
	private int numSections = 0;					// Number of named sections for this language
	private int alignment = 1;
	private int defaultPointerWordSize = 1;		// Default wordsize to send down with pointer data-types
	private SleighLanguageDescription description;
	private ParallelInstructionLanguageHelper parallelHelper;
	private SourceFileIndexer indexer;  //used to provide source file info for constructors

	/**
	 * Symbols used by sleigh
	 */
	private SymbolTable symtab = null;
	/**
	 * Non-null if a space should yes segmented addressing
	 */
	String segmentedspace = "";
	String segmentType = "";
	AddressSet volatileAddresses;
	private ContextCache contextcache = null;
	/**
	 * Cached instruction prototypes
	 */
	private LinkedHashMap<Integer, SleighInstructionPrototype> instructProtoMap;
	private DecisionNode root = null;
	/**
	 * table of AddressSpaces
	 */
	LinkedHashMap<String, AddressSpace> spacetable;
	private AddressSpace default_space;
	private List<ContextSetting> ctxsetting = new ArrayList<>();
	private LinkedHashMap<String, String> properties = new LinkedHashMap<>();
	SortedMap<String, ManualEntry> manual = null;

	SleighLanguage(SleighLanguageDescription description)
			throws SAXException, IOException, UnknownInstructionException {
		initialize(description);
	}

	private void addAdditionInject(InjectPayloadSleigh payload) {
		if (additionalInject == null) {
			additionalInject = new ArrayList<>();
		}
		additionalInject.add(payload);
	}

	private void initialize(SleighLanguageDescription langDescription)
			throws SAXException, IOException, UnknownInstructionException {
		this.defaultSymbols = new ArrayList<>();
		this.compilerSpecDescriptions = new LinkedHashMap<>();
		for (CompilerSpecDescription compilerSpecDescription : langDescription
				.getCompatibleCompilerSpecDescriptions()) {
			this.compilerSpecDescriptions.put(compilerSpecDescription.getCompilerSpecID(),
				(SleighCompilerSpecDescription) compilerSpecDescription);
		}
		compilerSpecs = new HashMap<>();
		this.description = langDescription;
		additionalInject = null;

		SleighLanguageValidator.validatePspecFile(langDescription.getSpecFile());

		readInitialDescription();
		// should addressFactory and registers initialization be done at
		// construction time?
		// for now we'll assume yes.
		contextcache = new ContextCache();

		ResourceFile slaFile = langDescription.getSlaFile();
		if (!slaFile.exists() ||
			(slaFile.canWrite() && (isSLAWrongVersion(slaFile) || isSLAStale(slaFile)))) {
			reloadLanguage(TaskMonitor.DUMMY, true);
		}

		// Read in the sleigh specification
		readSpecification(slaFile);

		registerBuilder = new RegisterBuilder();
		loadRegisters(registerBuilder);
		readRemainingSpecification();

		xrefRegisters();

		instructProtoMap = new LinkedHashMap<>();

		initParallelHelper();
	}

	private boolean isSLAWrongVersion(ResourceFile slaFile) {
		XmlPullParser parser = null;
		try {
			parser = XmlPullParserFactory.create(slaFile, new ErrorHandler() {

				@Override
				public void warning(SAXParseException exception) throws SAXException {
					// ignore
				}

				@Override
				public void fatalError(SAXParseException exception) throws SAXException {
					throw exception;
				}

				@Override
				public void error(SAXParseException exception) throws SAXException {
					throw exception;
				}
			}, false);

			XmlElement e = parser.peek();
			if (!"sleigh".equals(e.getName())) {
				return true;
			}

			int version = SpecXmlUtils.decodeInt(e.getAttribute("version"));
			return (version != SLA_FORMAT_VERSION);
		}
		catch (SAXException | IOException e) {
			return true;
		}
		finally {
			if (parser != null) {
				parser.dispose();
			}
		}
	}

	private boolean isSLAStale(ResourceFile slaFile) {
		String slafilename = slaFile.getName();
		int index = slafilename.lastIndexOf('.');
		String slabase = slafilename.substring(0, index);
		String slaspecfilename = slabase + ".slaspec";
		ResourceFile slaspecFile = new ResourceFile(slaFile.getParentFile(), slaspecfilename);

		File resourceAsFile = slaspecFile.getFile(true);
		SleighPreprocessor preprocessor =
			new SleighPreprocessor(new ModuleDefinitionsAdapter(), resourceAsFile);
		long sourceTimestamp = Long.MAX_VALUE;
		try {
			sourceTimestamp = preprocessor.scanForTimestamp();
		}
		catch (Exception e) {
			// squash the error because we will force recompilation and errors
			// will propagate elsewhere
		}
		long compiledTimestamp = slaFile.lastModified();
		return (sourceTimestamp > compiledTimestamp);
	}

	/**
	 * Returns the unique base offset from which additional temporary variables
	 * may be created.
	 * @return unique base offset
	 */
	public long getUniqueBase() {
		return uniqueBase;
	}

	public int getUniqueAllocationMask() {
		return uniqueAllocateMask;
	}

	/**
	 * @return (maximum) number of named p-code sections
	 */
	public int numSections() {
		return numSections;
	}

	@Override
	public String toString() {
		return description.toString();
	}

	private RegisterManager registerManager = null;

	private RegisterManager getRegisterManager() {
		if (registerManager == null) {
			registerManager = registerBuilder.getRegisterManager();
		}
		return registerManager;
	}

	@Override
	public void applyContextSettings(DefaultProgramContext programContext) {
		for (ContextSetting cs : ctxsetting) {
			RegisterValue registerValue = new RegisterValue(cs.getRegister(), cs.getValue());
			programContext.setDefaultValue(registerValue, cs.getStartAddress(), cs.getEndAddress());
		}
	}

	@Override
	public AddressFactory getAddressFactory() {
		return addressFactory;
	}

	public List<InjectPayloadSleigh> getAdditionalInject() {
		return additionalInject;
	}

	@Override
	public Register getContextBaseRegister() {
		return getRegisterManager().getContextBaseRegister();
	}

	@Override
	public List<Register> getContextRegisters() {
		return getRegisterManager().getContextRegisters();
	}

	@Override
	public MemoryBlockDefinition[] getDefaultMemoryBlocks() {
		return defaultMemoryBlocks;
	}

	@Override
	public Register getProgramCounter() {
		return programCounter;
	}

	@Override
	public List<AddressLabelInfo> getDefaultSymbols() {
		return defaultSymbols;
	}

	@Override
	public int getInstructionAlignment() {
		return alignment;
	}

	@Override
	public int getMinorVersion() {
		return description.getMinorVersion();
	}

	@Override
	public LanguageID getLanguageID() {
		return description.getLanguageID();
	}

	@Override
	public String getUserDefinedOpName(int index) {
		return symtab.getUserDefinedOpName(index);
	}

	@Override
	public int getNumberOfUserDefinedOpNames() {
		return symtab.getNumberOfUserDefinedOpNames();
	}

	@Override
	public Processor getProcessor() {
		return description.getProcessor();
	}

	@Override
	public Register getRegister(AddressSpace addrspc, long offset, int size) {
		return getRegister(addrspc.getAddress(offset), size);
	}

	@Override
	public Register getRegister(String name) {
		return getRegisterManager().getRegister(name);
	}

	@Override
	public Register getRegister(Address addr, int size) {
		return getRegisterManager().getRegister(addr, size);
	}

	@Override
	public Register[] getRegisters(Address address) {
		return getRegisterManager().getRegisters(address);
	}

	@Override
	public List<Register> getRegisters() {
		return getRegisterManager().getRegisters();
	}

	@Override
	public List<String> getRegisterNames() {
		return getRegisterManager().getRegisterNames();
	}

	@Override
	public String getSegmentedSpace() {
		return segmentedspace;
	}

	@Override
	public int getVersion() {
		return description.getVersion();
	}

	@Override
	public AddressSetView getVolatileAddresses() {
		return volatileAddresses;
	}

	@Override
	public boolean isBigEndian() {
		return description.getEndian().isBigEndian();
	}

	@Override
	public boolean isVolatile(Address addr) {
		if (volatileAddresses != null) {
			return volatileAddresses.contains(addr);
		}
		return false;
	}

	@Override
	public InstructionPrototype parse(MemBuffer buf, ProcessorContext context, boolean inDelaySlot)
			throws InsufficientBytesException, UnknownInstructionException {
		if (alignment != 1) {
			if (buf.getAddress().getOffset() % alignment != 0) {
				throw new UnknownInstructionException(
					"Instructions must be aligned on " + alignment + "byte boundary.");
			}
		}

		SleighInstructionPrototype res = null;

		try {
			SleighInstructionPrototype newProto =
				new SleighInstructionPrototype(this, buf, context, contextcache, inDelaySlot, null);
			Integer hashcode = newProto.hashCode();

			if (!instructProtoMap.containsKey(hashcode)) {
				newProto.cacheInfo(buf, context, true);
			}

			synchronized (instructProtoMap) {
				res = instructProtoMap.get(hashcode);
				if (res == null) { // We have a prototype we have never seen
					// before, build it fully
					instructProtoMap.put(hashcode, newProto);
					res = newProto;
				}
				if (inDelaySlot && res.hasDelaySlots()) {
					throw new NestedDelaySlotException();
				}
			}
		}
		catch (MemoryAccessException e) {
			throw new InsufficientBytesException(e.getMessage());
		}

		try {
			SleighParserContext protoContext = res.getParserContext(buf, context);
			protoContext.applyCommits(context);
		}
		catch (Exception e) {
			throw new UnknownInstructionException();
		}
		return res;
	}

	public DecisionNode getRootDecisionNode() {
		return root;
	}

	public SymbolTable getSymbolTable() {
		return symtab;
	}

	/**
	 * Returns the source file indexer
	 * @return indexer
	 */
	public SourceFileIndexer getSourceFileIndexer() {
		return indexer;
	}

	@Override
	public void reloadLanguage(TaskMonitor monitor) throws IOException {
		reloadLanguage(monitor, false);
	}

	private void reloadLanguage(TaskMonitor monitor, boolean calledFromInitialize)
			throws IOException {
		if (monitor == null) {
			monitor = TaskMonitor.DUMMY;
		}
		monitor.setMessage("Compiling Language File...");

		ResourceFile slaFile = description.getSlaFile();
		String slaName = slaFile.getName();
		int index = slaName.lastIndexOf('.');
		String specName = slaName.substring(0, index);
		String languageName = specName + ".slaspec";
		ResourceFile languageFile = new ResourceFile(slaFile.getParentFile(), languageName);

		// see gradle/processorUtils.gradle for sleighArgs.txt generation
		ResourceFile sleighArgsFile = null;
		ResourceFile languageModule = Application.getModuleContainingResourceFile(languageFile);
		if (languageModule != null) {
			if (SystemUtilities.isInReleaseMode()) {
				sleighArgsFile = new ResourceFile(languageModule, "data/sleighArgs.txt");
			}
			else {
				sleighArgsFile = new ResourceFile(languageModule, "build/tmp/sleighArgs.txt");
			}
		}

		String[] args;
		if (sleighArgsFile != null && sleighArgsFile.isFile()) {
			String baseDir = Application.getInstallationDirectory()
					.getAbsolutePath()
					.replace(File.separatorChar, '/');
			if (!baseDir.endsWith("/")) {
				baseDir += "/";
			}
			args = new String[] { "-DBaseDir=" + baseDir, "-i", sleighArgsFile.getAbsolutePath(),
				languageFile.getAbsolutePath(), description.getSlaFile().getAbsolutePath() };
		}
		else {
			args = new String[] { languageFile.getAbsolutePath(),
				description.getSlaFile().getAbsolutePath() };
		}

		try {
			StringBuilder buf = new StringBuilder();
			for (String str : args) {
				buf.append(str);
				buf.append(" ");
			}
			Msg.debug(this, "Sleigh compile: " + buf);
			int returnCode = SleighCompileLauncher.runMain(args);
			if (returnCode != 0) {
				throw new SleighException("Errors compiling " + languageFile.getAbsolutePath() +
					" -- please check log messages for details");
			}
		}
		catch (JDOMException e) {
			throw new IOException("JDOMException error recompiling: " + e.getMessage());
		}
		catch (RecognitionException e) {
			throw new IOException("RecognitionException error recompiling: " + e.getMessage());
		}

		if (!calledFromInitialize) {
			monitor.setMessage("Reloading Language...");
			try {
				initialize(description);
			}
			catch (SAXException e) {
				throw new IOException(e.getMessage());
			}
			catch (UnknownInstructionException e) {
				throw new IOException(e.getMessage());
			}
		}
	}

	@Override
	public boolean supportsPcode() {
		return true;
	}

	private ErrorHandler SPEC_ERR_HANDLER = new ErrorHandler() {
		@Override
		public void error(SAXParseException exception) throws SAXException {
			Msg.error(SleighLanguage.this, "Error parsing " + description.getSpecFile(), exception);
		}

		@Override
		public void fatalError(SAXParseException exception) throws SAXException {
			Msg.error(SleighLanguage.this, "Fatal error parsing " + description.getSpecFile(),
				exception);
		}

		@Override
		public void warning(SAXParseException exception) throws SAXException {
			Msg.warn(SleighLanguage.this, "Warning parsing " + description.getSpecFile(),
				exception);
		}
	};

	private void readInitialDescription() throws SAXException, IOException {
		ResourceFile specFile = description.getSpecFile();
		XmlPullParser parser = XmlPullParserFactory.create(specFile, SPEC_ERR_HANDLER, false);
		try {
			XmlElement nextElement = parser.peek();
			while (nextElement != null && !nextElement.getName().equals("segmented_address")) {
				parser.next(); // skip element
				nextElement = parser.peek();
			}
			if (nextElement != null) {
				XmlElement element = parser.start(); // segmented_address element
				segmentedspace = element.getAttribute("space");
				segmentType = element.getAttribute("type");
				if (segmentType == null) {
					segmentType = "";
				}
			}
		}
		finally {
			parser.dispose();
		}
	}

	private void setDefaultDataSpace(String spaceName) {
		if (spaceName == null) {
			return;
		}

		AddressSpace addressSpace = addressFactory.getAddressSpace(spaceName);
		if (addressSpace == null || !addressSpace.isLoadedMemorySpace()) {
			Msg.error(this,
				"unknown/invalid BSS space " + spaceName + ": " + description.getSpecFile());
			return;
		}
		defaultDataSpace = addressSpace;
		defaultPointerWordSize = defaultDataSpace.getAddressableUnitSize();
	}

	private void setProgramCounter(String programCounterName) {
		if (programCounterName == null) {
			return;
		}

		Register reg = registerBuilder.getRegister(programCounterName);

		if (reg == null) {
			Msg.error(this, "unknown program counter register " + programCounterName + ": " +
				description.getSpecFile());
			return;
		}
		registerBuilder.setFlag(programCounterName, Register.TYPE_PC);
		programCounter = reg;
	}

	private void addContextSetting(Register reg, BigInteger value, Address begad, Address endad) {
		ctxsetting.add(new ContextSetting(reg, value, begad, endad));
	}

	private Pair<Address, Address> parseRange(XmlElement element) {
		String space = element.getAttribute("space");
		AddressSpace addrspace = spacetable.get(space);
		if (addrspace == null) {
			throw new SleighException("Invalid address space name: " + space);
		}
		long first = 0;
		long last = addrspace.getMaxAddress().getOffset();
		String valstring = element.getAttribute("first");
		if (valstring != null) {
			first = SpecXmlUtils.decodeLong(valstring);
		}
		valstring = element.getAttribute("last");
		if (valstring != null) {
			last = SpecXmlUtils.decodeLong(valstring);
		}
		return new Pair<>(addrspace.getAddress(first), addrspace.getAddress(last));
	}

	private void read(XmlPullParser parser) throws XmlParseException {
		Set<String> registerDataSet = new HashSet<>();

		XmlElement el = parser.start("processor_spec");
		while (parser.peek().isStart()) {
			String elName = parser.peek().getName();
			if (elName.equals("properties")) {
				XmlElement subel = parser.start();
				while (!parser.peek().isEnd()) {
					XmlElement next = parser.start("property");
					String key = next.getAttribute("key");
					String value = next.getAttribute("value");
					properties.put(key, value);
					parser.end(next);
				}
				parser.end(subel);
			}
			else if (elName.equals("programcounter")) {
				XmlElement subel = parser.start();
				setProgramCounter(subel.getAttribute("register"));
				parser.end(subel);
			}
			else if (elName.equals("data_space")) {
				XmlElement subel = parser.start();
				setDefaultDataSpace(subel.getAttribute("space"));
				String overrideString = subel.getAttribute("ptr_wordsize");
				if (overrideString != null) {
					int val = SpecXmlUtils.decodeInt(overrideString);
					if (val <= 0 || val >= 32) {
						throw new SleighException("Bad ptr_wordsize attribute");
					}
					defaultPointerWordSize = val;
				}
				parser.end(subel);
			}
			else if (elName.equals("context_data")) {
				XmlElement subel = parser.start();
				while (!parser.peek().isEnd()) {
					XmlElement next = parser.start();
					boolean isContext = next.getName().equals("context_set");
					Pair<Address, Address> range = parseRange(next);
					while (parser.peek().getName().equals("set")) {
						XmlElement set = parser.start();
						String name = set.getAttribute("name");
						String sValue = set.getAttribute("val");
						int radix = 10;
						if (sValue.startsWith("0x") || sValue.startsWith("0X")) {
							sValue = sValue.substring(2);
							radix = 16;
						}
						BigInteger val;
						try {
							val = new BigInteger(sValue, radix);
						}
						catch (Exception e) {
							val = BigInteger.valueOf(0);
						}
						Register reg = registerBuilder.getRegister(name);
						boolean test;
						if (isContext) {
							test = reg == null || !reg.isProcessorContext();
						}
						else {
							test = reg == null || reg.isProcessorContext();
						}
						if (test) {
							throw new SleighException("Bad register name: " + name);
						}
						addContextSetting(reg, val, range.first, range.second);
						// skip the end tag
						parser.end(set);
					}
					// skip the end tag
					parser.end(next);
				}
				parser.end(subel);
			}
			else if (elName.equals("volatile")) {
				XmlElement subel = parser.start();
				while (!parser.peek().getName().equals("volatile")) {
					XmlElement next = parser.start();
					if (next.getName().equals("register")) {
						throw new SleighException("no support for volatile registers yet");
					}
					Pair<Address, Address> range = parseRange(next);
					if (volatileAddresses == null) {
						volatileAddresses = new AddressSet();
					}
					volatileAddresses.addRange(range.first, range.second);
					// skip the end tag
					parser.end(next);
				}
				parser.end(subel);
			}
			else if (elName.equals("jumpassist")) {
				XmlElement subel = parser.start();
				String source = "pspec: " + getLanguageID().getIdAsString();
				String name = subel.getAttribute("name");
				while (parser.peek().isStart()) {
					InjectPayloadSleigh payload = new InjectPayloadJumpAssist(name, source);
					payload.restoreXml(parser, this);
					addAdditionInject(payload);
				}
				parser.end(subel);
			}
			else if (elName.equals("register_data")) {
				XmlElement subel = parser.start();
				while (parser.peek().getName().equals("register")) {
					XmlElement reg = parser.start();
					String registerName = reg.getAttribute("name");
					String registerRename = reg.getAttribute("rename");
					String registerAlias = reg.getAttribute("alias");
					String groupName = reg.getAttribute("group");
					boolean isHidden = SpecXmlUtils.decodeBoolean(reg.getAttribute("hidden"));
					if (registerRename != null) {
						if (!registerBuilder.renameRegister(registerName, registerRename)) {
							throw new SleighException(
								"error renaming " + registerName + " to " + registerRename);
						}
						registerName = registerRename;
					}

					Register register = registerBuilder.getRegister(registerName);
					if (register != null) {
						if (!registerDataSet.add(registerName)) {
							Msg.error(this, "duplicate register " + registerName + ": " +
								description.getSpecFile());
						}
						if (registerAlias != null) {
							registerBuilder.addAlias(registerName, registerAlias);
						}
						if (groupName != null) {
							registerBuilder.setGroup(registerName, groupName);
						}
						if (isHidden) {
							registerBuilder.setFlag(registerName, Register.TYPE_HIDDEN);
						}
						String sizes = reg.getAttribute("vector_lane_sizes");
						if (sizes != null) {
							String[] lanes = sizes.split(",");
							for (String lane : lanes) {
								int laneSize = SpecXmlUtils.decodeInt(lane.trim());
								registerBuilder.addLaneSize(registerName, laneSize);
							}
						}
					}
					else {
						Msg.error(this,
							"unknown register " + registerName + ": " + description.getSpecFile());
					}
					// skip the end tag
					parser.end(reg);
				}
				parser.end(subel);
			}
			else if (elName.equals("default_symbols")) {
				XmlElement subel = parser.start();
				while (parser.peek().getName().equals("symbol")) {
					XmlElement symbol = parser.start();
					String labelName = symbol.getAttribute("name");
					String addressString = symbol.getAttribute("address");
					String typeString = symbol.getAttribute("type");
					ProcessorSymbolType type = ProcessorSymbolType.getType(typeString);
					boolean isEntry = SpecXmlUtils.decodeBoolean(symbol.getAttribute("entry"));
					Address address = addressFactory.getAddress(addressString);
					if (address == null) {
						Msg.error(this, "invalid symbol address \"" + addressString + "\": " +
							description.getSpecFile());
					}
					else {
						AddressLabelInfo info = new AddressLabelInfo(address, labelName, false,
							null, SourceType.IMPORTED, isEntry, type);
						defaultSymbols.add(info);
					}
					// skip the end tag
					parser.end(symbol);
				}
				parser.end(subel);
			}
			else if (elName.equals("default_memory_blocks")) {
				XmlElement subel = parser.start();
				List<MemoryBlockDefinition> list = new ArrayList<>();
				while (parser.peek().getName().equals("memory_block")) {
					XmlElement mblock = parser.start();
					list.add(new MemoryBlockDefinition(mblock));
					// skip the end tag
					parser.end(mblock);
				}
				parser.end(subel);
				defaultMemoryBlocks = new MemoryBlockDefinition[list.size()];
				list.toArray(defaultMemoryBlocks);
			}
			else if (elName.equals("incidentalcopy")) {
				XmlElement subel = parser.start();
				while (parser.peek().isStart()) {
					parser.discardSubTree();
				}
				parser.end(subel);
			}
			else if (elName.equals("inferptrbounds")) {
				XmlElement subel = parser.start();
				while (parser.peek().isStart()) {
					parser.discardSubTree();
				}
				parser.end(subel);
			}
			else if (elName.equals("segmentop")) {
				String source = "pspec: " + getLanguageID().getIdAsString();
				InjectPayloadSleigh payload = new InjectPayloadSegment(source);
				payload.restoreXml(parser, this);
				addAdditionInject(payload);
			}
			else if (elName.equals("segmented_address")) {
				XmlElement subel = parser.start();
				parser.end(subel);
			}
			else {
				throw new XmlParseException("Unknown pspec tag: " + elName);
			}
		}
		parser.end(el);
	}

	private void readRemainingSpecification() throws SAXException, IOException {
		ResourceFile specFile = description.getSpecFile();
		XmlPullParser parser = XmlPullParserFactory.create(specFile, SPEC_ERR_HANDLER, false);
		try {
			read(parser);
		}
		catch (XmlParseException e) {
			Msg.error(this, e.getMessage());
		}
		finally {
			parser.dispose();
		}
	}

	private void readSpecification(final ResourceFile sleighfile)
			throws SAXException, IOException, UnknownInstructionException {
		ErrorHandler errHandler = new ErrorHandler() {
			@Override
			public void error(SAXParseException exception) throws SAXException {
				Msg.error(SleighLanguage.this, "Error parsing " + sleighfile, exception);
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				Msg.error(SleighLanguage.this, "Fatal error parsing " + sleighfile, exception);
			}

			@Override
			public void warning(SAXParseException exception) throws SAXException {
				Msg.warn(SleighLanguage.this, "Warning parsing " + sleighfile, exception);
			}
		};
		XmlPullParser parser = XmlPullParserFactory.create(sleighfile, errHandler, false);
		try {
			restoreXml(parser);
		}
		finally {
			parser.dispose();
		}
	}

	private void restoreXml(XmlPullParser parser) throws UnknownInstructionException {
		XmlElement el = parser.start("sleigh");
		int version = SpecXmlUtils.decodeInt(el.getAttribute("version"));
		if (version != SLA_FORMAT_VERSION) {
			throw new SleighException(".sla file for " + getLanguageID() + " has the wrong format");
		}
		boolean isBigEndian = SpecXmlUtils.decodeBoolean(el.getAttribute("bigendian"));
		if (isBigEndian ^ description.getEndian().isBigEndian()) {
			if (description.getInstructionEndian().isBigEndian() == description.getEndian()
					.isBigEndian()) {
				throw new SleighException(".ldefs says " + getLanguageID() + " is " +
					description.getEndian() + " but .sla says " + el.getAttribute("bigendian"));
			}
		}
		uniqueBase = SpecXmlUtils.decodeLong(el.getAttribute("uniqbase"));
		alignment = SpecXmlUtils.decodeInt(el.getAttribute("align"));
		uniqueAllocateMask = 0;		// Default mask is 0
		String uniqmaskstr = el.getAttribute("uniqmask");
		if (uniqmaskstr != null) {
			uniqueAllocateMask = SpecXmlUtils.decodeInt(uniqmaskstr);
		}
		String numsecstr = el.getAttribute("numsections");
		if (numsecstr != null) {
			numSections = SpecXmlUtils.decodeInt(numsecstr);
		}
		indexer = new SourceFileIndexer();
		indexer.restoreXml(parser);
		parseSpaces(parser);
		symtab = new SymbolTable();
		symtab.restoreXml(parser, this);
		root =
			((SubtableSymbol) symtab.getGlobalScope().findSymbol("instruction")).getDecisionNode();
		parser.end(el);
	}

	private void parseSpaces(XmlPullParser parser) {
		Set<String> truncatedSpaceNames = description.getTruncatedSpaceNames();
		int truncatedSpaceCnt = truncatedSpaceNames.size();
		XmlElement el = parser.start("spaces");
		String defname = el.getAttribute("defaultspace");
		spacetable = new LinkedHashMap<>();
		// Slot zero is always the constant space
		AddressSpace constspc = new GenericAddressSpace("const", 64, AddressSpace.TYPE_CONSTANT, 0);
		spacetable.put("const", constspc);
		//spacetable.put("OTHER", AddressSpace.OTHER_SPACE);
		default_space = null;
		XmlElement subel = parser.peek();
		if (subel.getName().equals("space_other")) {	// tag must be present
			parser.discardSubTree();	// We don't process it
			// Instead the ProgramAddressFactory maps in the static OTHER_SPACE automatically 
		}
		else {
			throw new SleighException(".sla file missing required OTHER space tag");
		}
		while ((subel = parser.softStart("space", "space_unique")) != null) {
			String name = subel.getAttribute("name");
			int index = SpecXmlUtils.decodeInt(subel.getAttribute("index"));
			String typename = subel.getName();
			int delay = SpecXmlUtils.decodeInt(subel.getAttribute("delay"));
			int size = SpecXmlUtils.decodeInt(subel.getAttribute("size"));

			int type = AddressSpace.TYPE_UNKNOWN;
			if (typename.equals("space")) {
				if (delay > 0) {
					type = AddressSpace.TYPE_RAM;
				}
				else {
					type = AddressSpace.TYPE_REGISTER;
				}
			}
			else if (typename.equals("space_unique")) {
				type = AddressSpace.TYPE_UNIQUE;
			}
			if (type == AddressSpace.TYPE_UNKNOWN) {
				throw new SleighException("Sleigh cannot match new space definition to old type");
			}

			String wSizeString = subel.getAttribute("wordsize");
			int wordsize = 1;
			if (wSizeString != null) {
				wordsize = SpecXmlUtils.decodeInt(wSizeString);
			}

			boolean truncateSpace = truncatedSpaceNames.contains(name);
			if (truncateSpace && type != AddressSpace.TYPE_RAM) {
				throw new SleighException("Non-ram space does not support truncation: " + name);
			}

			AddressSpace spc;
			if (getSegmentedSpace().equals(name)) {
				if (truncateSpace && type != AddressSpace.TYPE_RAM) {
					throw new SleighException(
						"Segmented space does not support truncation: " + name);
				}
				if (segmentType.equals("protected")) {
					spc = new ProtectedAddressSpace(name, index);
				}
				else {
					spc = new SegmentedAddressSpace(name, index);
				}
			}
			else {
				if (truncateSpace) {
					int truncatedSize = description.getTruncatedSpaceSize(name);
					if (truncatedSize <= 0 || truncatedSize >= size) {
						throw new SleighException("Invalid space truncation: " + name + ":" + size +
							" -> " + truncatedSize);
					}
					size = truncatedSize;
					--truncatedSpaceCnt;
				}
				spc = new GenericAddressSpace(name, 8 * size, wordsize, type, index);
			}
			spacetable.put(name, spc);
			parser.end(subel);
		}
		if (truncatedSpaceCnt > 0) {
			throw new SleighException(
				"One or more truncated spaced not applied: " + description.getLanguageID());
		}
		default_space = spacetable.get(defname);
		defaultDataSpace = default_space;
		defaultPointerWordSize = defaultDataSpace.getAddressableUnitSize();
		buildAddressSpaceFactory();
		parser.end(el);
	}

	void buildAddressSpaceFactory() {
		GenericAddressSpace[] spaceArray = new GenericAddressSpace[spacetable.size()];
		spacetable.values().toArray(spaceArray);
		addressFactory = new DefaultAddressFactory(spaceArray, default_space);
	}

	private void loadRegisters(RegisterBuilder builder) {
		Symbol[] symbollist = symtab.getSymbolList();
		for (Symbol element : symbollist) {
			if (element instanceof VarnodeSymbol) {
				VarnodeData vn = ((VarnodeSymbol) element).getFixedVarnode();
				// TODO:
				if (vn.space.getType() == AddressSpace.TYPE_REGISTER) {
					Address a = vn.space.getAddress(vn.offset);
					builder.addRegister(element.getName(), null, a, vn.size,
						description.getEndian().isBigEndian(), 0);
				}
				if (vn.space.getType() == AddressSpace.TYPE_RAM) {
					Address a = vn.space.getAddress(vn.offset);
					builder.addRegister(element.getName(), null, a, vn.size,
						description.getEndian().isBigEndian(), 0);
					if (vn.space.isMemorySpace()) {
						setHasMappedRegisters(vn.space);
					}
				}
			}
			else if (element instanceof VarnodeListSymbol) {
				VarnodeListSymbol sym = (VarnodeListSymbol) element;
				PatternValue patternValue = sym.getPatternValue();
				if (patternValue instanceof ContextField) {
					registerContext(sym.getName(), (ContextField) patternValue, builder);
				}
			}
			else if (element instanceof ContextSymbol) {
				ContextSymbol sym = (ContextSymbol) element;
				registerContext(sym, builder);
			}
		}
	}

	private void setHasMappedRegisters(AddressSpace space) {
		if (space instanceof GenericAddressSpace) {
			((GenericAddressSpace) space).setHasMappedRegisters(true);
		}
	}

	private void registerContext(String name, ContextField field, RegisterBuilder builder) {

		int startbit = field.getStartBit();
		int endbit = field.getEndBit();
		int bitLength = endbit - startbit + 1;
		int contextByteLength = (endbit / 8) + 1;
		int contextBitLength = contextByteLength * 8;

		int flags = Register.TYPE_CONTEXT; // assume transient context

		builder.addRegister(name, name, builder.getProcessContextAddress(), contextByteLength,
			contextBitLength - endbit - 1, bitLength, true, flags);
	}

	private void registerContext(ContextSymbol sym, RegisterBuilder builder) {
		ContextField field = (ContextField) sym.getPatternValue();
		int startbit = field.getStartBit();
		int endbit = field.getEndBit();
		int bitLength = endbit - startbit + 1;

		VarnodeData vn = sym.getVarnode().getFixedVarnode();
		int contextBitLength = vn.size * 8;
		Address a = vn.space.getAddress(vn.offset);

		int flags = Register.TYPE_CONTEXT;
		if (!sym.followsFlow()) {
			flags |= Register.TYPE_DOES_NOT_FOLLOW_FLOW;
		}

		builder.addRegister(sym.getName(), sym.getName(), a, vn.size, contextBitLength - endbit - 1,
			bitLength, true, flags);
	}

	private void xrefRegisters() {
		for (Register register : getRegisterManager().getContextRegisters()) {
			contextcache.registerVariable(register);
		}
	}

	@Override
	public AddressSpace getDefaultSpace() {
		return default_space;
	}

	@Override
	public AddressSpace getDefaultDataSpace() {
		return defaultDataSpace;
	}

	/**
	 * @deprecated Will be removed once we have better way to attach address spaces to pointer data-types
	 * @return the default wordsize to use when analyzing pointer offsets
	 */
	@Deprecated
	public int getDefaultPointerWordSize() {
		return defaultPointerWordSize;
	}

	@Override
	public List<CompilerSpecDescription> getCompatibleCompilerSpecDescriptions() {
		return description.getCompatibleCompilerSpecDescriptions();
	}

	@Override
	public CompilerSpec getCompilerSpecByID(CompilerSpecID compilerSpecID)
			throws CompilerSpecNotFoundException {
		if (!compilerSpecDescriptions.containsKey(compilerSpecID)) {
			throw new CompilerSpecNotFoundException(getLanguageID(), compilerSpecID);
		}
		SleighCompilerSpecDescription compilerSpecDescription =
			compilerSpecDescriptions.get(compilerSpecID);
		BasicCompilerSpec compilerSpec = compilerSpecs.get(compilerSpecID);
		if (compilerSpec == null) {
			compilerSpec = new BasicCompilerSpec(compilerSpecDescription, this,
				compilerSpecDescription.getFile());
			compilerSpecs.put(compilerSpecID, compilerSpec);
		}
		return compilerSpec;
	}

	@Override
	public LanguageDescription getLanguageDescription() {
		return description;
	}

	@Override
	public CompilerSpec getDefaultCompilerSpec() {
		SleighCompilerSpecDescription compilerSpecDescription =
			(SleighCompilerSpecDescription) description.getCompatibleCompilerSpecDescriptions()
					.iterator()
					.next();
		try {
			return getCompilerSpecByID(compilerSpecDescription.getCompilerSpecID());
		}
		catch (CompilerSpecNotFoundException e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public String getProperty(String key) {
		return properties.get(key);
	}

	@Override
	public Set<String> getPropertyKeys() {
		return Collections.unmodifiableSet(properties.keySet());
	}

	@Override
	public String getProperty(String key, String defaultString) {
		if (properties.containsKey(key)) {
			return properties.get(key);
		}
		return defaultString;
	}

	@Override
	public boolean getPropertyAsBoolean(String key, boolean defaultBoolean) {
		if (properties.containsKey(key)) {
			return Boolean.parseBoolean(properties.get(key));
		}
		return defaultBoolean;
	}

	@Override
	public int getPropertyAsInt(String key, int defaultInt) {
		if (properties.containsKey(key)) {
			return Integer.parseInt(properties.get(key));
		}
		return defaultInt;
	}

	@Override
	public boolean hasProperty(String key) {
		return properties.containsKey(key);
	}

	@Override
	public ManualEntry getManualEntry(String instruction) {
		initManual();

		if (instruction == null || instruction.length() == 0) {
			return manual.get(null);
		}
		instruction = instruction.toUpperCase();
		String firstKey = instruction.substring(0, 1);
		String lastKey = Character.toString((char) (firstKey.charAt(0) + 1));

		SortedMap<String, ManualEntry> tail = manual.tailMap(firstKey);
		SortedMap<String, ManualEntry> subMap;
		try {
			subMap = tail.headMap(lastKey);
		}
		catch (IllegalArgumentException e) {
			subMap = tail;
		}

		ManualEntry manualEntry = null;
		int maxInCommon = -1;

		Iterator<Entry<String, ManualEntry>> ii = subMap.entrySet().iterator();
		while (ii.hasNext()) {
			Entry<String, ManualEntry> mapEntry = ii.next();
			String key = mapEntry.getKey();
			if (instruction.startsWith(key) && key.length() > maxInCommon) {
				manualEntry = mapEntry.getValue();
				maxInCommon = key.length();
			}
		}

		if (manualEntry == null) {
			return manual.get(null);
		}
		return manualEntry;
	}

	@Override
	public Set<String> getManualInstructionMnemonicKeys() {
		initManual();
		return Collections.unmodifiableSet(manual.keySet());
	}

	private Exception manualException = null;

	private static final Comparator<String> CASE_INSENSITIVE = (o1, o2) -> {
		if (o1 == null) {
			if (o2 == null) {
				return 0;
			}
			return -1;
		}
		if (o2 == null) {
			return 1;
		}
		return o1.compareToIgnoreCase(o2);
	};

	private void initManual() {
		if (manual == null) {
			manual = new TreeMap<>(CASE_INSENSITIVE);
			try {
				if (description.getManualIndexFile() != null) {
					loadIndex(description.getManualIndexFile());
				}
			}
			catch (Exception e) {
				manualException = e;
				Msg.error(this, "error loading manual index", e);
			}
		}
	}

	private static final Pattern COMMENT = Pattern.compile("^\\s*#(.*)");
	private static final Pattern FILE_INCLUDE = Pattern.compile("^\\s*<(.*)");
	private static final Pattern FILE_SWITCH = Pattern.compile("^\\s*@(.*)");
	private static final Pattern FILE_SWITCH_WITH_DESCRIPTION =
		Pattern.compile("^\\s*@(.*)\\[(.*)\\]");
	private static final Pattern INSTRUCTION = Pattern.compile("\\s*([^,]+)\\s*,\\s*(.+)");

	public void loadIndex(ResourceFile processorFile) throws IOException {
		ResourceFile manualDirectory = processorFile.getParentFile().getCanonicalFile();
		ResourceFile currentManual = null;
		ResourceFile defaultManual = null;
		String missingDescription = "(no information available)";
		Reader fr = null;
		BufferedReader buff = null;
		try {
			fr = new InputStreamReader(processorFile.getInputStream());
			buff = new BufferedReader(fr);
			String line;
			while ((line = buff.readLine()) != null) {
				Matcher matcher = COMMENT.matcher(line);
				if (matcher.find()) {
					continue; // skip comment line
				}
				matcher = FILE_INCLUDE.matcher(line);
				if (matcher.find()) {
					String includeFilePath = matcher.group(1).trim();
					ResourceFile includedIndexFile =
						new ResourceFile(manualDirectory, includeFilePath);
					FileResolutionResult result =
						FileUtilities.existsAndIsCaseDependent(includedIndexFile);
					if (!result.isOk()) {
						throw new SleighException("manual index file " + includedIndexFile +
							" is not properly case dependent: " + result.getMessage());
					}
					loadIndex(includedIndexFile);
				}
				else {
					matcher = FILE_SWITCH_WITH_DESCRIPTION.matcher(line);
					if (matcher.find()) {
						if (SystemUtilities.isInDevelopmentMode()) {
							// Search across repositories in development mode
							currentManual = Application
									.findDataFileInAnyModule("manuals/" + matcher.group(1).trim());
						}
						if (currentManual == null) {
							currentManual =
								new ResourceFile(manualDirectory, matcher.group(1).trim());
						}
						FileResolutionResult result =
							FileUtilities.existsAndIsCaseDependent(currentManual);
						missingDescription = matcher.group(2).trim();
						if (defaultManual == null) {
							defaultManual = currentManual;
						}
						if (!result.isOk()) {
							// Since we do not always deliver manuals, generate warning only
							Msg.warn(this,
								"manual file " + currentManual +
									" not found or is not properly case dependent.\n  >>  " +
									missingDescription);
						}
					}
					else {
						matcher = FILE_SWITCH.matcher(line);
						if (matcher.find()) {
							currentManual =
								new ResourceFile(manualDirectory, matcher.group(1).trim());
							FileResolutionResult result =
								FileUtilities.existsAndIsCaseDependent(currentManual);
							if (!result.isOk()) {
								throw new SleighException("manual file " + currentManual +
									" is not properly case dependent: " + result.getMessage());
							}
							missingDescription = "(no information available)";
							if (defaultManual == null) {
								defaultManual = currentManual;
							}
						}
						else {
							matcher = INSTRUCTION.matcher(line);
							if (matcher.find()) {
								if (currentManual == null) {
									throw new IOException("index file " + processorFile +
										" does not specify manual first");
								}
								String mnemonic = matcher.group(1).trim().toUpperCase();
								String page = matcher.group(2).trim();
								ManualEntry entry = new ManualEntry(mnemonic,
									currentManual.getAbsolutePath(), missingDescription, page);
								manual.put(mnemonic, entry);
							}
						}
					}
				}
			}
			if (defaultManual != null) {
				manual.put(null, new ManualEntry(null, defaultManual.getAbsolutePath(),
					missingDescription, null));
			}
		}
		finally {
			if (fr != null) {
				fr.close();
			}
			if (buff != null) {
				buff.close();
			}
		}
	}

	@Override
	public Exception getManualException() {
		initManual();
		return manualException;
	}

	@Override
	public boolean hasManual() {
		initManual();
		return description.getManualIndexFile() != null && manualException == null;
	}

	/**
	 * Generates a limited translator XML tag for the specified address factory and optional register set.
	 * @param factory address factory
	 * @param uniqueOffset the initial offset within the unique address space to start assigning temporary registers
	 * @param optionalSymTab optional symbol table to be passed (may be null to omit).  Only non-context registers
	 * and user-defined pcodeop's are included.
	 * @return the entire XML tag as a String
	 */
	public String buildTranslatorTag(AddressFactory factory, long uniqueOffset,
			SymbolTable optionalSymTab) {
		AddressSpace[] spclist = factory.getAllAddressSpaces();

		StringBuilder resBuf = new StringBuilder();

		resBuf.append("<sleigh");
		SpecXmlUtils.encodeBooleanAttribute(resBuf, "bigendian", isBigEndian());
		SpecXmlUtils.encodeUnsignedIntegerAttribute(resBuf, "uniqbase", uniqueOffset);
		resBuf.append(">\n");
		resBuf.append("<spaces");
		SpecXmlUtils.encodeStringAttribute(resBuf, "defaultspace",
			factory.getDefaultAddressSpace().getName());
		resBuf.append(">\n");

		String tag;
		int delay;
		boolean physical;
		boolean global;

		for (AddressSpace element : spclist) {
			if ((element instanceof OverlayAddressSpace)) {
				OverlayAddressSpace ospace = (OverlayAddressSpace) element;
				resBuf.append("<space_overlay");
				SpecXmlUtils.encodeStringAttribute(resBuf, "name", ospace.getName());
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "index", ospace.getUnique());
				SpecXmlUtils.encodeStringAttribute(resBuf, "base",
					ospace.getOverlayedSpace().getName());
				resBuf.append("/>\n");
				continue;
			}
			switch (element.getType()) {
				case AddressSpace.TYPE_RAM:
					tag = "space";
					delay = 1;
					physical = true;
					global = true;
					break;
				case AddressSpace.TYPE_REGISTER:
					tag = "space";
					delay = 0;
					physical = true;
					global = false;
					break;
				case AddressSpace.TYPE_UNIQUE:
					tag = "space_unique";
					delay = 0;
					physical = true;
					global = false;
					break;
				case AddressSpace.TYPE_OTHER:
					tag = "space_other";
					delay = 0;
					physical = true;
					global = true;
					break;
				default:
					continue;
			}
			resBuf.append("<").append(tag);
			SpecXmlUtils.encodeStringAttribute(resBuf, "name", element.getName());
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "index", element.getUnique());

			int size = element.getSize(); // Size in bits
			if (element instanceof SegmentedAddressSpace) {
				// TODO: SegmentedAddressSpace shouldn't really return 21
				size = 32;
			}
			if (size > 64) {
				size = 64;
			}
			int bytesize = (size + 7) / 8; // Convert bits to bytes
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", bytesize);

			if (element.getAddressableUnitSize() > 1) {
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "wordsize",
					element.getAddressableUnitSize());
			}

			SpecXmlUtils.encodeBooleanAttribute(resBuf, "bigendian", isBigEndian());
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "delay", delay);
			SpecXmlUtils.encodeBooleanAttribute(resBuf, "physical", physical);
			SpecXmlUtils.encodeBooleanAttribute(resBuf, "global", global);

			resBuf.append("/>\n");
		}
		resBuf.append("</spaces>\n");

		SleighLanguageDescription sleighDescription =
			(SleighLanguageDescription) getLanguageDescription();
		Set<String> truncatedSpaceNames = sleighDescription.getTruncatedSpaceNames();
		if (!truncatedSpaceNames.isEmpty()) {
			for (String spaceName : truncatedSpaceNames) {
				int sz = sleighDescription.getTruncatedSpaceSize(spaceName);
				resBuf.append("<truncate_space");
				SpecXmlUtils.encodeStringAttribute(resBuf, "space", spaceName);
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", sz);
				resBuf.append("/>\n");
			}
		}
		if (optionalSymTab != null) {
			resBuf.append(buildSymbolsXml(optionalSymTab));
		}

		resBuf.append("</sleigh>\n");
		return resBuf.toString();
	}

	private static String buildSymbolsXml(SymbolTable symtab) {

		ArrayList<Symbol> symList = new ArrayList<>();
		for (Symbol sym : symtab.getSymbolList()) {
			if (sym instanceof UseropSymbol) {
				symList.add(sym);
			}
			else if (sym instanceof VarnodeSymbol) {
				if ("contextreg".equals(sym.getName())) {
					continue;
				}
				symList.add(sym);
			}
		}

		int count = symList.size();
		StringBuilder s = new StringBuilder();
		s.append("<symbol_table scopesize=\"1\" symbolsize=\"");
		s.append(count);
		s.append("\">\n");
		s.append("<scope id=\"0x0\" parent=\"0x0\"/>\n");

		// First save the headers
		for (int i = 0; i < count; ++i) {
			Symbol sym = symList.get(i);
			String type;
			if (sym instanceof UseropSymbol) {
				type = "userop_head";
			}
			else {
				type = "varnode_sym_head";
			}
			s.append("<" + type + " name=\"" + sym.getName() + "\" id=\"0x" +
				Integer.toHexString(i) + "\" scope=\"0x0\"/>\n");
		}

		// Now save the content of each symbol
		for (int i = 0; i < count; ++i) {
			Symbol sym = symList.get(i);
			if (sym instanceof UseropSymbol) {
				UseropSymbol opSym = (UseropSymbol) sym;
				s.append("<userop name=\"" + sym.getName() + "\" id=\"0x" + Integer.toHexString(i) +
					"\" scope=\"0x0\" index=\"" + opSym.getIndex() + "\"/>\n");
			}
			else {
				VarnodeSymbol vnSym = (VarnodeSymbol) sym;
				VarnodeData vn = vnSym.getFixedVarnode();
				s.append(
					"<varnode_sym name=\"" + sym.getName() + "\" id=\"0x" + Integer.toHexString(i) +
						"\" scope=\"0x0\" space=\"" + vn.space.getName() + "\" offset=\"0x" +
						Long.toHexString(vn.offset) + "\" size=\"" + vn.size + "\"/>\n");
			}
		}
		s.append("</symbol_table>\n");
		return s.toString();
	}

	private void initParallelHelper() {
		String className =
			getProperty(GhidraLanguagePropertyKeys.PARALLEL_INSTRUCTION_HELPER_CLASS);
		if (className == null) {
			return;
		}
		try {
			Class<?> helperClass = Class.forName(className);
			if (!ParallelInstructionLanguageHelper.class.isAssignableFrom(helperClass)) {
				Msg.error(this,
					"Invalid Class specified for " +
						GhidraLanguagePropertyKeys.PARALLEL_INSTRUCTION_HELPER_CLASS + " (" +
						helperClass.getName() + "): " + description.getSpecFile());
			}
			else {
				parallelHelper =
					(ParallelInstructionLanguageHelper) helperClass.getDeclaredConstructor()
							.newInstance();
			}
		}
		catch (Exception e) {
			throw new SleighException("Failed to instantiate " +
				GhidraLanguagePropertyKeys.PARALLEL_INSTRUCTION_HELPER_CLASS + " (" + className +
				"): " + description.getSpecFile(), e);
		}
	}

	@Override
	public ParallelInstructionLanguageHelper getParallelInstructionHelper() {
		return parallelHelper;
	}

	@Override
	public List<Register> getSortedVectorRegisters() {
		return registerManager.getSortedVectorRegisters();
	}

}
