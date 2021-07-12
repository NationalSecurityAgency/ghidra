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
package ghidra.app.util.bin.format.dwarf4.next;

import java.io.Closeable;
import java.io.IOException;
import java.util.*;

import org.apache.commons.collections4.ListValuedMap;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.dwarf4.*;
import ghidra.app.util.bin.format.dwarf4.attribs.DWARFAttributeFactory;
import ghidra.app.util.bin.format.dwarf4.encoding.*;
import ghidra.app.util.bin.format.dwarf4.expression.DWARFExpressionException;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.*;
import ghidra.app.util.opinion.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.datastruct.FixedSizeHashMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * DWARFProgram encapsulates a {@link Program Ghidra program} with DWARF specific reference data
 * used by {@link DWARFDataTypeImporter} and {@link DWARFFunctionImporter}, along with some
 * helper functions.
 */
public class DWARFProgram implements Closeable {
	public static final String DWARF_ROOT_NAME = "DWARF";
	public static final int DEFAULT_NAME_LENGTH_CUTOFF = SymbolUtilities.MAX_SYMBOL_NAME_LENGTH;
	public static final int MAX_NAME_LENGTH_CUTOFF = SymbolUtilities.MAX_SYMBOL_NAME_LENGTH;
	public static final int MIN_NAME_LENGTH_CUTOFF = 20;
	private static final int NAME_HASH_REPLACEMENT_SIZE = 8 + 2 + 2;
	private static final String ELLIPSES_STR = "...";

	/**
	 * Returns true if the {@link Program program} probably has DWARF information.
	 * <p>
	 * If the program is an Elf binary, it must have (at least) ".debug_info" and ".debug_abbr" program sections.
	 * <p>
	 * If the program is a MachO binary (ie. Mac), it must have a ".dSYM" directory co-located next to the
	 * original binary file on the native filesystem.  (ie. outside of Ghidra).  See the DSymSectionProvider
	 * for more info.
	 * <p>
	 * @param program {@link Program} to test
	 * @return boolean true if program has DWARF info, false if not
	 */
	public static boolean isDWARF(Program program) {
		String format = Objects.requireNonNullElse(program.getExecutableFormat(), "");

		switch (format) {
			case ElfLoader.ELF_NAME:
			case PeLoader.PE_NAME:
				try (DWARFSectionProvider dsp =
					DWARFSectionProviderFactory.createSectionProviderFor(program)) {
					return dsp != null;
				}
			case MachoLoader.MACH_O_NAME:
				return DSymSectionProvider.getDSYMForProgram(program) != null;
		}
		return false;
	}

	private final Program program;
	private DWARFImportOptions importOptions;
	private DWARFNameInfo rootDNI =
		DWARFNameInfo.createRoot(new CategoryPath(CategoryPath.ROOT, DWARF_ROOT_NAME));
	private DWARFNameInfo unCatDataTypeRoot = DWARFNameInfo.createRoot(
		new CategoryPath(rootDNI.getOrganizationalCategoryPath(), "_UNCATEGORIZED_"));

	private DWARFSectionProvider sectionProvider;
	private StringTable debugStrings;
	private List<DWARFCompilationUnit> compUnits = new ArrayList<>();
	private DWARFCompilationUnit currentCompUnit;
	private DWARFAttributeFactory attributeFactory;
	private int totalDIECount = -1;
	private int totalAggregateCount;
	private boolean foundCrossCURefs = false;
	private long programBaseAddressFixup;

	private int maxDNICacheSize = 50;
	private FixedSizeHashMap<Long, DWARFNameInfo> dniCache =
		new FixedSizeHashMap<>(100, maxDNICacheSize);
	private int nameLengthCutoffSize = DEFAULT_NAME_LENGTH_CUTOFF;

	private Map<DWARFAttributeSpecification, DWARFAttributeSpecification> attributeSpecIntern =
		new HashMap<>();

	private BinaryReader debugLocation;
	private BinaryReader debugRanges;
	private BinaryReader debugInfoBR;
	private BinaryReader debugLineBR;
	private BinaryReader debugAbbrBR;

	private DWARFRegisterMappings dwarfRegisterMappings;

	/**
	 * List of all the currently loaded DIE records.
	 */
	private List<DebugInfoEntry> currentDIEs = new ArrayList<>();

	/**
	 * Map of DIE offsets to DIE instances of the elements in {@link #currentDIEs}.
	 */
	private Map<Long, DebugInfoEntry> offsetMap = new HashMap<>();

	/**
	 * Map of DIE offsets to {@link DIEAggregate} instances.
	 */
	private Map<Long, DIEAggregate> aggregatesByOffset = new HashMap<>();

	/**
	 * List of current {@link DIEAggregate} instances.
	 */
	private List<DIEAggregate> aggregates = new ArrayList<>();

	/**
	 * Map of DIE offsets of {@link DIEAggregate}s that are being pointed to by
	 * other {@link DIEAggregate}s with a DW_AT_type property.
	 * <p>
	 * In other words, a map of inbound links to a DIEA.
	 */
	private ListValuedMap<Long, DIEAggregate> typeReferers = new ArrayListValuedHashMap<>();

	/**
	 * Main constructor for DWARFProgram.
	 * <p>
	 * Auto-detects the DWARFSectionProvider and chains to the next constructor.
	 *
	 * @param program Ghidra {@link Program}.
	 * @param importOptions {@link DWARFImportOptions} to controls options during reading / parsing /importing.
	 * @param monitor {@link TaskMonitor} to control canceling and progress.
	 * @throws CancelledException if user cancels
	 * @throws IOException if error reading data
	 * @throws DWARFException if bad stuff happens.
	 */
	public DWARFProgram(Program program, DWARFImportOptions importOptions, TaskMonitor monitor)
			throws CancelledException, IOException, DWARFException {
		this(program, importOptions, monitor,
			DWARFSectionProviderFactory.createSectionProviderFor(program));
	}

	/**
	 * Constructor for DWARFProgram.
	 *
	 * @param program Ghidra {@link Program}.
	 * @param importOptions {@link DWARFImportOptions} to controls options during reading / parsing /importing.
	 * @param monitor {@link TaskMonitor} to control canceling and progress.
	 * @param sectionProvider {@link DWARFSectionProvider} factory that finds DWARF .debug_* sections
	 * wherever they live.
	 * @throws CancelledException if user cancels
	 * @throws IOException if error reading data
	 * @throws DWARFException if bad stuff happens.
	 */
	public DWARFProgram(Program program, DWARFImportOptions importOptions, TaskMonitor monitor,
			DWARFSectionProvider sectionProvider)
			throws CancelledException, IOException, DWARFException {
		if (sectionProvider == null) {
			throw new IllegalArgumentException("Null DWARFSectionProvider");
		}

		this.program = program;
		this.sectionProvider = sectionProvider;
		this.importOptions = importOptions;
		this.nameLengthCutoffSize = Math.max(MIN_NAME_LENGTH_CUTOFF,
			Math.min(importOptions.getNameLengthCutoff(), MAX_NAME_LENGTH_CUTOFF));

		monitor.setMessage("Reading DWARF debug string table");
		this.debugStrings = StringTable.readStringTable(
			sectionProvider.getSectionAsByteProvider(DWARFSectionNames.DEBUG_STR));
//		Msg.info(this, "Read DWARF debug string table, " + debugStrings.getByteCount() + " bytes.");

		this.attributeFactory = new DWARFAttributeFactory(this);

		this.debugLocation = getBinaryReaderFor(DWARFSectionNames.DEBUG_LOC);
		this.debugInfoBR = getBinaryReaderFor(DWARFSectionNames.DEBUG_INFO);
		this.debugLineBR = getBinaryReaderFor(DWARFSectionNames.DEBUG_LINE);
		this.debugAbbrBR = getBinaryReaderFor(DWARFSectionNames.DEBUG_ABBREV);
		this.debugRanges = getBinaryReaderFor(DWARFSectionNames.DEBUG_RANGES);// sectionProvider.getSectionAsByteProvider(DWARFSectionNames.DEBUG_RANGES);

		// if there are relocations (already handled by the ghidra loader) anywhere in the debuginfo or debugrange sections, then
		// we don't need to manually fix up addresses extracted from DWARF data.
		boolean hasRelocations = hasRelocations(debugInfoBR) || hasRelocations(debugRanges);
		if (!hasRelocations) {
			Long oib = ElfLoader.getElfOriginalImageBase(program);
			if (oib != null && oib.longValue() != program.getImageBase().getOffset()) {
				this.programBaseAddressFixup = program.getImageBase().getOffset() - oib.longValue();
			}
		}

		dwarfRegisterMappings =
			DWARFRegisterMappingsManager.hasDWARFRegisterMapping(program.getLanguage())
					? DWARFRegisterMappingsManager.getMappingForLang(program.getLanguage())
					: null;
		bootstrapCompilationUnits(monitor);
		checkPreconditions(monitor);
	}

	@Override
	public void close() throws IOException {
		sectionProvider.close();
		compUnits.clear();
		debugAbbrBR = null;
		debugInfoBR = null;
		debugLineBR = null;
		debugLocation = null;
		debugRanges = null;
		debugStrings.clear();
		dniCache.clear();
		clearDIEIndexes();
	}

	public DWARFImportOptions getImportOptions() {
		return importOptions;
	}

	public Program getGhidraProgram() {
		return program;
	}

	public boolean isBigEndian() {
		return program.getLanguage().isBigEndian();
	}

	public boolean isLittleEndian() {
		return !program.getLanguage().isBigEndian();
	}

	private BinaryReader getBinaryReaderFor(String sectionName) throws IOException {
		ByteProvider bp = sectionProvider.getSectionAsByteProvider(sectionName);
		return (bp != null) ? new BinaryReader(bp, !isBigEndian()) : null;
	}

	private boolean hasRelocations(BinaryReader br) throws IOException {
		if (br == null) {
			return false;
		}
		ByteProvider bp = br.getByteProvider();
		if (bp instanceof MemoryByteProvider && bp.length() > 0) {
			MemoryByteProvider mbp = (MemoryByteProvider) bp;
			Address startAddr = mbp.getAddress(0);
			Address endAddr = mbp.getAddress(mbp.length() - 1);
			if (program.getRelocationTable().getRelocations(
				new AddressSet(startAddr, endAddr)).hasNext()) {
				return true;
			}
		}
		return false;
	}

	//-------------------------------------------------------------------------
	private static boolean isAnonDWARFName(String name) {
		return (name == null) || name.startsWith("._") || name.startsWith("<anonymous");
	}

	public String getEntryName(DIEAggregate diea) {
		String name = diea.getString(DWARFAttribute.DW_AT_name, null);

		if (name == null) {
			String linkageName = diea.getString(DWARFAttribute.DW_AT_linkage_name, null);
			if (linkageName == null) {
				linkageName = diea.getString(DWARFAttribute.DW_AT_MIPS_linkage_name, null);
			}
			name = linkageName;
		}

		return name;
	}

	/**
	 * Returns the string path of a DWARF entry.
	 * <p>
	 * Always returns a name for the passed-in entry, but you should probably only use this
	 * for entries that are {@link DIEAggregate#isNamedType()}
	 * <p>
	 * @param diea
	 * @return never null
	 */
	private DWARFNameInfo getDWARFNameInfo(DIEAggregate diea, DWARFNameInfo localRootDNI) {

		DWARFNameInfo parentDNI = localRootDNI;

		DIEAggregate declParent = diea.getDeclParent();
		if ((declParent != null) && declParent.getTag() != DWARFTag.DW_TAG_compile_unit) {
			parentDNI = lookupDNIByOffset(declParent.getOffset());
			if (parentDNI == null) {
				parentDNI = getDWARFNameInfo(declParent, localRootDNI);
				if (parentDNI != null) {
					cacheDNIByOffset(declParent.getOffset(), parentDNI);
				}
			}
		}

		String name = getEntryName(diea);

		// Mangled names can occur in linkage attributes or in the regular name attribute.
		if (name != null && name.contains("_Z") /* mangler start seq */ && !name.startsWith(
			"_GLOBAL_") /* compiler generated, don't demangle as they tend to conflict with existing names */) {
			List<String> nestings = ensureSafeNameLengths(DWARFUtil.parseMangledNestings(name));
			if (!nestings.isEmpty()) {
				name = nestings.remove(nestings.size() - 1);
				if (parentDNI == localRootDNI && !nestings.isEmpty()) {
					parentDNI = DWARFNameInfo.fromList(localRootDNI, nestings);
				}
			}
		}

		// If namespace info got squashed due to compiler/linker flags, try to
		// dig it up from the mangled linkage info that might be present in our children.
		if (localRootDNI.equals(parentDNI)) {
			List<String> nestings = DWARFUtil.findLinkageNameInChildren(diea.getHeadFragment());
			if (!nestings.isEmpty()) {
				nestings.remove(nestings.size() - 1);
				parentDNI = DWARFNameInfo.fromList(localRootDNI, nestings);
			}
		}

		if (name == null) {
			// check to see if there is a single inbound typedef that we can
			// steal its name.
			DIEAggregate referringTypedef = DWARFUtil.getReferringTypedef(diea);
			if (referringTypedef != null) {
				return getDWARFNameInfo(referringTypedef, localRootDNI);
			}
		}

		boolean isAnon = false;
		if (name == null) {
			switch (diea.getTag()) {
				case DWARFTag.DW_TAG_base_type:
					name = getAnonBaseTypeName(diea);
					isAnon = true;
					break;
				case DWARFTag.DW_TAG_enumeration_type:
					name = getAnonEnumName(diea);
					isAnon = true;
					break;
				case DWARFTag.DW_TAG_subroutine_type:
					// unnamed subroutines (C func ptrs)
					// See {@link #isAnonSubroutine(DataType)}
					name = "anon_subr";
					isAnon = true;
					break;
				case DWARFTag.DW_TAG_lexical_block:
					name = DWARFUtil.getLexicalBlockName(diea);
					break;
				case DWARFTag.DW_TAG_formal_parameter:
					name = "param_" + DWARFUtil.getMyPositionInParent(diea.getHeadFragment());
					isAnon = true;
					break;
				case DWARFTag.DW_TAG_subprogram:
				case DWARFTag.DW_TAG_inlined_subroutine:
					if (declParent != null && declParent.isStructureType() &&
						diea.getBool(DWARFAttribute.DW_AT_artificial, false)) {
						name = parentDNI.getName();
					}
					else {
						name = "anon_func";
						isAnon = true;
					}
					break;
				default:
					if (declParent != null && declParent.isNameSpaceContainer()) {
						name = DWARFUtil.getAnonNameForMeFromParentContext2(diea);
					}
					break;
			}
		}

		// Name was not found
		if (isAnonDWARFName(name)) {
			name = createAnonName("anon_" + DWARFUtil.getContainerTypeName(diea), diea);
			isAnon = true;
		}

		String origName = isAnon ? null : name;
		String workingName = ensureSafeNameLength(name);

		DWARFNameInfo result =
			parentDNI.createChild(origName, workingName, DWARFUtil.getSymbolTypeFromDIE(diea));
		return result;
	}

	private String getAnonBaseTypeName(DIEAggregate diea) {
		try {
			int dwarfSize = diea.parseInt(DWARFAttribute.DW_AT_byte_size, 0);
			int dwarfEncoding = (int) diea.getUnsignedLong(DWARFAttribute.DW_AT_encoding, -1);
			String name = createAnonName(
				"anon_basetype_" + DWARFEncoding.getTypeName(dwarfEncoding) + "_" + dwarfSize,
				diea);
			return name;
		}
		catch (IOException | DWARFExpressionException e) {
			return createAnonName("anon_basetype_unknown", diea);
		}
	}

	private String getAnonEnumName(DIEAggregate diea) {
		int enumSize = Math.max(1, (int) diea.getUnsignedLong(DWARFAttribute.DW_AT_byte_size, 1));
		String name = createAnonName("anon_enum_" + (enumSize * 8), diea);
		return name;
	}

	private static String createAnonName(String baseName, DIEAggregate diea) {
		return baseName + DataType.CONFLICT_SUFFIX + diea.getHexOffset();

	}

	/**
	 * Transform a string with a C++ template-like syntax into a hopefully shorter version that
	 * uses a fixed-length hash of the original string.
	 * <p>
	 * blah&lt;foo, bar&gt;
	 * <p>
	 * becomes
	 * <p>
	 * blah&lt;$12345678$&gt;
	 * @param s
	 * @return
	 */
	private static String abbrevTemplateName(String s) {
		int startBracket = s.indexOf('<');
		int endBracket = s.lastIndexOf('>');
		if (startBracket + NAME_HASH_REPLACEMENT_SIZE < endBracket) {
			String templateParams = s.substring(startBracket, endBracket);
			return s.substring(0, startBracket + 1) + "$" +
				Integer.toHexString(templateParams.hashCode()) + "$" + s.substring(endBracket);
		}
		return s;
	}

	private String ensureSafeNameLength(String s) {
		if (s.length() <= nameLengthCutoffSize) {
			return s;
		}
		s = abbrevTemplateName(s);
		if (s.length() <= nameLengthCutoffSize) {
			return s;
		}
		int prefixKeepLength =
			nameLengthCutoffSize - ELLIPSES_STR.length() - NAME_HASH_REPLACEMENT_SIZE;
		return s.substring(0, prefixKeepLength) + ELLIPSES_STR + "$" +
			Integer.toHexString(s.hashCode()) + "$";
	}

	private List<String> ensureSafeNameLengths(List<String> strs) {
		for (int i = 0; i < strs.size(); i++) {
			strs.set(i, ensureSafeNameLength(strs.get(i)));
		}
		return strs;
	}

	public DWARFNameInfo getName(DIEAggregate diea) {
		DWARFNameInfo dni = lookupDNIByOffset(diea.getOffset());
		if (dni == null) {
			dni = getDWARFNameInfo(diea, unCatDataTypeRoot);
			cacheDNIByOffset(diea.getOffset(), dni);
		}
		return dni;
	}

	public DWARFNameInfo lookupDNIByOffset(long offset) {
		DWARFNameInfo tmp = dniCache.get(offset);
		return tmp;
	}

	public void cacheDNIByOffset(long offset, DWARFNameInfo dni) {
		dniCache.put(offset, dni);
	}

	//------------------------------------------------------------------------------

	/**
	 * Bootstrap all compilation unit headers and abbreviation definitions.
	 * @throws DWARFException
	 * @throws IOException
	 * @throws CancelledException
	 */
	private void bootstrapCompilationUnits(TaskMonitor monitor)
			throws CancelledException, IOException, DWARFException {

		BinaryReader br = debugInfoBR;
		br.setPointerIndex(0);
		while (br.getPointerIndex() < br.getByteProvider().length()) {
			monitor.checkCanceled();
			monitor.setMessage("Bootstrapping DWARF Compilation Unit #" + compUnits.size());

			DWARFCompilationUnit cu = DWARFCompilationUnit.readCompilationUnit(this, br,
				debugAbbrBR, compUnits.size(), monitor);

			if (cu != null) {
				compUnits.add(cu);
				br.setPointerIndex(cu.getEndOffset());
			}
		}
	}

	/**
	 * Returns the {@link DIEAggregate} that contains the specified {@link DebugInfoEntry}.
	 *
	 * @param die {@link DebugInfoEntry} or null
	 * @return {@link DIEAggregate} that contains the specified DIE, or null if DIE null or
	 * the aggregate was not found.
	 */
	public DIEAggregate getAggregate(DebugInfoEntry die) {
		if (die != null && !importOptions.isPreloadAllDIEs() &&
			die.getCompilationUnit() != currentCompUnit) {
			throw new RuntimeException(
				"Bad request for getAggregate() when compUnit is not updated");
		}
		return (die != null) ? aggregatesByOffset.get(die.getOffset()) : null;
	}

	/**
	 * Returns the {@link DIEAggregate} that contains the {@link DebugInfoEntry} specified
	 * by the offset.
	 *
	 * @param offset offset of a DIE record
	 * @return {@link DIEAggregate} that contains the DIE record specified, or null if bad
	 * offset.
	 */
	public DIEAggregate getAggregate(long offset) {
		return aggregatesByOffset.get(offset);
	}

	/**
	 * Returns the list of all currently loaded {@link DIEAggregate}s, which will be either
	 * just the DIEA of the current CU, or all DIEA if {@link DWARFImportOptions#isPreloadAllDIEs()}.
	 *
	 * @return List of {@link DIEAggregate}.
	 */
	public List<DIEAggregate> getAggregates() {
		return aggregates;
	}

	/**
	 * Returns the total number of DIE records in the entire program.
	 *
	 * @return the total number of DIE records in the entire program.
	 */
	public int getTotalDIECount() {
		return totalDIECount;
	}

	/**
	 * Returns the total number of {@link DIEAggregate} objects in the entire program.
	 *
	 * @return the total number of {@link DIEAggregate} objects in the entire program.
	 */
	public int getTotalAggregateCount() {
		return totalAggregateCount;
	}

	/**
	 * Sets the currently active compilation unit.  Used when 'paging' through the DIE records
	 * in a compilation-unit-at-a-time manner, vs the {@link DWARFImportOptions#isPreloadAllDIEs()}
	 * where all DIE/DIEA records are loaded at once.
	 *
	 * @param cu {@link DWARFCompilationUnit} to set as the active element and load it's DIE records.
	 * @param monitor {@link TaskMonitor} to update with status and check for cancelation.
	 * @throws CancelledException if user cancels
	 * @throws IOException if error reading data
	 * @throws DWARFException if error in DWARF record structure
	 */
	public void setCurrentCompilationUnit(DWARFCompilationUnit cu, TaskMonitor monitor)
			throws CancelledException, IOException, DWARFException {
		if (cu != currentCompUnit) {
			currentCompUnit = cu;
			if (cu != null && !importOptions.isPreloadAllDIEs()) {
				clearDIEIndexes();
				cu.readDIEs(currentDIEs, monitor);
				rebuildDIEIndexes();
			}
		}
	}

	public List<DWARFCompilationUnit> getCompilationUnits() {
		return compUnits;
	}

	public DWARFCompilationUnit getCompilationUnitFor(long offset) {
		for (DWARFCompilationUnit cu : getCompilationUnits()) {
			if (cu.containsOffset(offset)) {
				return cu;
			}
		}
		return null;
	}

	public BinaryReader getDebugLocation() {
		return debugLocation;
	}

	public BinaryReader getDebugRanges() {
		return debugRanges;
	}

	public BinaryReader getDebugInfo() {
		return debugInfoBR;
	}

	public BinaryReader getDebugLine() {
		return debugLineBR;
	}

	public DWARFRegisterMappings getRegisterMappings() {
		return dwarfRegisterMappings;
	}

	public DWARFNameInfo getRootDNI() {
		return rootDNI;
	}

	public DWARFNameInfo getUncategorizedRootDNI() {
		return unCatDataTypeRoot;
	}

	public StringTable getDebugStrings() {
		return debugStrings;
	}

	public DWARFAttributeFactory getAttributeFactory() {
		return attributeFactory;
	}

	public void setAttributeFactory(DWARFAttributeFactory attributeFactory) {
		this.attributeFactory = attributeFactory;
	}

	public boolean getFoundCrossCURefs() {
		return foundCrossCURefs;
	}

	public void setFoundCrossCURefs(boolean b) {
		this.foundCrossCURefs = b;
	}

	public DWARFAttributeSpecification internAttributeSpec(DWARFAttributeSpecification das) {
		DWARFAttributeSpecification inDAS = attributeSpecIntern.get(das);
		if (inDAS == null) {
			inDAS = das;
			attributeSpecIntern.put(inDAS, inDAS);
		}
		return inDAS;
	}

	/**
	 * @return the entries list
	 */
	public List<DebugInfoEntry> getEntries() {
		return currentDIEs;
	}

	/**
	 * Returns the count of the DIE records in this compilation unit.
	 * <p>
	 * Only valid if called after {@link #checkPreconditions(TaskMonitor)}
	 * and before {@link #clearDIEIndexes()}.
	 * @return number of DIE records in the compunit.
	 * @throws IOException
	 * @throws CancelledException
	 */
	public int getDIECount() throws IOException, CancelledException {
		return currentDIEs.size();
	}

	/**
	 * Releases the memory used by the DIE entries read when invoking
	 * {@link #checkPreconditions(TaskMonitor)}.
	 */
	public void clearDIEIndexes() {
		offsetMap.clear();
		currentDIEs.clear();
		aggregatesByOffset.clear();
		aggregates.clear();
		typeReferers.clear();
	}

	/**
	 * Returns the entry with the given byte offset.
	 * <p>
	 * The byte offset corresponds to the byte index
	 * in the original file where the entry was defined.
	 * <p>
	 * Returns null if the requested entry does not exist.
	 *
	 * @param byteOffset the byte offset
	 * @return the entry with the given byte offset
	 */
	public DebugInfoEntry getEntryAtByteOffsetUnchecked(long byteOffset) {
		return offsetMap.get(Long.valueOf(byteOffset));
	}

	private List<DIEAggregate> getTypeReferers(DIEAggregate targetDIEA) {
		List<DIEAggregate> result = typeReferers.get(targetDIEA.getOffset());
		return (result != null) ? result : Collections.emptyList();
	}

	/**
	 * Returns a list of {@link DIEAggregate}s that refer to the targetDIEA via an
	 * attribute of the specified tag type.
	 *
	 * @param targetDIEA {@link DIEAggregate} that might be pointed to by other DIEAs.
	 * @param tag the {@link DWARFTag} attribute type that is pointing DIEAs are using
	 * to refer to the target DIEA.
	 * @return list of DIEAs that point to the target, empty list if nothing found.
	 */
	public List<DIEAggregate> getTypeReferers(DIEAggregate targetDIEA, int tag) {
		List<DIEAggregate> result = new ArrayList<>();

		for (DIEAggregate referer : getTypeReferers(targetDIEA)) {
			if (referer.getTag() == tag) {
				result.add(referer);
			}
		}
		return result;
	}

	private void rebuildDIEIndexes() {
		buildDIEIndex();
		buildAggregateIndex();
		buildTypeRefIndex();
	}

	private void buildDIEIndex() {
		for (DebugInfoEntry die : currentDIEs) {
			offsetMap.put(Long.valueOf(die.getOffset()), die);
		}
	}

	private boolean checkForCrossCURefs(List<DebugInfoEntry> dies) {
		// 'static' set of attribute types that refer from one DIE to another DIE
		int[] refAttrs = { DWARFAttribute.DW_AT_type, DWARFAttribute.DW_AT_abstract_origin,
			DWARFAttribute.DW_AT_specification };
		for (DebugInfoEntry die : dies) {
			DIEAggregate diea = DIEAggregate.createSingle(die);
			for (int attr : refAttrs) {
				long refdOffset = diea.getUnsignedLong(attr, -1);
				if (refdOffset == -1) {
					continue;
				}
				if (!die.getCompilationUnit().containsOffset(refdOffset)) {
					return true;
				}
			}
		}
		return false;
	}

	private void buildAggregateIndex() {
		Map<Long, DebugInfoEntry> offsetMap2Head = buildHeadIndex();
		for (DebugInfoEntry die : currentDIEs) {
			if (aggregatesByOffset.containsKey(die.getOffset())) {
				continue;
			}
			DebugInfoEntry head = getHead(die, offsetMap2Head);
			DIEAggregate diea = DIEAggregate.createFromHead(head);
			aggregates.add(diea);
			for (long fragOffset : diea.getOffsets()) {
				aggregatesByOffset.put(fragOffset, diea);
			}
		}
	}

	private int countAggregates() {
		Map<Long, DebugInfoEntry> offsetMap2Head = buildHeadIndex();
		Set<Long> uniqueHeads = new HashSet<>();
		for (DebugInfoEntry die : currentDIEs) {
			DebugInfoEntry head = getHead(die, offsetMap2Head);
			uniqueHeads.add(head.getOffset());
		}
		return uniqueHeads.size();
	}

	private void buildTypeRefIndex() {
		for (DIEAggregate diea : aggregates) {
			DIEAggregate typeRef = diea.getTypeRef();
			if (typeRef != null) {
				typeReferers.put(typeRef.getOffset(), diea);
			}
		}
	}

	private Map<Long, DebugInfoEntry> buildHeadIndex() {
		Map<Long, DebugInfoEntry> offsetMap2Head = new HashMap<>();
		for (DebugInfoEntry die : currentDIEs) {
			offsetMap2Head.put(Long.valueOf(die.getOffset()), die);

			// If this entry has refs back to a previous DIE, overwrite their
			// offset2head mapping so that their offset points to this entry.
			// This codeblock is similar to the logic in DIEAggregrate#createFromHead()
			DIEAggregate diea = DIEAggregate.createSingle(die);
			int[] refAttrs =
				{ DWARFAttribute.DW_AT_abstract_origin, DWARFAttribute.DW_AT_specification };
			for (int attr : refAttrs) {
				long refdOffset = diea.getUnsignedLong(attr, -1);
				if (refdOffset == -1) {
					continue;
				}

				offsetMap2Head.put(refdOffset, die);
			}
		}
		return offsetMap2Head;
	}

	/**
	 * Returns the 'head'-most {@link DebugInfoEntry DIE} instance of the DIEs that
	 * make up the fragment chain that include the {@code die} parameter.
	 * <p>
	 * Since there can be many-to-one DIE relationships (for instance, many 'spec' DIEs pointing
	 * to the same decl DIE), the results can be asymmetric, and will return the last
	 * 'head' that references the non-head DIE.
	 *
	 * @param die {@link DebugInfoEntry} record
	 * @return never null
	 */
	private DebugInfoEntry getHead(DebugInfoEntry die, Map<Long, DebugInfoEntry> offsetMap2Head) {
		// Loop until the we don't find any more redirections in the offset2HeadMap.
		// This loop isn't endless because the lastmost DIE read will always
		// point to itself, ending the loop.
		while (true) {
			DebugInfoEntry tmp = offsetMap2Head.get(die.getOffset());
			if (tmp == die) {
				return die;
			}
			die = tmp;
		}
	}

	/**
	 * Iterates over all the DWARF DIE records in the program and checks for some
	 * pre-known issues, throwing an exception if there is a problem that would
	 * prevent a successful run.
	 *
	 * @param monitor {@link TaskMonitor} to check for cancel and upate with status.
	 * @throws DWARFException if DWARF structure error.
	 * @throws CancelledException if user cancels.
	 * @throws IOException if error reading data.
	 */
	public void checkPreconditions(TaskMonitor monitor)
			throws DWARFPreconditionException, DWARFException, CancelledException, IOException {
		monitor.setIndeterminate(false);
		monitor.setShowProgressValue(true);

		monitor.setMaximum(getCompilationUnits().size());

		if (getCompilationUnits().size() > 0 &&
			getCompilationUnits().get(0).getCompileUnit().hasDWO()) {
			// probably won't get anything from the file because its all in an external DWO
			Msg.warn(this,
				"Unsupported DWARF DWO (external debug file) detected -- unlikely any debug information will be found");
		}

		// This loop:
		// 1) preloads the DIEs if that option is set
		// 2) checks for cross-cu refs
		// 3) sums up the total number of DIE records found and updates prog with total.
		boolean preLoad = importOptions.isPreloadAllDIEs();
		totalDIECount = 0;
		totalAggregateCount = 0;
		clearDIEIndexes();
		for (DWARFCompilationUnit cu : getCompilationUnits()) {
			monitor.setMessage("DWARF Checking Preconditions - Compilation Unit #" +
				cu.getCompUnitNumber() + "/" + getCompilationUnits().size());
			monitor.setProgress(cu.getCompUnitNumber());

			cu.readDIEs(currentDIEs, monitor);

			if (totalDIECount > importOptions.getImportLimitDIECount() && !preLoad) {
				throw new DWARFPreconditionException(
					String.format(program.getName() + " has more DIE records (%d) than limit of %d",
						totalDIECount, importOptions.getImportLimitDIECount()));
			}

			if (!preLoad) {
				foundCrossCURefs |= checkForCrossCURefs(currentDIEs);
				totalDIECount += currentDIEs.size();
				totalAggregateCount += countAggregates();
				currentDIEs.clear();
				if (foundCrossCURefs) {
					throw new DWARFPreconditionException(
						"Found cross-compilation unit references between DIE records, but 'preload' is not turned on");
				}
			}

		}
		if (preLoad) {
			// build DIE indexes once
			rebuildDIEIndexes();
			this.totalAggregateCount = aggregates.size();
			this.totalDIECount = currentDIEs.size();
		}
	}

	/**
	 * Sets the maximum length of symbols and datatypes created during import.
	 *
	 * @param nameLenCutoff int, should not be more than {@link SymbolUtilities#MAX_SYMBOL_NAME_LENGTH}.
	 */
	public void setNameLengthCutoff(int nameLenCutoff) {
		this.nameLengthCutoffSize = nameLenCutoff;
	}

	/**
	 * A fixup value that needs to be applied to static addresses of the program.
	 * <p>
	 * This value is necessary if the program's built-in base address is overridden at import time.
	 * <p>
	 * @return long value to add to static addresses discovered in DWARF to make it agree with
	 * Ghidra's imported program.
	 */
	public long getProgramBaseAddressFixup() {
		return programBaseAddressFixup;
	}
}
