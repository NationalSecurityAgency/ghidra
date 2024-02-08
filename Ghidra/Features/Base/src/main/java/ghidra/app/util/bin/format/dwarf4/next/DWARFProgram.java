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

import java.io.*;
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.collections4.ListValuedMap;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.dwarf4.*;
import ghidra.app.util.bin.format.dwarf4.attribs.DWARFAttributeFactory;
import ghidra.app.util.bin.format.dwarf4.encoding.*;
import ghidra.app.util.bin.format.dwarf4.expression.DWARFExpressionException;
import ghidra.app.util.bin.format.dwarf4.external.ExternalDebugInfo;
import ghidra.app.util.bin.format.dwarf4.funcfixup.DWARFFunctionFixup;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.*;
import ghidra.app.util.bin.format.golang.rtti.GoSymbolName;
import ghidra.app.util.opinion.*;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.datastruct.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * DWARFProgram encapsulates a {@link Program Ghidra program} with DWARF specific reference data
 * used by {@link DWARFDataTypeImporter} and {@link DWARFFunctionImporter}, along with some
 * helper functions.
 */
public class DWARFProgram implements Closeable {
	public static final String DWARF_ROOT_NAME = "DWARF";
	public static final CategoryPath DWARF_ROOT_CATPATH = CategoryPath.ROOT.extend(DWARF_ROOT_NAME);
	public static final CategoryPath UNCAT_CATPATH = DWARF_ROOT_CATPATH.extend("_UNCATEGORIZED_");

	private static final int NAME_HASH_REPLACEMENT_SIZE = 8 + 2 + 2;
	private static final String ELLIPSES_STR = "...";

	/**
	 * Returns true if the {@link Program program} probably has DWARF information, without doing
	 * all the work that querying all registered DWARFSectionProviders would take.
	 * <p>
	 * If the program is an Elf binary, it must have (at least) ".debug_info" and ".debug_abbr",
	 * program sections, or their compressed "z" versions, or ExternalDebugInfo that would point
	 * to an external DWARF file.
	 * <p>
	 * If the program is a MachO binary (Mac), it must have a ".dSYM" directory co-located 
	 * next to the original binary file on the native filesystem (outside of Ghidra).  See the 
	 * DSymSectionProvider for more info.
	 * <p>
	 * @param program {@link Program} to test
	 * @return boolean true if program probably has DWARF info, false if not
	 */
	public static boolean isDWARF(Program program) {
		String format = Objects.requireNonNullElse(program.getExecutableFormat(), "");

		switch (format) {
			case ElfLoader.ELF_NAME:
			case PeLoader.PE_NAME:
				return hasExpectedDWARFSections(program) ||
					ExternalDebugInfo.fromProgram(program) != null;
			case MachoLoader.MACH_O_NAME:
				return hasExpectedDWARFSections(program) ||
					DSymSectionProvider.getDSYMForProgram(program) != null;
		}
		return false;
	}

	private static boolean hasExpectedDWARFSections(Program program) {
		// the compressed section provider will find normally named sections as well
		// as compressed sections
		try (DWARFSectionProvider tmp =
			new CompressedSectionProvider(new BaseSectionProvider(program))) {
			return tmp.hasSection(DWARFSectionNames.MINIMAL_DWARF_SECTIONS);
		}
	}

	/**
	 * Returns true if the specified {@link Program program} has DWARF information.
	 * <p>
	 * This is similar to {@link #isDWARF(Program)}, but is a stronger check that is more
	 * expensive as it could involve searching for external files.
	 * <p>
	 * 
	 * @param program {@link Program} to test
	 * @param monitor {@link TaskMonitor} that can be used to cancel
	 * @return boolean true if the program has DWARF info, false if not
	 */
	public static boolean hasDWARFData(Program program, TaskMonitor monitor) {
		if (!isDWARF(program)) {
			return false;
		}
		try (DWARFSectionProvider dsp =
			DWARFSectionProviderFactory.createSectionProviderFor(program, monitor)) {
			return dsp != null;
		}
	}

	private final Program program;
	private final DWARFDataTypeManager dwarfDTM;
	private DWARFNameInfo rootDNI = DWARFNameInfo.createRoot(DWARF_ROOT_CATPATH);
	private DWARFNameInfo unCatDataTypeRoot = DWARFNameInfo.createRoot(UNCAT_CATPATH);
	private DWARFImportOptions importOptions;
	private DWARFImportSummary importSummary;

	private DWARFSectionProvider sectionProvider;
	private StringTable debugStrings;
	private DWARFAttributeFactory attributeFactory;
	private int totalAggregateCount;
	private long programBaseAddressFixup;

	private int maxDNICacheSize = 50;
	private FixedSizeHashMap<Long, DWARFNameInfo> dniCache =
		new FixedSizeHashMap<>(100, maxDNICacheSize);

	private Map<DWARFAttributeSpecification, DWARFAttributeSpecification> attributeSpecIntern =
		new HashMap<>();

	private DWARFRegisterMappings dwarfRegisterMappings;
	private final boolean stackGrowsNegative;

	private List<DWARFFunctionFixup> functionFixups;
	private BinaryReader debugLocation;
	private BinaryReader debugRanges;
	private BinaryReader debugInfoBR;
	private BinaryReader debugLineBR;
	private BinaryReader debugAbbrBR;


	// dieOffsets, siblingIndexes, parentIndexes contain for each DIE the information needed 
	// to read each DIE and to navigate to parent / child / sibling elements.
	// Each DIE record in the binary will consume 8+4+4=16 bytes in ram in these indexes.
	// DIE instances do not keep references to other DIEs.
	protected long[] dieOffsets = new long[0]; // offset in the debuginfo stream of this DIE
	protected int[] siblingIndexes = new int[0]; // index of each DIE's next sibling.
	protected int[] parentIndexes = new int[0]; // index of each DIE's parent record, or -1 for root

	// DIE index -> compunit lookup.  Each key in the map is the index of the last DIE of a
	// compunit.  Querying the map for the ceilingEntry() of a DIE's index will return
	// the compunit for that DIE.
	protected TreeMap<Integer, DWARFCompilationUnit> compUnitDieIndex = new TreeMap<>();
	protected List<DWARFCompilationUnit> compUnits = new ArrayList<>();

	// boolean flag, per die record, indicating that the DIE is the target of another DIE via
	// an aggregate reference, and therefore not the root DIE record of an aggregate. 
	protected BitSet indexHasRef = new BitSet();

	// Cache of DIE and DIEAggregate instances.  If needed instance is not found (because of
	// gc), it will be re-read / re-created and placed back into the map.
	protected WeakValueHashMap<Long, DebugInfoEntry> diesByOffset = new WeakValueHashMap<>();
	private WeakValueHashMap<Long, DIEAggregate> aggsByOffset = new WeakValueHashMap<>();

	// Map of DIE offsets of {@link DIEAggregate}s that are being pointed to by
	// other {@link DIEAggregate}s with a DW_AT_type property.
	// In other words, a map of inbound links to a DIEA.
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
			DWARFSectionProviderFactory.createSectionProviderFor(program, monitor));
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
			DWARFSectionProvider sectionProvider) throws CancelledException, IOException {
		if (sectionProvider == null) {
			throw new IllegalArgumentException("Null DWARFSectionProvider");
		}

		this.program = program;
		this.sectionProvider = sectionProvider;
		this.importOptions = importOptions;
		this.importSummary = new DWARFImportSummary();
		this.dwarfDTM = new DWARFDataTypeManager(this, program.getDataTypeManager());
		this.stackGrowsNegative = program.getCompilerSpec().stackGrowsNegative();
		this.attributeFactory = new DWARFAttributeFactory(this);

		this.debugLocation = getBinaryReaderFor(DWARFSectionNames.DEBUG_LOC, monitor);
		this.debugInfoBR = getBinaryReaderFor(DWARFSectionNames.DEBUG_INFO, monitor);
		this.debugLineBR = getBinaryReaderFor(DWARFSectionNames.DEBUG_LINE, monitor);
		this.debugAbbrBR = getBinaryReaderFor(DWARFSectionNames.DEBUG_ABBREV, monitor);
		this.debugRanges = getBinaryReaderFor(DWARFSectionNames.DEBUG_RANGES, monitor);

		// if there are relocations (already handled by the ghidra loader) anywhere in the 
		// debuginfo or debugrange sections, then we don't need to manually fix up addresses
		// extracted from DWARF data.
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
	}

	/**
	 * Reads and indexes available DWARF information.
	 * 
	 * @param monitor {@link TaskMonitor}
	 * @throws IOException if error reading data
	 * @throws DWARFException if bad or invalid DWARF information
	 * @throws CancelledException if cancelled
	 */
	public void init(TaskMonitor monitor) throws IOException, DWARFException, CancelledException {
		monitor.setMessage("DWARF: Reading string table");
		this.debugStrings = StringTable.readStringTable(
			sectionProvider.getSectionAsByteProvider(DWARFSectionNames.DEBUG_STR, monitor));

		bootstrapCompilationUnits(monitor);

		LongArrayList dieOffsetList = new LongArrayList();
		IntArrayList siblingIndexList = new IntArrayList();
		IntArrayList parentIndexList = new IntArrayList();
		LongArrayList aggrTargets = new LongArrayList();

		monitor.initialize(debugInfoBR.length(), "DWARF: Indexing records");
		for (DWARFCompilationUnit cu : compUnits) {
			debugInfoBR.setPointerIndex(cu.getFirstDIEOffset());
			monitor.setMessage("DWARF: Indexing records - Compilation Unit #%d/%d"
					.formatted(cu.getCompUnitNumber() + 1, compUnits.size()));
			indexDIEsForCU(cu, dieOffsetList, parentIndexList, siblingIndexList, aggrTargets, monitor);
			compUnitDieIndex.put(dieOffsetList.size() - 1, cu);
		}

		dieOffsets = dieOffsetList.toLongArray();
		siblingIndexes = siblingIndexList.toArray();
		parentIndexes = parentIndexList.toArray();

		indexDIEAggregates(aggrTargets, monitor); // after this point, DIEAggregates are functional
		int nonHeadCount = indexHasRef.cardinality();
		totalAggregateCount = dieOffsetList.size() - nonHeadCount;

		indexDIEATypeRefs(monitor);

		Msg.info(this,
			"DWARF: %d compile units, %d DIEs".formatted(compUnits.size(), dieOffsets.length));
	}

	protected void indexDIEATypeRefs(TaskMonitor monitor) throws CancelledException {
		monitor.initialize(totalAggregateCount, "DWARF: Indexing Type References");
		for (DIEAggregate diea : allAggregates()) {
			monitor.increment();
			DIEAggregate typeRef = diea.getTypeRef();
			if (typeRef != null) {
				typeReferers.put(typeRef.getOffset(), diea);
			}
		}

	}

	protected void indexDIEAggregates(LongArrayList aggrTargets, TaskMonitor monitor)
			throws CancelledException, DWARFException {
		monitor.initialize(aggrTargets.size(), "DWARF: Indexing DIE Aggregates");
		for (long aggrTargetOffset : aggrTargets) {
			monitor.increment();
			int dieIndex = getDIEIndex(aggrTargetOffset);
			if (dieIndex < 0) {
				throw new DWARFException();
			}
			indexHasRef.set(dieIndex);
		}
	}

	private void bootstrapCompilationUnits(TaskMonitor monitor)
			throws CancelledException, IOException, DWARFException {

		debugInfoBR.setPointerIndex(0);
		monitor.initialize(debugInfoBR.length(), "DWARF: Bootstrapping Compilation Units");
		while (debugInfoBR.hasNext()) {
			monitor.checkCancelled();
			monitor.setProgress(debugInfoBR.getPointerIndex());
			monitor.setMessage("DWARF: Bootstrapping Compilation Unit #" + compUnits.size());

			DWARFCompilationUnit cu = DWARFCompilationUnit.readCompilationUnit(this, debugInfoBR,
				debugAbbrBR, compUnits.size(), monitor);

			if (cu != null) {
				compUnits.add(cu);
				debugInfoBR.setPointerIndex(cu.getEndOffset());
			}
		}
	}

	private void indexDIEsForCU(DWARFCompilationUnit cu, LongArrayList dieOffsetList,
			IntArrayList parentIndexList, IntArrayList siblingIndexList,
			LongArrayList aggrTargets, TaskMonitor monitor) throws CancelledException {
		long endOffset = cu.getEndOffset();

		int perCuDieCount = 0;
		int parentIndex = -1;
		long unexpectedTerminator = -1;
		while (debugInfoBR.getPointerIndex() < endOffset) {

			long startOfDIE = debugInfoBR.getPointerIndex();
			monitor.setProgress(startOfDIE);
			monitor.setMessage("DWARF: Indexing Compilation Unit #" + compUnits.size());
			monitor.checkCancelled();

			try {
				int dieIndex = dieOffsetList.size();
				DebugInfoEntry die =
					DebugInfoEntry.read(debugInfoBR, cu, dieIndex, attributeFactory);

				if (die.isTerminator()) {
					if (parentIndex == -1) {
						unexpectedTerminator = startOfDIE;
						continue;
					}
					parentIndex = parentIndexList.get(parentIndex);
					continue;
				}
				if (unexpectedTerminator != -1) {
					// if we run into a non-terminator die after hitting a terminator, throw error
					throw new DWARFException(
						"Unexpected terminator entry at 0x%x".formatted(unexpectedTerminator));
				}
				if (parentIndex == -1 && perCuDieCount != 0 /* first die of CU */) {
					throw new DWARFException(
						"Unexpected root level DIE at 0x%x".formatted(startOfDIE));
				}

				dieOffsetList.add(startOfDIE);
				parentIndexList.add(parentIndex);
				siblingIndexList.add(dieIndex + 1);
				perCuDieCount++;

				updateSiblingIndexes(siblingIndexList, parentIndexList, dieIndex);

				if (die.getAbbreviation().hasChildren()) {
					parentIndex = dieIndex;
				}

				DIEAggregate diea = DIEAggregate.createSingle(die);
				for (int attr : DIEAggregate.REF_ATTRS) {
					long refdOffset = diea.getUnsignedLong(attr, -1);
					if (refdOffset != -1) {
						aggrTargets.add(refdOffset);
					}
				}

				diesByOffset.put(startOfDIE, die);
			}
			catch (IOException e) {
				Msg.error(this,
					"Failed to read DIE at offset 0x%x in compunit %d (at 0x%x), skipping remainder of compilation unit."
							.formatted(startOfDIE, cu.getCompUnitNumber(), cu.getStartOffset()),
					e);
				debugInfoBR.setPointerIndex(endOffset);
			}
		}

	}

	protected void updateSiblingIndexes(IntArrayList siblingIndexList, IntArrayList parentIndexList,
			int index) {
		int x = siblingIndexList.size();
		while (index != -1) {
			siblingIndexList.set(index, x);
			index = parentIndexList.get(index);
		}
	}

	@Override
	public void close() throws IOException {
		if (sectionProvider != null) {
			sectionProvider.close();
		}
		if (debugStrings != null) {
			debugStrings.clear();
		}
		compUnits.clear();
		dniCache.clear();

		debugAbbrBR = null;
		debugInfoBR = null;
		debugLineBR = null;
		debugLocation = null;
		debugRanges = null;

		dieOffsets = new long[0];
		parentIndexes = new int[0];
		siblingIndexes = new int[0];
		indexHasRef.clear();
		aggsByOffset.clear();
		diesByOffset.clear();
		typeReferers.clear();
		compUnitDieIndex.clear();

		if (functionFixups != null) {
			for (DWARFFunctionFixup funcFixup : functionFixups) {
				if (funcFixup instanceof Closeable c) {
					FSUtilities.uncheckedClose(c, null);
				}
			}
			functionFixups.clear();
			functionFixups = null;
		}
	}

	public DWARFImportOptions getImportOptions() {
		return importOptions;
	}

	public DWARFImportSummary getImportSummary() {
		return importSummary;
	}

	public Program getGhidraProgram() {
		return program;
	}

	public DWARFDataTypeManager getDwarfDTM() {
		return dwarfDTM;
	}

	public boolean isBigEndian() {
		return program.getLanguage().isBigEndian();
	}

	public boolean isLittleEndian() {
		return !program.getLanguage().isBigEndian();
	}

	private BinaryReader getBinaryReaderFor(String sectionName, TaskMonitor monitor)
			throws IOException {
		ByteProvider bp = sectionProvider.getSectionAsByteProvider(sectionName, monitor);
		return (bp != null) ? new BinaryReader(bp, isLittleEndian()) : null;
	}

	private boolean hasRelocations(BinaryReader br) {
		if (br == null) {
			return false;
		}
		ByteProvider bp = br.getByteProvider();
		if (bp instanceof MemoryByteProvider mbp && !mbp.isEmpty()) {
			if (program.getRelocationTable().getRelocations(mbp.getAddressSet()).hasNext()) {
				return true;
			}
		}
		return false;
	}

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

	/*
	 * Returns the string path of a DWARF entry.
	 * <p>
	 * Always returns a name for the passed-in entry, but you should probably only use this
	 * for entries that are {@link DIEAggregate#isNamedType()}
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

		if (name == null && diea.isStructureType()) {
			String fingerprint = DWARFUtil.getStructLayoutFingerprint(diea);

			// check to see if there are struct member defs that ref this anon type
			// and build a name using the field names
			List<DIEAggregate> referringMembers =
				diea.getProgram().getTypeReferers(diea, DWARFTag.DW_TAG_member);

			String referringMemberNames = getReferringMemberFieldNames(referringMembers);
			if (!referringMemberNames.isEmpty()) {
				// this re-homes this anon struct def from the root of the compunit to the
				// structure that is using this anon struct def.
				parentDNI = getName(referringMembers.get(0).getParent());
				referringMemberNames = "_for_" + referringMemberNames;
			}
			name =
				"anon_" + DWARFUtil.getContainerTypeName(diea) + "_" + fingerprint +
					referringMemberNames;
			return parentDNI.createChild(null, name, DWARFUtil.getSymbolTypeFromDIE(diea));
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
					name = "param_%d".formatted(diea.getHeadFragment().getPositionInParent());
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
		workingName = GoSymbolName.fixGolangSpecialSymbolnameChars(workingName);

		if (diea.getCompilationUnit()
				.getCompileUnit()
				.getLanguage() == DWARFSourceLanguage.DW_LANG_Rust &&
			workingName.startsWith("{impl#") && parentDNI != null) {
			// if matches a Rust {impl#NN} name, skip it and re-use the parent name
			return parentDNI;
		}

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

	private String getReferringMemberFieldNames(List<DIEAggregate> referringMembers) {
		if (referringMembers == null || referringMembers.isEmpty()) {
			return "";
		}
		DIEAggregate commonParent = referringMembers.get(0).getParent();
		StringBuilder result = new StringBuilder();
		for (DIEAggregate referringMember : referringMembers) {
			if (commonParent != referringMember.getParent()) {
				// if there is an inbound referring link that isn't from the same parent,
				// abort
				return "";
			}
			String memberName = referringMember.getName();
			if (memberName == null) {
				int positionInParent = referringMember.getHeadFragment().getPositionInParent();
				if (positionInParent == -1) {
					continue;
				}
				DWARFNameInfo parentDNI = getName(commonParent);
				memberName = "%s_%d".formatted(parentDNI.getName(), positionInParent);
			}
			if (result.length() > 0) {
				result.append("_");
			}
			result.append(memberName);
		}
		return result.toString();
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
	 * @param s data type name
	 * @return transformed data type name
	 */
	private static String abbrevTemplateName(String s) {
		int startBracket = s.indexOf('<');
		int endBracket = s.lastIndexOf('>');
		if (startBracket + NAME_HASH_REPLACEMENT_SIZE < endBracket) {
			String templateParams = s.substring(startBracket, endBracket);
			return "%s$%x$%s".formatted(s.substring(0, startBracket + 1), templateParams.hashCode(),
				s.substring(endBracket));
		}
		return s;
	}

	private String ensureSafeNameLength(String s) {
		if (s.length() <= SymbolUtilities.MAX_SYMBOL_NAME_LENGTH) {
			return s;
		}
		s = abbrevTemplateName(s);
		if (s.length() <= SymbolUtilities.MAX_SYMBOL_NAME_LENGTH) {
			return s;
		}
		int prefixKeepLength = SymbolUtilities.MAX_SYMBOL_NAME_LENGTH - ELLIPSES_STR.length() -
			NAME_HASH_REPLACEMENT_SIZE;
		return "%s%s$%x$".formatted(s.substring(0, prefixKeepLength), ELLIPSES_STR, s.hashCode());
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

	private DWARFNameInfo lookupDNIByOffset(long offset) {
		DWARFNameInfo tmp = dniCache.get(offset);
		return tmp;
	}

	private void cacheDNIByOffset(long offset, DWARFNameInfo dni) {
		dniCache.put(offset, dni);
	}

	/**
	 * Returns the parent DIE of the specified (by index) DIE
	 * 
	 * @param dieIndex index of a DIE record
	 * @return parent DIE, or null if no parent (eg. root DIE)
	 */
	public DebugInfoEntry getParentOf(int dieIndex) {
		int parentIndex = parentIndexes[dieIndex];
		return parentIndex >= 0 ? getDIEByIndex(parentIndex) : null;
	}

	/**
	 * Returns the index of the parent of the specified DIE.
	 * 
	 * @param dieIndex index of a DIE record
	 * @return index of the parent of specified DIE, or -1 if no parent (eg. root DIE)
	 */
	public int getParentIndex(int dieIndex) {
		return parentIndexes[dieIndex];
	}

	/**
	 * Returns the depth of the specified DIE.
	 * 
	 * @param dieIndex index of a DIE record
	 * @return parent/child depth of specified record, where 0 is the root DIE
	 */
	public int getParentDepth(int dieIndex) {
		int depth = 0;
		while (dieIndex != -1) {
			dieIndex = parentIndexes[dieIndex];
			depth++;
		}
		return depth - 1;
	}

	/**
	 * Returns the children of the specified DIE
	 * 
	 * @param dieIndex index of a DIE record
	 * @return list of DIE instances that are children of the specified DIE
	 */
	public List<DebugInfoEntry> getChildrenOf(int dieIndex) {
		IntArrayList childIndexes = getDIEChildIndexes(dieIndex);
		if (childIndexes.isEmpty()) {
			return List.of();
		}
		List<DebugInfoEntry> result = new ArrayList<>(childIndexes.size());
		for (int i = 0; i < childIndexes.size(); i++) {
			result.add(getDIEByIndex(childIndexes.get(i)));
		}
		return result;
	}

	/**
	 * Returns list of indexes of the children of the specified DIE
	 * 
	 * @param dieIndex index of a DIE record
	 * @return list of DIE indexes that are children of the specified DIE
	 */
	public IntArrayList getDIEChildIndexes(int dieIndex) {
		IntArrayList result = new IntArrayList(true);
		if (dieIndex >= 0) {
			int parentSiblingIndex = siblingIndexes[dieIndex];
			for (int index = dieIndex + 1; index < parentSiblingIndex; index =
				siblingIndexes[index]) {
				result.add(index);
			}
		}
		return result;
	}

	private DWARFCompilationUnit getCompilationUnitForDIE(int dieIndex) {
		Entry<Integer, DWARFCompilationUnit> entry = compUnitDieIndex.ceilingEntry(dieIndex);
		return entry != null ? entry.getValue() : null;
	}

	/**
	 * Returns the specified DIE record.
	 * 
	 * @param dieOffset offset of a DIE record
	 * @return {@link DebugInfoEntry} instance, or null if invalid offset
	 */
	public DebugInfoEntry getDIEByOffset(long dieOffset) {
		DebugInfoEntry die = diesByOffset.get(dieOffset);
		if (die != null) {
			return die;
		}
		int dieIndex = getDIEIndex(dieOffset);
		return getDIEByOffset(dieOffset, dieIndex);
	}

	private DebugInfoEntry getDIEByOffset(long dieOffset, int dieIndex) {
		if (dieOffset == -1 || dieIndex == -1) {
			return null;
		}

		DebugInfoEntry die = diesByOffset.get(dieOffset);
		if (die == null) {
			try {
				debugInfoBR.setPointerIndex(dieOffset);
				DWARFCompilationUnit cu = getCompilationUnitForDIE(dieIndex);
				if (dieOffset < cu.getFirstDIEOffset() || cu.getEndOffset() < dieOffset) {
					throw new RuntimeException();
				}
				die = DebugInfoEntry.read(debugInfoBR, cu, dieIndex, attributeFactory);
				diesByOffset.put(dieOffset, die);
			}
			catch (IOException e) {
				// shouldn't happen, will fall thru and return null
			}
		}
		return die;
	}

	private int getDIEIndex(long dieOffset) {
		DebugInfoEntry die = diesByOffset.get(dieOffset);
		if (die != null) {
			return die.getIndex();
		}
		int index = Arrays.binarySearch(dieOffsets, dieOffset);
		return index >= 0 ? index : -1;
	}

	private DebugInfoEntry getDIEByIndex(int dieIndex) {
		long dieOffset =
			0 <= dieIndex && dieIndex < dieOffsets.length ? dieOffsets[dieIndex] : -1;
		return getDIEByOffset(dieOffset, dieIndex);
	}

	public void dumpDIEs(PrintStream ps) {
		for (int dieIndex = 0; dieIndex < dieOffsets.length; dieIndex++) {
			DebugInfoEntry die = getDIEByIndex(dieIndex);
			ps.append(die.toString());
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
		DIEAggregate diea = (die != null) ? aggsByOffset.get(die.getOffset()) : null;
		if (diea == null && die != null) {
			diea = DIEAggregate.createFromHead(die);
			aggsByOffset.put(die.getOffset(), diea);
		}
		return diea;
	}

	private DIEAggregate getAggregateByIndex(int dieIndex) {
		DebugInfoEntry die = getDIEByIndex(dieIndex);
		return getAggregate(die);
	}

	/**
	 * Returns the {@link DIEAggregate} that contains the {@link DebugInfoEntry} specified
	 * by the offset.
	 *
	 * @param dieOffset offset of a DIE record
	 * @return {@link DIEAggregate} that contains the DIE record specified, or null if bad
	 * offset.
	 */
	public DIEAggregate getAggregate(long dieOffset) {
		DIEAggregate diea = aggsByOffset.get(dieOffset);
		if (diea != null) {
			return diea;
		}
		DebugInfoEntry die = getDIEByOffset(dieOffset);
		return getAggregate(die);
	}

	/**
	 * Returns iterable that traverses all {@link DIEAggregate}s in the program. 
	 *
	 * @return sequence of {@link DIEAggregate}es
	 */
	public Iterable<DIEAggregate> allAggregates() {
		return new DIEAggregateIterator();
	}

	/**
	 * Returns the total number of {@link DIEAggregate} objects in the entire program.
	 *
	 * @return the total number of {@link DIEAggregate} objects in the entire program.
	 */
	public int getTotalAggregateCount() {
		return totalAggregateCount;
	}

	public BinaryReader getDebugLocation() {
		return debugLocation;
	}

	public BinaryReader getDebugRanges() {
		return debugRanges;
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

	public void setDebugStrings(StringTable debugStrings) {
		this.debugStrings = debugStrings;
	}

	public AddressSpace getStackSpace() {
		return program.getAddressFactory().getStackSpace();
	}

	public DWARFAttributeFactory getAttributeFactory() {
		return attributeFactory;
	}

	public void setAttributeFactory(DWARFAttributeFactory attributeFactory) {
		this.attributeFactory = attributeFactory;
	}

	public DWARFAttributeSpecification internAttributeSpec(DWARFAttributeSpecification das) {
		DWARFAttributeSpecification inDAS = attributeSpecIntern.get(das);
		if (inDAS == null) {
			inDAS = das;
			attributeSpecIntern.put(inDAS, inDAS);
		}
		return inDAS;
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

	public Address getCodeAddress(Number offset) {
		return program.getAddressFactory()
				.getDefaultAddressSpace()
				.getAddress(offset.longValue(), true);
	}

	public Address getDataAddress(Number offset) {
		return program.getAddressFactory()
				.getDefaultAddressSpace()
				.getAddress(offset.longValue(), true);
	}

	public boolean stackGrowsNegative() {
		return stackGrowsNegative;
	}

	public List<DWARFFunctionFixup> getFunctionFixups() {
		if (functionFixups == null) {
			functionFixups = DWARFFunctionFixup.findFixups();
		}
		return functionFixups;
	}

	//---------------------------------------------------------------------------------------------

	private class DIEAggregateIterator implements Iterator<DIEAggregate>, Iterable<DIEAggregate> {

		private int index = -1;

		private int findNext() {
			int i = index;
			if (i < dieOffsets.length) {
				for (i = i + 1; i < dieOffsets.length; i++) {
					if (!indexHasRef.get(i)) {
						return i;
					}
				}
			}
			return i;
		}

		@Override
		public Iterator<DIEAggregate> iterator() {
			return this;
		}

		@Override
		public boolean hasNext() {
			if (index == -1) {
				index = findNext();
			}
			return 0 <= index && index < dieOffsets.length;
		}

		@Override
		public DIEAggregate next() {
			if (!hasNext()) {
				throw new NoSuchElementException();
			}
			int resultIndex = index;
			index = findNext();
			return getAggregateByIndex(resultIndex);
		}

	}
}
