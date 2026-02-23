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
package ghidra.app.util.bin.format.dwarf;

import static ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeId.*;
import static ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionId.*;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.Charset;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Predicate;

import org.apache.commons.collections4.ListValuedMap;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.dwarf.attribs.*;
import ghidra.app.util.bin.format.dwarf.line.DWARFLine;
import ghidra.app.util.bin.format.dwarf.macro.DWARFMacroHeader;
import ghidra.app.util.bin.format.dwarf.macro.entry.DWARFMacroInfoEntry;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionId;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProvider;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.datastruct.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Provides access to a set of DIE records (and associated bits and bobs)
 */
public class DIEContainer implements Iterable<DebugInfoEntry> {
	protected static final EnumSet<DWARFAttributeId> REF_ATTRS =
		EnumSet.of(DW_AT_abstract_origin, DW_AT_specification);

	protected DWARFProgram dprog;
	protected DWARFSectionProvider sectionProvider;

	protected Map<Long, Map<Integer, DWARFAbbreviation>> abbrCache = new HashMap<>();

	// dieOffsets, siblingIndexes, parentIndexes contain for each DIE the information needed 
	// to read each DIE and to navigate to parent / child / sibling elements.
	// Each DIE record in the binary will consume 8+4+4=16 bytes of ram in these indexes.
	// DIE instances do not keep references to other DIEs.
	protected long[] dieOffsets = new long[0]; // offset in the debuginfo stream of this DIE
	protected int[] siblingIndexes = new int[0]; // index of each DIE's next sibling.
	protected int[] parentIndexes = new int[0]; // index of each DIE's parent record, or -1 for root

	// DIE index -> compunit lookup.  Each key in the map is the index of the last DIE of a
	// compunit.  Querying the map for the ceilingEntry() of a DIE's index will return
	// the compunit for that DIE.
	protected TreeMap<Integer, DWARFCompilationUnit> compUnitDieIndex = new TreeMap<>();
	protected List<DWARFCompilationUnit> compUnits = new ArrayList<>();

	// Indirect tables, added with dwarf v5, provide an index -> offset lookup feature for 
	// index values such as DW_FORM_addrx or DW_FORM_strx and other similar 'x' attribute values.
	// Each DWARFIndirectTable is made of per-CU lookup arrays held in a DWARFIndirectTableHeader.  
	protected DWARFIndirectTable addressListTable; // DWARFAddressListHeaders, DW_AT_addr_base
	protected DWARFIndirectTable locationListTable; // DWARFLocationListHeaders, DW_AT_rgnlists_base
	protected DWARFIndirectTable rangeListTable; // DWARFRangeListHeaders, DW_AT_rgnlists_base
	protected DWARFIndirectTable stringsOffsetTable; // DWARFStringOffsetTableHeader, DW_AT_str_offsets_base

	// boolean flag, per die record, indicating that the DIE is the target of another DIE via
	// an aggregate reference, and therefore not the root DIE record of an aggregate. 
	protected BitSet indexHasRef = new BitSet();

	// Cache of DIE and DIEAggregate instances.  If needed instance is not found (because of
	// gc), it will be re-read / re-created and placed back into the map.
	protected WeakValueHashMap<Long, DebugInfoEntry> diesByOffset = new WeakValueHashMap<>();
	protected WeakValueHashMap<Long, DIEAggregate> aggsByOffset = new WeakValueHashMap<>();

	// Map of DIE offsets of DIEAggregates that are being pointed to by
	// other DIEAggregates with a DW_AT_type property.
	// In other words, a map of inbound links to a DIEA.
	protected ListValuedMap<Long, Long> typeReferers = new ArrayListValuedHashMap<>();

	protected int totalAggregateCount;

	protected StringTable debugStrings;
	protected StringTable lineStrings;

	protected Map<Long, DWARFLine> cachedDWARFLines = new HashMap<>();

	// BinaryReaders for each of the various dwarf sections
	protected BinaryReader debugLocation;
	protected BinaryReader debugLocLists;	// v5+
	protected BinaryReader debugRanges;
	protected BinaryReader debugRngLists; // v5+
	protected BinaryReader debugInfoBR;
	protected BinaryReader debugLineBR;
	protected BinaryReader debugAbbrBR;
	protected BinaryReader debugAddr; // v5+
	protected BinaryReader debugStrOffsets; // v5+
	protected BinaryReader debugMacros; // v5+

	protected DWARFImportSummary importSummary;

	public DIEContainer(DWARFProgram dprog) {
		this.dprog = dprog;
		this.sectionProvider = dprog.getSectionProvider();
		this.importSummary = dprog.getImportSummary();
	}

	/**
	 * Fetches required sections and sets up variables.
	 * 
	 * @param monitor {@link TaskMonitor}
	 * @throws IOException if error
	 */
	public void init(TaskMonitor monitor) throws IOException {
		this.debugInfoBR = getReader(DEBUG_INFO, monitor);
		this.debugAbbrBR = getReader(DEBUG_ABBREV, monitor);

		this.debugLocation = getReader(DEBUG_LOC, monitor);
		this.debugLocLists = getReader(DEBUG_LOCLISTS, monitor);

		this.debugRanges = getReader(DEBUG_RANGES, monitor);
		this.debugRngLists = getReader(DEBUG_RNGLISTS, monitor);

		this.debugLineBR = getReader(DEBUG_LINE, monitor);
		this.debugAddr = getReader(DEBUG_ADDR, monitor);
		this.debugStrOffsets = getReader(DEBUG_STROFFSETS, monitor);

		this.debugMacros = getReader(DEBUG_MACRO, monitor);

		this.rangeListTable =
			new DWARFIndirectTable(this.debugRngLists, DWARFCompilationUnit::getRangeListsBase);
		this.addressListTable =
			new DWARFIndirectTable(this.debugAddr, DWARFCompilationUnit::getAddrTableBase);
		this.stringsOffsetTable =
			new DWARFIndirectTable(this.debugStrOffsets, DWARFCompilationUnit::getStrOffsetsBase);
		this.locationListTable =
			new DWARFIndirectTable(this.debugLocLists, DWARFCompilationUnit::getLocListsBase);

		Charset charset = dprog.getCharset();
		this.debugStrings = StringTable.of(getReader(DEBUG_STR, monitor), charset);
		this.lineStrings = StringTable.of(getReader(DEBUG_LINE_STR, monitor), charset);

		// if there are relocations (already handled by the ghidra loader) anywhere in the 
		// debuginfo or debugrange sections, then we don't need to manually fix up addresses
		// extracted from DWARF data.
		// TODO: probably only needed for local section provider
		boolean hasRelocations = hasRelocations(debugInfoBR) || hasRelocations(debugRanges);
		if (!hasRelocations) {
			Program prog = dprog.getGhidraProgram();
			Long oib = ElfLoader.getElfOriginalImageBase(prog);
			if (oib != null && oib.longValue() != prog.getImageBase().getOffset()) {
				dprog.setProgramBaseAddressFixup(prog.getImageBase().getOffset() - oib.longValue());
			}
		}
	}

	/**
	 * Reads and indexes the DIE records found in the section.
	 * 
	 * @param monitor {@link TaskMonitor}
	 * @throws CancelledException if cancelled
	 * @throws DWARFException if error
	 * @throws IOException if error
	 */
	public void indexData(TaskMonitor monitor)
			throws CancelledException, DWARFException, IOException {
		bootstrapCompilationUnits(monitor);

		int defaultIntSize = dprog.getDefaultIntSize();
		rangeListTable.bootstrap("DWARF: Bootstrapping Range Lists",
			reader -> DWARFRangeListHeader.read(reader, defaultIntSize), monitor);
		locationListTable.bootstrap("DWARF: Bootstrapping Location Lists",
			reader -> DWARFLocationListHeader.read(reader, defaultIntSize), monitor);
		addressListTable.bootstrap("DWARF: Bootstrapping Address Lists",
			reader -> DWARFAddressListHeader.read(reader, defaultIntSize), monitor);
		stringsOffsetTable.bootstrap("DWARF: Bootstrapping String Offset Lists",
			reader -> DWARFStringOffsetTableHeader.readV5(reader, defaultIntSize), monitor);

		indexDIEs(monitor);
		indexDIEATypeRefs(monitor);

		importSummary.addCompunitInfo(compUnits);
	}

	public void close() {
		if (debugStrings != null) {
			debugStrings.clear();
			debugStrings = null;
		}
		if (lineStrings != null) {
			lineStrings.clear();
			lineStrings = null;
		}
		compUnits.clear();

		debugAbbrBR = null;
		debugInfoBR = null;
		debugLineBR = null;
		debugLocation = null;
		debugLocLists = null;
		debugRanges = null;
		debugRngLists = null;
		debugAddr = null;

		dieOffsets = new long[0];
		parentIndexes = new int[0];
		siblingIndexes = new int[0];
		indexHasRef.clear();
		aggsByOffset.clear();
		diesByOffset.clear();
		typeReferers.clear();
		compUnitDieIndex.clear();

		locationListTable.clear();
		rangeListTable.clear();
		stringsOffsetTable.clear();
		addressListTable.clear();
	}

	private BinaryReader getReader(DWARFSectionId section, TaskMonitor monitor) throws IOException {
		ByteProvider bp =
			sectionProvider.getSectionAsByteProvider(section.getSectionName(), monitor);
		return (bp != null) ? new BinaryReader(bp, dprog.isLittleEndian()) : null;
	}

	private boolean hasRelocations(BinaryReader br) {
		if (br == null) {
			return false;
		}
		ByteProvider bp = br.getByteProvider();
		if (bp instanceof MemoryByteProvider mbp && !mbp.isEmpty()) {
			Program providerProgram = mbp.getMemory().getProgram();
			if (providerProgram.getRelocationTable()
					.getRelocations(mbp.getAddressSet())
					.hasNext()) {
				return true;
			}
		}
		return false;
	}

	private void bootstrapCompilationUnits(TaskMonitor monitor)
			throws CancelledException, IOException, DWARFException {

		debugInfoBR.setPointerIndex(0);
		monitor.initialize(debugInfoBR.length(), "DWARF: Bootstrapping Compilation Units");
		while (debugInfoBR.hasNext()) {
			monitor.checkCancelled();
			monitor.setProgress(debugInfoBR.getPointerIndex());
			monitor.setMessage("DWARF: Bootstrapping Compilation Unit #" + compUnits.size());

			DWARFUnitHeader unitHeader = DWARFUnitHeader.read(this, debugInfoBR, compUnits.size());
			if (unitHeader == null) {
				break;
			}

			debugInfoBR.setPointerIndex(unitHeader.getEndOffset());
			if (unitHeader instanceof DWARFCompilationUnit cu) {
				compUnits.add(cu);
				importSummary.dwarfVers.add((int) cu.getDWARFVersion());
			}
			else {
				Msg.info(this, "Unsupported unit header: " + unitHeader + " at " +
					unitHeader.getStartOffset());
			}
		}
		importSummary.compUnitCount = compUnits.size();
	}

	private void indexDIEs(TaskMonitor monitor) throws CancelledException, IOException {
		LongArrayList dieOffsetList = new LongArrayList();
		IntArrayList siblingIndexList = new IntArrayList();
		IntArrayList parentIndexList = new IntArrayList();
		LongArrayList aggrTargets = new LongArrayList();

		monitor.initialize(debugInfoBR.length(), "DWARF: Indexing records");
		for (DWARFCompilationUnit cu : compUnits) {
			debugInfoBR.setPointerIndex(cu.getFirstDIEOffset());
			monitor.setMessage("DWARF: Indexing records - Compilation Unit #%d/%d"
					.formatted(cu.getUnitNumber() + 1, compUnits.size()));
			indexDIEsForCU(cu, dieOffsetList, parentIndexList, siblingIndexList, aggrTargets,
				monitor);
			compUnitDieIndex.put(dieOffsetList.size() - 1, cu);
		}

		dieOffsets = dieOffsetList.toLongArray();
		siblingIndexes = siblingIndexList.toArray();
		parentIndexes = parentIndexList.toArray();

		indexDIEAggregates(aggrTargets, monitor); // after this point, DIEAggregates are functional
		int nonHeadCount = indexHasRef.cardinality();
		totalAggregateCount = dieOffsetList.size() - nonHeadCount;

		importSummary.dieCount = dieOffsets.length;
	}

	protected void indexDIEATypeRefs(TaskMonitor monitor) throws CancelledException {
		monitor.initialize(totalAggregateCount, "DWARF: Indexing Type References");
		for (DIEAggregate diea : allAggregates()) {
			monitor.increment();
			DIEAggregate typeRef = diea.getTypeRef();
			if (typeRef != null) {
				typeReferers.put(typeRef.getOffset(), diea.getOffset());
			}
		}
		monitor.initialize(0, "");
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

	private void indexDIEsForCU(DWARFCompilationUnit cu, LongArrayList dieOffsetList,
			IntArrayList parentIndexList, IntArrayList siblingIndexList, LongArrayList aggrTargets,
			TaskMonitor monitor) throws CancelledException, DWARFException {
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
				DebugInfoEntry die = DebugInfoEntry.read(debugInfoBR, cu, dieIndex);

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

				if (die.getOffset() == cu.getFirstDIEOffset()) {
					cu.init(die);
				}

				DIEAggregate diea = DIEAggregate.createSingle(die);
				for (DWARFAttributeId attrId : REF_ATTRS) {
					DWARFAttribute refAttr = diea.findAttribute(attrId);
					if (refAttr != null &&
						refAttr.getValue() instanceof DWARFNumericAttribute refVal) {
						long refdOffset = getLocalDIEOffset(refAttr.getAttributeForm(),
							refVal.getUnsignedValue(), cu);
						aggrTargets.add(refdOffset);
					}
				}

				diesByOffset.put(startOfDIE, die);
			}
			catch (DWARFException e) {
				throw e;
			}
			catch (IOException e) {
				Msg.error(this,
					"Failed to read DIE at offset 0x%x in compunit %d (at 0x%x), skipping remainder of compilation unit: %s"
							.formatted(startOfDIE, cu.getUnitNumber(), cu.getStartOffset(),
								Objects.requireNonNullElse(e.getMessage(), "unspecified")));
				Msg.debug(this, "Error location", e);
				debugInfoBR.setPointerIndex(endOffset);
			}
		}

	}

	private long getLocalDIEOffset(DWARFForm form, long rawOffset, DWARFCompilationUnit cu)
			throws DWARFException {
		switch (form) {
			case DW_FORM_ref1, DW_FORM_ref2, DW_FORM_ref4, DW_FORM_ref8, DW_FORM_ref_udata:
				return rawOffset + cu.getStartOffset();
			case DW_FORM_ref_addr:
				return rawOffset;
			case DW_FORM_gnu_ref_alt:
				throw new DWARFException("Unsupported DIE reference form: " + form);
			default:
				Msg.warn(this, "Nontypical form %s used for reference".formatted(form));
				return rawOffset;
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

	private DWARFCompilationUnit getCompilationUnitForDIE(int dieIndex) {
		Entry<Integer, DWARFCompilationUnit> entry = compUnitDieIndex.ceilingEntry(dieIndex);
		return entry != null ? entry.getValue() : null;
	}

	/**
	 * Return the DIE referenced by an attribute value (a DW_FORM and offset)
	 * 
	 * @param form {@link DWARFForm} 
	 * @param rawOffset index / offset from the numeric attribute
	 * @param cu compilation unit containing the value
	 * @return {@link DebugInfoEntry}, or null if doesn't exist
	 * @throws IOException if unsupported format for reference
	 */
	public DebugInfoEntry getDIE(DWARFForm form, long rawOffset, DWARFCompilationUnit cu)
			throws IOException {
		return getDIEByOffset(getLocalDIEOffset(form, rawOffset, cu));
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
				die = DebugInfoEntry.read(debugInfoBR, cu, dieIndex);
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
		long dieOffset = 0 <= dieIndex && dieIndex < dieOffsets.length ? dieOffsets[dieIndex] : -1;
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

	public BinaryReader getReaderForCompUnit(DWARFCompilationUnit cu) {
		return debugInfoBR;
	}

	public Map<Integer, DWARFAbbreviation> getAbbrevs(long abbrevOffset) throws IOException {
		Map<Integer, DWARFAbbreviation> result = abbrCache.get(abbrevOffset);
		if (result == null) {
			debugAbbrBR.setPointerIndex(abbrevOffset);
			result = DWARFAbbreviation.readAbbreviations(debugAbbrBR, this);
			abbrCache.put(abbrevOffset, result);
		}
		return result;
	}

	public DWARFProgram getProgram() {
		return dprog;
	}

	public List<DWARFCompilationUnit> getCompilationUnits() {
		return compUnits;
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
	private int getParentIndex(int dieIndex) {
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
	private IntArrayList getDIEChildIndexes(int dieIndex) {
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

	public int getChildCount(int dieIndex) {
		int result = 0;
		if (dieIndex >= 0) {
			int parentSiblingIndex = siblingIndexes[dieIndex];
			for (int index = dieIndex + 1; index < parentSiblingIndex; index =
				siblingIndexes[index]) {
				result++;
			}
		}
		return result;
	}

	/**
	 * Returns the raw offset of an indexed item.  For DW_FORM_addrx values, the returned value
	 * is not fixed up with Ghidra load offset.
	 * 
	 * @param form {@link DWARFForm} of the index
	 * @param index int index into a lookup table (see {@link #addressListTable}, 
	 * {@link #locationListTable}, {@link #rangeListTable}, {@link #stringsOffsetTable})
	 * @param cu {@link DWARFCompilationUnit}
	 * @return raw offset of indexed item
	 * @throws IOException if error reading index table
	 */
	public long getOffsetOfIndexedElement(DWARFForm form, int index, DWARFCompilationUnit cu)
			throws IOException {
		DWARFIndirectTable table = switch (form) {
			case DW_FORM_addrx:
			case DW_FORM_addrx1:
			case DW_FORM_addrx2:
			case DW_FORM_addrx3:
			case DW_FORM_addrx4:
				yield addressListTable;
			case DW_FORM_rnglistx:
				yield rangeListTable;
			case DW_FORM_loclistx:
				yield locationListTable;
			case DW_FORM_strx:
			case DW_FORM_strx1:
			case DW_FORM_strx2:
			case DW_FORM_strx3:
			case DW_FORM_strx4:
				yield stringsOffsetTable;
			default:
				yield null;
		};
		return table != null ? table.getOffset(index, cu) : -1;
	}

	/**
	 * Returns an address value.
	 * 
	 * @param form the format of the numeric value
	 * @param value raw offset or indirect address index (depending on the DWARFForm)
	 * @param cu {@link DWARFCompilationUnit}
	 * @return address
	 * @throws IOException if error reading indirect lookup tables
	 */
	public long getAddress(DWARFForm form, long value, DWARFCompilationUnit cu) throws IOException {
		switch (form) {
			case DW_FORM_addr:
			case DW_FORM_udata:
				return value;
			case DW_FORM_addrx:
			case DW_FORM_addrx1:
			case DW_FORM_addrx2:
			case DW_FORM_addrx3:
			case DW_FORM_addrx4: {
				long addr = addressListTable.getOffset((int) value, cu);
				return addr;
			}
			case DW_FORM_gnu_addr_index:
			default:
				throw new IOException("Unsupported form %s".formatted(form));
		}
	}

	/**
	 * Returns the {@link DWARFLocationList} pointed to by the specified attribute value.
	 * 
	 * @param diea {@link DIEAggregate}
	 * @param attrId attribute id that points to the location list
	 * @return {@link DWARFLocationList}, never null
	 * @throws IOException if specified attribute is not the correct type, or if other error reading
	 * data 
	 */
	public DWARFLocationList getLocationList(DIEAggregate diea, DWARFAttributeId attrId)
			throws IOException {
		DWARFAttribute attrib = diea.findAttribute(attrId);
		if (attrib == null) {
			return DWARFLocationList.EMPTY;
		}
		return switch (attrib.getValue()) {
			case DWARFNumericAttribute dnum -> readLocationList(attrib, dnum);
			case DWARFBlobAttribute dblob -> DWARFLocationList.withWildcardRange(dblob.getBytes());
			default -> throw new IOException("Unsupported form %s.".formatted(attrib));
		};
	}


	private DWARFLocationList readLocationList(DWARFAttribute attr, DWARFNumericAttribute val)
			throws IOException {
		try {
			DWARFCompilationUnit cu = attr.getCU();
			switch (attr.getAttributeForm()) {
				case DW_FORM_sec_offset:
				case DW_FORM_data2:
				case DW_FORM_data4:
				case DW_FORM_data8:
					int dwarfVer = cu.getDWARFVersion();
					if (dwarfVer < 5) {
						debugLocation.setPointerIndex(val.getUnsignedValue());
						return DWARFLocationList.readV4(debugLocation, cu);
					}
					else if (dwarfVer == 5) {
						debugLocLists.setPointerIndex(val.getUnsignedValue());
						return DWARFLocationList.readV5(debugLocLists, cu);
					}
					break;
				case DW_FORM_loclistx:
					int index = val.getUnsignedIntExact();
					long locOffset = locationListTable.getOffset(index, cu);
					debugLocLists.setPointerIndex(locOffset);
					return DWARFLocationList.readV5(debugLocLists, cu);
				default:
					break; // fallthru to throw
			}
		}
		catch (IOException | IllegalArgumentException e) {
			throw new IOException(
				"Failed to read location list specified by %s".formatted(attr.toString()), e);
		}
		throw new IOException("Unsupported loclist form %s".formatted(attr.getAttributeForm()));
	}

	/**
	 * Returns a DWARF attribute string value, as specified by a form, offset/index, and the cu.
	 *  
	 * @param form {@link DWARFForm}
	 * @param offset offset or index of the value
	 * @param cu {@link DWARFCompilationUnit}
	 * @return String value, never null
	 * @throws IOException if invalid form or bad offset/index
	 */
	public String getString(DWARFForm form, long offset, DWARFCompilationUnit cu)
			throws IOException {
		switch (form) {
			case DW_FORM_line_strp:
				return lineStrings.getStringAtOffset(offset);
			case DW_FORM_strp:
				return debugStrings.getStringAtOffset(offset);
			case DW_FORM_gnu_strp_alt:
			case DW_FORM_gnu_str_index:
				throw new IOException("Unsupported DWARF string attribute form " + form);
			case DW_FORM_strx, DW_FORM_strx1, DW_FORM_strx2, DW_FORM_strx3, DW_FORM_strx4:
				long strOffset = stringsOffsetTable.getOffset((int) offset, cu);
				return debugStrings.getStringAtOffset(strOffset);

			default:
				throw new IOException("Unsupported string form: " + form);
		}
	}

	public StringTable getStringTable() {
		return debugStrings;
	}

	/**
	 * Returns the {@link DWARFRangeList} pointed at by the specified attribute.
	 * 
	 * @param diea {@link DIEAggregate}
	 * @param attribute attribute id to find in the DIEA
	 * @return {@link DWARFRangeList}, or null if attribute is not present
	 * @throws IOException if error reading range list
	 */
	public DWARFRangeList getRangeList(DIEAggregate diea, DWARFAttributeId attribute)
			throws IOException {

		DWARFAttribute rngListAttr = diea.findAttribute(attribute);
		if (rngListAttr == null ||
			!(rngListAttr.getValue() instanceof DWARFNumericAttribute rngListVal)) {
			return null;
		}

		DWARFCompilationUnit cu = diea.getCompilationUnit();

		switch (rngListAttr.getAttributeForm()) {
			case DW_FORM_rnglistx: { // assumes v5
				int index = rngListVal.getUnsignedIntExact();
				long rnglistOffset = rangeListTable.getOffset(index, cu);
				debugRngLists.setPointerIndex(rnglistOffset);
				return DWARFRangeList.readV5(debugRngLists, cu);
			}
			case DW_FORM_sec_offset:
			case DW_FORM_data2:
			case DW_FORM_data4:
			case DW_FORM_data8: {
				long rnglistOffset = rngListVal.getValue();
				short dwarfVersion = cu.getDWARFVersion();
				if (dwarfVersion < 5) {
					debugRanges.setPointerIndex(rnglistOffset);
					return DWARFRangeList.readV4(debugRanges, cu);
				}
				else if (dwarfVersion == 5) {
					debugRngLists.setPointerIndex(rnglistOffset);
					return DWARFRangeList.readV5(debugRngLists, cu);
				}
				break;
			}
			default:
				break; // fall thru to throw
		}
		throw new IOException("Unsupported attribute form " + rngListAttr);
	}

	/**
	 * Returns the DWARFLine info pointed to by the specified attribute.
	 * 
	 * @param diea {@link DIEAggregate}
	 * @param attribute attribute id that points to the line info
	 * @return {@link DWARFLine}, never null, see {@link DWARFLine#empty()}
	 * @throws IOException if error reading line data
	 */
	public DWARFLine getLine(DIEAggregate diea, DWARFAttributeId attribute) throws IOException {
		DWARFNumericAttribute attrib = diea.findValue(attribute, DWARFNumericAttribute.class);
		if (attrib == null || debugLineBR == null) {
			return DWARFLine.empty();
		}
		long stmtListOffset = attrib.getUnsignedValue();
		return getLine(stmtListOffset, diea.getCompilationUnit(), true);
	}

	public DWARFLine getLine(long offset, DWARFCompilationUnit cu, boolean readIfMissing)
			throws IOException {
		DWARFLine result = cachedDWARFLines.get(offset);
		if (result == null && readIfMissing) {
			result = DWARFLine.read(debugLineBR.clone(offset), dprog.getDefaultIntSize(), cu);
			cachedDWARFLines.put(offset, result);
		}
		return result;
	}

	public long getLineDataSize() {
		return debugLineBR != null ? debugLineBR.length() : 0;
	}

	public BinaryReader getDebugLineReader() {
		return debugLineBR;
	}

	public boolean hasLineInfo() {
		return debugLineBR != null;
	}

	public DWARFMacroHeader getMacroHeader(long offset, DWARFCompilationUnit cu) {
		if (debugMacros != null) {
			try {
				return DWARFMacroHeader.readV5(debugMacros.clone(offset), cu);
			}
			catch (IOException e) {
				// ignore, fall thru return emtpy
			}
		}
		return DWARFMacroHeader.EMTPY;
	}

	public List<DWARFMacroInfoEntry> getMacroEntries(DWARFMacroHeader macroHeader)
			throws IOException {
		if (debugMacros == null) {
			return List.of();
		}

		return DWARFMacroHeader.readMacroEntries(
			debugMacros.clone(macroHeader.getEntriesStartOffset()), macroHeader);
	}

	public int getPositionInParent(DebugInfoEntry die, Predicate<DWARFTag> dwTagFilter) {
		int dieIndex = die.getIndex();
		int parentIndex = getParentIndex(dieIndex);
		if (parentIndex < 0) {
			return -1;
		}
		IntArrayList childIndexes = getDIEChildIndexes(parentIndex);
		for (int i = 0, positionNum = 0; i < childIndexes.size(); i++) {
			int childDIEIndex = childIndexes.get(i);
			if (childDIEIndex == dieIndex) {
				return positionNum;
			}
			DebugInfoEntry childDIE = getDIEByIndex(childDIEIndex);
			if (childDIE != null && dwTagFilter.test(childDIE.getTag())) {
				positionNum++;
			}
		}
		// only way to get here is if our in-memory indexes are corrupt / incorrect
		throw new RuntimeException("DWARF DIE index failure.");
	}

	@Override
	public DIEIterator iterator() {
		return new DIEIterator();
	}

	public DIEIterator unreferencedDIEs() {
		return new DIEHeadIterator();
	}

	private List<DIEAggregate> getTypeReferers(DIEAggregate targetDIEA) {
		List<Long> dieaOffsets = typeReferers.get(targetDIEA.getOffset());
		if (dieaOffsets == null) {
			return List.of();
		}
		return dieaOffsets.stream().map(dieaOffset -> getAggregate(dieaOffset)).toList();
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
	public List<DIEAggregate> getTypeReferers(DIEAggregate targetDIEA, DWARFTag tag) {
		List<DIEAggregate> result = new ArrayList<>();

		for (DIEAggregate referer : getTypeReferers(targetDIEA)) {
			if (referer.getTag() == tag) {
				result.add(referer);
			}
		}
		return result;
	}

	private class DIEHeadIterator extends DIEIterator {
		@Override
		protected boolean includeDIE(int dieIndex) {
			return !indexHasRef.get(dieIndex);
		}

		@Override
		public Iterator<DebugInfoEntry> iterator() {
			return this;
		}
	}

	private class DIEIterator implements Iterator<DebugInfoEntry>, Iterable<DebugInfoEntry> {

		private int index = -1;

		private int findNext() {
			int i = index;
			if (i < dieOffsets.length) {
				for (i = i + 1; i < dieOffsets.length; i++) {
					if (includeDIE(i)) {
						return i;
					}
				}
			}
			return i;
		}

		protected boolean includeDIE(int dieIndex) {
			return true;
		}

		@Override
		public Iterator<DebugInfoEntry> iterator() {
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
		public DebugInfoEntry next() {
			if (!hasNext()) {
				throw new NoSuchElementException();
			}
			int resultIndex = index;
			index = findNext();
			return getDIEByIndex(resultIndex);
		}

	}

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
