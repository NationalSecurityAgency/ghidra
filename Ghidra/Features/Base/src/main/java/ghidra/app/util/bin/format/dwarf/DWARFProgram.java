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

import static ghidra.app.util.bin.format.dwarf.DWARFTag.*;
import static ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeId.*;

import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeId;
import ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionException;
import ghidra.app.util.bin.format.dwarf.external.ExternalDebugInfo;
import ghidra.app.util.bin.format.dwarf.funcfixup.DWARFFunctionFixup;
import ghidra.app.util.bin.format.dwarf.sectionprovider.*;
import ghidra.app.util.bin.format.golang.rtti.GoSymbolName;
import ghidra.app.util.opinion.*;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.program.model.address.*;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.listing.*;
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
	public static final CategoryPath DWARF_ROOT_CATPATH = CategoryPath.ROOT.extend(DWARF_ROOT_NAME);
	public static final CategoryPath UNCAT_CATPATH = DWARF_ROOT_CATPATH.extend("_UNCATEGORIZED_");

	public static final String DWARF_BOOKMARK_CAT = "DWARF";
	private static final int NAME_HASH_REPLACEMENT_SIZE = 8 + 2 + 2;
	private static final String ELLIPSES_STR = "...";
	protected static final EnumSet<DWARFAttributeId> REF_ATTRS =
		EnumSet.of(DW_AT_abstract_origin, DW_AT_specification);

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
	 * 
	 * @param program {@link Program} to test
	 * @return boolean true if program probably has DWARF info, false if not
	 */
	public static boolean isDWARF(Program program) {
		String format = Objects.requireNonNullElse(program.getExecutableFormat(), "");

		return switch (format) {
			case ElfLoader.ELF_NAME, PeLoader.PE_NAME -> hasExpectedDWARFSections(program) ||
				ExternalDebugInfo.fromProgram(program) != null;
			case MachoLoader.MACH_O_NAME -> hasExpectedDWARFSections(program) ||
				DSymSectionProvider.getDSYMForProgram(program) != null;
			default -> false;
		};
	}

	private static boolean hasExpectedDWARFSections(Program program) {
		// the compressed section provider will find normally named sections as well
		// as compressed sections
		try (DWARFSectionProvider tmp =
			new CompressedSectionProvider(new BaseSectionProvider(program))) {
			return tmp.hasSection(DWARFSectionId.MINIMAL_DWARF_SECTIONS);
		}
	}

	/**
	 * Returns true if the specified {@link Program program} has DWARF information.
	 * <p>
	 * This is similar to {@link #isDWARF(Program)}, but is a stronger check that is more
	 * expensive as it could involve searching for external files.
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
	private DWARFName rootDNI = DWARFName.createRoot(DWARF_ROOT_CATPATH);
	private DWARFName unCatDataTypeRoot = DWARFName.createRoot(UNCAT_CATPATH);
	private DWARFImportOptions importOptions;
	private DWARFImportSummary importSummary = new DWARFImportSummary();
	private DWARFSectionProvider sectionProvider;
	protected long programBaseAddressFixup;
	private Charset charset;

	private int maxDNICacheSize = 50;
	private FixedSizeHashMap<Long, DWARFName> dniCache =
		new FixedSizeHashMap<>(100, maxDNICacheSize);

	private DWARFRegisterMappings dwarfRegisterMappings;
	private final boolean stackGrowsNegative;

	private List<DWARFFunctionFixup> functionFixups;

	protected DIEContainer dieContainer;

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
		this(program, importOptions,
			DWARFSectionProviderFactory.createSectionProviderFor(program, monitor));
	}

	/**
	 * Constructor for DWARFProgram.
	 *
	 * @param program Ghidra {@link Program}.
	 * @param importOptions {@link DWARFImportOptions} to controls options during reading / parsing /importing.
	 * @param sectionProvider {@link DWARFSectionProvider} factory that finds DWARF .debug_* sections
	 * wherever they live.
	 * @throws IOException if error reading data
	 */
	public DWARFProgram(Program program, DWARFImportOptions importOptions,
			DWARFSectionProvider sectionProvider) throws IOException {
		if (sectionProvider == null) {
			throw new IllegalArgumentException("Null DWARFSectionProvider");
		}

		this.program = program;
		this.sectionProvider = sectionProvider;
		this.importOptions = importOptions;
		this.dwarfDTM = new DWARFDataTypeManager(this, program.getDataTypeManager());
		this.stackGrowsNegative = program.getCompilerSpec().stackGrowsNegative();

		this.charset = importOptions.getCharset(StandardCharsets.UTF_8);

		dwarfRegisterMappings =
			DWARFRegisterMappingsManager.hasDWARFRegisterMapping(program.getLanguage())
					? DWARFRegisterMappingsManager.getMappingForLang(program.getLanguage())
					: null;

		dieContainer = new DIEContainer(this);
	}

	public DIEContainer getDIEContainer() {
		return dieContainer;
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
		dieContainer.init(monitor);
		dieContainer.indexData(monitor);
	}

	@Override
	public void close() throws IOException {
		if (sectionProvider != null) {
			sectionProvider.close();
		}
		if (dieContainer != null) {
			dieContainer.close();
		}
		dniCache.clear();

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

	public List<DWARFCompilationUnit> getCompilationUnits() {
		return dieContainer.getCompilationUnits();
	}

	public boolean isBigEndian() {
		return program.getLanguage().isBigEndian();
	}

	public boolean isLittleEndian() {
		return !program.getLanguage().isBigEndian();
	}

	public DWARFSectionProvider getSectionProvider() {
		return sectionProvider;
	}

	private static boolean isAnonDWARFName(String name) {
		return (name == null) || name.startsWith("._") || name.startsWith("<anonymous");
	}

	public String getEntryName(DIEAggregate diea) {
		String name = diea.getString(DW_AT_name, null);

		if (name == null) {
			String linkageName = diea.getString(DW_AT_linkage_name, null);
			if (linkageName == null) {
				linkageName = diea.getString(DW_AT_MIPS_linkage_name, null);
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
	private DWARFName getDWARFName(DIEAggregate diea, DWARFName localRootDNI) {

		DWARFName parentDNI = localRootDNI;

		DIEAggregate declParent = diea.getDeclParent();
		if ((declParent != null) && declParent.getTag() != DW_TAG_compile_unit) {
			parentDNI = lookupDNIByOffset(declParent.getOffset());
			if (parentDNI == null) {
				parentDNI = getDWARFName(declParent, localRootDNI);
				if (parentDNI != null) {
					cacheDNIByOffset(declParent.getOffset(), parentDNI);
				}
			}
		}

		DWARFTag tag = diea.getTag();
		String name = getEntryName(diea);

		// Mangled names can occur in linkage attributes or in the regular name attribute.
		if (name != null && name.contains("_Z") /* mangler start seq */ && !name.startsWith(
			"_GLOBAL_") /* compiler generated, don't demangle as they tend to conflict with existing names */) {
			List<String> nestings = ensureSafeNameLengths(DWARFUtil.parseMangledNestings(name));
			if (!nestings.isEmpty()) {
				name = nestings.remove(nestings.size() - 1);
				if (parentDNI == localRootDNI && !nestings.isEmpty()) {
					parentDNI = DWARFName.fromList(localRootDNI, nestings);
				}
			}
		}

		// If namespace info got squashed due to compiler/linker flags, try to
		// dig it up from the mangled linkage info that might be present in our children.
		if (localRootDNI.equals(parentDNI)) {
			List<String> nestings = DWARFUtil.findLinkageNameInChildren(diea.getHeadFragment());
			if (!nestings.isEmpty()) {
				nestings.remove(nestings.size() - 1);
				parentDNI = DWARFName.fromList(localRootDNI, nestings);
			}
		}

		if (name == null) {
			// check to see if there is a single inbound typedef that we can steal its name.
			List<DIEAggregate> referers = dieContainer.getTypeReferers(diea, DW_TAG_typedef);
			if (referers.size() == 1) {
				return getDWARFName(referers.get(0), localRootDNI);
			}
		}

		if (name == null && tag.isStructureType()) {
			String fingerprint = DWARFUtil.getStructLayoutFingerprint(diea);

			// check to see if there are struct member defs that ref this anon type
			// and build a name using the field names
			List<DIEAggregate> referringMembers = dieContainer.getTypeReferers(diea, DW_TAG_member);

			String referringMemberNames = getReferringMemberFieldNames(referringMembers);
			if (!referringMemberNames.isEmpty()) {
				// this re-homes this anon struct def from the root of the compunit to the
				// structure that is using this anon struct def.
				parentDNI = getName(referringMembers.get(0).getParent());
				referringMemberNames = "_for_" + referringMemberNames;
			}
			name = "anon_" + tag.getContainerTypeName() + "_" + fingerprint + referringMemberNames;
			return parentDNI.createChild(null, name, tag.getSymbolType());
		}

		boolean isAnon = false;
		if (name == null) {
			switch (diea.getTag()) {
				case DW_TAG_base_type:
					name = getAnonBaseTypeName(diea);
					isAnon = true;
					break;
				case DW_TAG_enumeration_type:
					name = getAnonEnumName(diea);
					isAnon = true;
					break;
				case DW_TAG_subroutine_type:
					// unnamed subroutines (C func ptrs)
					// See {@link #isAnonSubroutine(DataType)}
					name = "anon_subr";
					isAnon = true;
					break;
				case DW_TAG_lexical_block: // "lexical_block_1_2_3"
					name = "lexical_block" + getLexicalBlockNameWorker(diea.getHeadFragment());
					break;
				case DW_TAG_formal_parameter:
					name = "param_%d".formatted(dieContainer.getPositionInParent(
						diea.getHeadFragment(), dietag -> dietag == DW_TAG_formal_parameter));
					isAnon = true;
					break;
				case DW_TAG_subprogram:
				case DW_TAG_inlined_subroutine:
					if (declParent != null && declParent.getTag().isStructureType() &&
						diea.getBool(DW_AT_artificial, false)) {
						name = parentDNI.getName();
					}
					else {
						name = "anon_func";
						isAnon = true;
					}
					break;
				default:
					if (declParent != null && declParent.getTag().isNameSpaceContainer()) {
						name = DWARFUtil.getAnonNameForMeFromParentContext2(diea);
					}
					break;
			}
		}

		// Name was not found
		if (isAnonDWARFName(name)) {
			name = createAnonName("anon_" + tag.getContainerTypeName(), diea);
			isAnon = true;
		}

		String origName = isAnon ? null : name;
		String workingName = ensureSafeNameLength(name);
		workingName = GoSymbolName.fixGolangSpecialSymbolnameChars(workingName);

		if (diea.getCompilationUnit().getLanguage() == DWARFSourceLanguage.DW_LANG_Rust &&
			workingName.startsWith("{impl#") && parentDNI != null) {
			// if matches a Rust {impl#NN} name, skip it and re-use the parent name
			return parentDNI;
		}

		DWARFName result = parentDNI.createChild(origName, workingName, tag.getSymbolType());
		return result;
	}

	private String getAnonBaseTypeName(DIEAggregate diea) {
		try {
			int dwarfSize = diea.parseInt(DW_AT_byte_size, 0);
			int dwarfEncoding = (int) diea.getUnsignedLong(DW_AT_encoding, -1);
			return "anon_basetype_%s_%d".formatted(DWARFEncoding.getTypeName(dwarfEncoding),
				dwarfSize);
		}
		catch (IOException | DWARFExpressionException e) {
			return createAnonName("anon_basetype_unknown", diea);
		}
	}

	private String getAnonEnumName(DIEAggregate diea) {
		int enumSize = Math.max(1, (int) diea.getUnsignedLong(DW_AT_byte_size, 1));
		return "anon_enum_%d".formatted(enumSize * 8);
	}

	private static String createAnonName(String baseName, DIEAggregate diea) {
		return "%s.dwarf_%x".formatted(baseName, diea.getOffset());
	}

	private String getLexicalBlockNameWorker(DebugInfoEntry die) {
		if (isLexicalBlockTag(die.getTag())) {
			return "%s_%d".formatted(getLexicalBlockNameWorker(die.getParent()),
				dieContainer.getPositionInParent(die, this::isLexicalBlockTag));
		}
		return "";
	}

	private boolean isLexicalBlockTag(DWARFTag tag) {
		return tag == DW_TAG_lexical_block || tag == DW_TAG_inlined_subroutine;
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
				int positionInParent =
					dieContainer.getPositionInParent(referringMember.getHeadFragment(), x -> true);
				if (positionInParent == -1) {
					continue;
				}
				DWARFName parentDNI = getName(commonParent);
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

	/**
	 * Returns a {@link DWARFName} for a {@link DIEAggregate}.
	 * 
	 * @param diea {@link DIEAggregate}
	 * @return {@link DWARFName}, never null
	 */
	public DWARFName getName(DIEAggregate diea) {
		DWARFName dni = lookupDNIByOffset(diea.getOffset());
		if (dni == null) {
			dni = getDWARFName(diea, unCatDataTypeRoot);
			cacheDNIByOffset(diea.getOffset(), dni);
		}
		return dni;
	}

	private DWARFName lookupDNIByOffset(long offset) {
		DWARFName tmp = dniCache.get(offset);
		return tmp;
	}

	private void cacheDNIByOffset(long offset, DWARFName dni) {
		dniCache.put(offset, dni);
	}

	/**
	 * {@return charset to use when decoding debug strings}
	 */
	public Charset getCharset() {
		return charset;
	}



	/**
	 * Returns iterable that traverses all {@link DIEAggregate}s in the program. 
	 *
	 * @return sequence of {@link DIEAggregate}es
	 */
	public Iterable<DIEAggregate> allAggregates() {
		return dieContainer.allAggregates();
	}

	/**
	 * Returns the total number of {@link DIEAggregate} objects in the entire program.
	 *
	 * @return the total number of {@link DIEAggregate} objects in the entire program.
	 */
	public int getTotalAggregateCount() {
		return dieContainer.getTotalAggregateCount();
	}

	public DWARFRegisterMappings getRegisterMappings() {
		return dwarfRegisterMappings;
	}

	public DWARFName getRootDNI() {
		return rootDNI;
	}

	public DWARFName getUncategorizedRootDNI() {
		return unCatDataTypeRoot;
	}

	public AddressSpace getStackSpace() {
		return program.getAddressFactory().getStackSpace();
	}

	/**
	 * A fixup value that needs to be applied to static addresses of the program.
	 * <p>
	 * This value is necessary if the program's built-in base address is overridden at import time.
	 * 
	 * @return long value to add to static addresses discovered in DWARF to make it agree with
	 * Ghidra's imported program.
	 */
	public long getProgramBaseAddressFixup() {
		return programBaseAddressFixup;
	}

	public void setProgramBaseAddressFixup(long programBaseAddressFixup) {
		this.programBaseAddressFixup = programBaseAddressFixup;
	}

	public AddressRange getAddressRange(DWARFRange range, boolean isCode) {
		AddressSpace defAS = program.getAddressFactory().getDefaultAddressSpace();
		Address start =
			defAS.getAddress(range.getFrom() + programBaseAddressFixup, true /* TODO check this */);
		Address end = defAS.getAddress(range.getTo() - 1 + programBaseAddressFixup,
			true /* TODO check this */);
		return new AddressRangeImpl(start, end);
	}

	public Address getCodeAddress(long offset) {
		return program.getAddressFactory()
				.getDefaultAddressSpace()
				.getAddress(offset + programBaseAddressFixup, true);
	}

	public Address getDataAddress(long offset) {
		return program.getAddressFactory()
				.getDefaultAddressSpace()
				.getAddress(offset + programBaseAddressFixup, true);
	}

	public boolean isZeroDataAddress(Address addr) {
		Address realZero = getDataAddress(0);
		return realZero.equals(addr);
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

	public int getDefaultIntSize() {
		return program.getDefaultPointerSize();
	}

	public void logWarningAt(Address addr, String addrName, String msg) {
		if (importOptions.isUseBookmarks()) {
			BookmarkManager bmm = program.getBookmarkManager();
			Bookmark existingBM = bmm.getBookmark(addr, BookmarkType.WARNING, DWARF_BOOKMARK_CAT);
			String existingTxt = existingBM != null ? existingBM.getComment() : "";
			if (existingTxt.contains(msg)) {
				return;
			}
			msg = !existingTxt.isEmpty() ? existingTxt + "; " + msg : msg;
			bmm.setBookmark(addr, BookmarkType.WARNING, DWARF_BOOKMARK_CAT, msg);
		}
		else {
			Msg.warn(this, "%s: %s at %s@%s".formatted(DWARF_BOOKMARK_CAT, msg, addrName, addr));
		}
	}

}
