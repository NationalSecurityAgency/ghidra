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
//DO NOT RUN. THIS IS NOT A SCRIPT! THIS IS A CLASS THAT IS USED BY SCRIPTS. 
package classrecovery;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.label.DemanglerCmd;
import ghidra.app.plugin.core.analysis.ReferenceAddressPair;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.PointerTypedef;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.Msg;
import ghidra.util.bytesearch.GenericByteSequencePattern;
import ghidra.util.bytesearch.GenericMatchAction;
import ghidra.util.bytesearch.Match;
import ghidra.util.bytesearch.MemoryBytePatternSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class RTTIGccClassRecoverer extends RTTIClassRecoverer {

	private static final String SPECIAL_CLASS_NAMESPACE = "__cxxabiv1";
	private static final String CLASS_TYPEINFO_NAMESPACE = "__class_type_info";
	private static final String SI_CLASS_TYPEINFO_NAMESPACE = "__si_class_type_info";
	private static final String VMI_CLASS_TYPEINFO_NAMESPACE = "__vmi_class_type_info";
	private static final String TYPEINFO_LABEL = "typeinfo";
	private static final String MANGLED_CLASS_TYPEINFO_NAMESPACE = "N10__cxxabiv117__class_type_infoE";
	private static final String MANGLED_SI_CLASS_TYPEINFO_NAMESPACE = "N10__cxxabiv120__si_class_type_infoE";
	private static final String MANGLED_VMI_CLASS_TYPEINFO_NAMESPACE = "N10__cxxabiv121__vmi_class_type_infoE";
	private static final String MANGLED_VTABLE_PREFIX = "_ZTV";
	private static final String MANGLED_STRING_PREFIX = "_ZTS";
	private static final String MANGLED_TYPEINFO_PREFIX = "_ZTI";

	private static final String VMI_CLASS_TYPE_INFO_STRUCTURE = "VmiClassTypeInfoStructure";
	private static final String BASE_CLASS_TYPE_INFO_STRUCTURE = "BaseClassTypeInfoStructure";
	private static final String SI_CLASS_TYPE_INFO_STRUCTURE = "SiClassTypeInfoStructure";
	private static final String CLASS_TYPE_INFO_STRUCTURE = "ClassTypeInfoStructure";
	private static final String VTABLE_LABEL = "vtable";
	private static final String CONSTRUCTION_VTABLE_LABEL = "construction-vtable";
	private static final String CLASS_VTABLE_PTR_FIELD_EXT = "vftablePtr";
	private static final int NONE = -1;
	private static final int UNKNOWN = -2;
	private static final boolean DEBUG = false;

	Map<Address, Integer> vtableToSizeMap = new HashMap<Address, Integer>();
	Map<Address, Address> typeinfoToVtableMap = new HashMap<Address, Address>();
	Map<Address, String> typeinfoToStructuretypeMap = new HashMap<Address, String>();
	Map<RecoveredClass, Address> classToTypeinfoMap = new HashMap<RecoveredClass, Address>();
	Address class_type_info_vtable = null;
	Address si_class_type_info_vtable = null;
	Address vmi_class_type_info_vtable = null;
	Address class_type_info = null;
	Address si_class_type_info = null;
	Address vmi_class_type_info = null;

	int componentOffset;

	Map<Address, Set<Address>> directRefMap = new HashMap<Address, Set<Address>>();

	List<RecoveredClass> nonInheritedClasses = new ArrayList<RecoveredClass>();
	List<RecoveredClass> singleInheritedClasses = new ArrayList<RecoveredClass>();
	List<RecoveredClass> multiAndOrVirtuallyInheritedClasses = new ArrayList<RecoveredClass>();

	List<RecoveredClass> recoveredClasses = new ArrayList<RecoveredClass>();

	private Map<RecoveredClass, Map<Integer, RecoveredClass>> classToParentOrderMap = new HashMap<RecoveredClass, Map<Integer, RecoveredClass>>();

	private Map<RecoveredClass, Map<RecoveredClass, Long>> classToParentOffsetMap = new HashMap<RecoveredClass, Map<RecoveredClass, Long>>();

	boolean isDwarfLoaded;
	boolean replaceClassStructs;

	FunctionManager functionManager = null;

	public RTTIGccClassRecoverer(Program program, ProgramLocation location, PluginTool tool, FlatProgramAPI api,
			boolean createBookmarks, boolean useShortTemplates, boolean nameVfunctions, boolean isDwarfLoaded,
			TaskMonitor monitor) throws Exception {

		super(program, location, tool, api, createBookmarks, useShortTemplates, nameVfunctions, isDwarfLoaded, monitor);
		this.isDwarfLoaded = isDwarfLoaded;

		functionManager = program.getFunctionManager();
	}

	@Override
	public boolean containsRTTI() throws CancelledException {

		try {
			if (!hasSpecialTypeinfos()) {
				return false;
			}
		} catch (InvalidInputException | UnsupportedEncodingException e) {

			e.printStackTrace();
			return false;
		}

		return true;
	}

	@Override
	public boolean isValidProgramType() {

		if (isGcc()) {
			return true;
		}

		return false;
	}

	@Override
	public List<RecoveredClass> createRecoveredClasses() throws CancelledException, Exception {

		AddressSetView initializedMem = program.getMemory().getAllInitializedAddressSet();
		List<ReferenceAddressPair> directReferenceList = new ArrayList<ReferenceAddressPair>();

		ProgramMemoryUtil.loadDirectReferenceList(program, 1, initializedMem.getMinAddress(), initializedMem,
				directReferenceList, monitor);
		createGlobalDirectRefMap(directReferenceList);

		Msg.debug(this, "Creating Special Typeinfos");
		List<GccTypeinfo> specialTypeinfos = createSpecialTypeinfos();
		if (specialTypeinfos.isEmpty()) {
			Msg.debug(this, "Could not create special typeinfos");
			return null;
		}

		Msg.debug(this, "Creating Special Vtables");
		List<SpecialVtable> specialVtables = findSpecialVtables(specialTypeinfos);

		if (specialVtables.isEmpty()) {
			Msg.debug(this, "Could not create special vtables");
			return null;
		}
		
		if(specialVtables.size() != specialTypeinfos.size()) {
			Msg.debug(this, "Not equal number of special vtables and special typeinfos");
			return null;
		}

		setComponentOffset();

		Msg.debug(this, "Creating Typeinfo Structs");
		List<GccTypeinfo> typeinfos = createTypeinfoStructs(specialTypeinfos, specialVtables);

		Msg.debug(this, "Creating Vtables");
		List<Vtable> vtables = processVtables(typeinfos);

		Msg.debug(this, "Creating Classes from Typeinfos");
		createClassesFromTypeinfos(typeinfos);

		if (recoveredClasses == null) {
			Msg.debug(this, "Could not recover ELF rtti classes");
			return null;
		}
		
		if (recoveredClasses.isEmpty()) {
			return recoveredClasses;
		}
		
		Msg.debug(this, "Updating classes with parents and flags");
		updateClassesWithParentsAndFlags(typeinfos);

		Msg.debug(this, "Updating classes with vftables");
		updateClassWithVfunctions(recoveredClasses, vtables);

		Msg.debug(this, "Creating Class Hierarchy lists and maps");
		createClassHierarchyListAndMap();

		if (isDwarfLoaded) {
			retrieveExistingClassStructures(recoveredClasses);
		}

		Msg.debug(this, "Processing constructors and destructors");
		processConstructorAndDestructors();

		Msg.debug(this, "Creating vftable order maps");
		createVftableOrderMap(recoveredClasses);

		Msg.debug(this, "Figuring out class data members");
		figureOutClassDataMembers(recoveredClasses);

		Msg.debug(this, "Creating and Applying Class structures");
		createAndApplyClassStructures();

		return recoveredClasses;

	}

	private List<GccTypeinfo> createSpecialTypeinfos() throws CancelledException {

		List<GccTypeinfo> specialGccTypeinfos = new ArrayList<GccTypeinfo>();

		GccTypeinfo gccTypeinfo = findSpecialTypeinfoSymbol(CLASS_TYPEINFO_NAMESPACE, MANGLED_CLASS_TYPEINFO_NAMESPACE);

		if (gccTypeinfo != null) {
			gccTypeinfo.setMangledNamespaceString(MANGLED_CLASS_TYPEINFO_NAMESPACE);
			class_type_info = gccTypeinfo.getAddress();
			specialGccTypeinfos.add(gccTypeinfo);
		}

		gccTypeinfo = findSpecialTypeinfoSymbol(SI_CLASS_TYPEINFO_NAMESPACE, MANGLED_SI_CLASS_TYPEINFO_NAMESPACE);

		if (gccTypeinfo != null) {
			gccTypeinfo.setMangledNamespaceString(MANGLED_SI_CLASS_TYPEINFO_NAMESPACE);
			si_class_type_info = gccTypeinfo.getAddress();
			specialGccTypeinfos.add(gccTypeinfo);
		}

		gccTypeinfo = findSpecialTypeinfoSymbol(VMI_CLASS_TYPEINFO_NAMESPACE, MANGLED_VMI_CLASS_TYPEINFO_NAMESPACE);

		if (gccTypeinfo != null) {
			gccTypeinfo.setMangledNamespaceString(MANGLED_VMI_CLASS_TYPEINFO_NAMESPACE);
			vmi_class_type_info = gccTypeinfo.getAddress();
			specialGccTypeinfos.add(gccTypeinfo);
		}

		return specialGccTypeinfos;

	}

	private GccTypeinfo findSpecialTypeinfoSymbol(String namespaceName, String mangledNamespaceString)
			throws CancelledException {

		// try finding with normal symbol name and namespace
		Symbol typeinfoSymbol = getSymbolInNamespaces(SPECIAL_CLASS_NAMESPACE, namespaceName, TYPEINFO_LABEL);
		if (typeinfoSymbol == null) {
			// then try finding with mangled symbol
			typeinfoSymbol = findAndReturnDemangledSymbol(MANGLED_TYPEINFO_PREFIX + mangledNamespaceString,
					SPECIAL_CLASS_NAMESPACE, namespaceName, TYPEINFO_LABEL);
			if (typeinfoSymbol == null) {

				// then try finding vtable in fake ext mem block (in this case there is no
				// typeinfo symbol because it
				// is in an external prog so it is assigned to the same address as the vtable
				typeinfoSymbol = findTypeinfoUsingExternalVtableSymbol(namespaceName, mangledNamespaceString);

				if (typeinfoSymbol == null) {

					// then try finding with mangled namespace string in memory
					typeinfoSymbol = findTypeinfoSymbolUsingMangledNamespaceString(mangledNamespaceString,
							namespaceName);
				}
			}
		}
		if (typeinfoSymbol != null) {
			return createGccTypeinfo(typeinfoSymbol, true);
		}
		return null;
	}

	private Symbol findTypeinfoUsingExternalVtableSymbol(String namespaceName, String mangledNamespaceString)
			throws CancelledException {

		// try finding with normal symbol name and namespace
		boolean isIndirectPointerToVtable = false;
		Symbol vtableSymbol = getSymbolInNamespaces(SPECIAL_CLASS_NAMESPACE, namespaceName, VTABLE_LABEL);
		if (vtableSymbol == null) {
			// then try finding with mangled symbol
			vtableSymbol = findAndReturnDemangledSymbol(MANGLED_VTABLE_PREFIX + mangledNamespaceString,
					SPECIAL_CLASS_NAMESPACE, namespaceName, VTABLE_LABEL);
			if (vtableSymbol == null) {
				vtableSymbol = findAndReturnDemangledSymbol(
						"__imp_" + MANGLED_VTABLE_PREFIX + mangledNamespaceString, SPECIAL_CLASS_NAMESPACE,
						namespaceName, VTABLE_LABEL);
				if (vtableSymbol == null) {
					return null;
				}
				isIndirectPointerToVtable = true;

			}

		}

		Address vtableAddress = vtableSymbol.getAddress();

		// if the vtable is not in the external block and it isn't an external address
		// then
		// it shouldn't be the case where the typeinfo is at the same location as the
		// vtable
		// since it should have enough memory for whole table then
		if (!inExternalBlock(vtableAddress) && !vtableAddress.isExternalAddress() && !isIndirectPointerToVtable) {
			return null;
		}

		if (vtableAddress.isExternalAddress()) {
			vtableAddress = getSingleReferenceTo(vtableAddress);
			if (vtableAddress == null) {
				return null;
			}
		}

		Symbol typeinfoSymbol;
		try {
			typeinfoSymbol = symbolTable.createLabel(vtableAddress, "typeinfo", vtableSymbol.getParentNamespace(),
					SourceType.ANALYSIS);
			// api.setPlateComment(typeinfoAddress, "typeinfo for " + namespace);
		} catch (InvalidInputException e) {
			Msg.debug(this, "Could not make typeinfo symbol at " + vtableAddress);
			return null;
		}

		return typeinfoSymbol;

	}

	private Namespace getOrCreateNamespace(String namespaceName, Namespace parentNamespace) {

		Namespace namespace = symbolTable.getNamespace(namespaceName, parentNamespace);
		if (namespace == null) {

			try {
				namespace = symbolTable.createNameSpace(parentNamespace, namespaceName, SourceType.ANALYSIS);
			} catch (DuplicateNameException | InvalidInputException e) {
				return null;
			}
		}
		return namespace;
	}

	// TODO: this assumes only one and returns the first found - have never seen
	// more than one but should probably check
	private Symbol findAndReturnDemangledSymbol(String mangledSymbolName, String specialClassNamespaceName,
			String classNamespaceName, String label) {

		SymbolIterator symbolIterator = symbolTable.getSymbolIterator(mangledSymbolName, true);
		if (symbolIterator.hasNext()) {

			Symbol mangledSymbol = symbolIterator.next();
			Address symbolAddress = mangledSymbol.getAddress();
			Namespace specialClassNamespace = getOrCreateNamespace(specialClassNamespaceName, globalNamespace);
			if (specialClassNamespace == null) {
				return null;
			}
			Namespace classNamespace = getOrCreateNamespace(classNamespaceName, specialClassNamespace);
			if (classNamespace == null) {
				return null;
			}

			try {
				Symbol demangledSymbol = symbolTable.createLabel(symbolAddress, label, classNamespace,
						SourceType.ANALYSIS);
				demangledSymbol.setPrimary();
				return demangledSymbol;
			} catch (InvalidInputException e) {
				return null;
			}

		}
		return null;
	}

	// TODO: can this be used for regular ones too?
	private Symbol findTypeinfoSymbolUsingMangledNamespaceString(String mangledNamespace, String namespaceName)
			throws CancelledException {

		Symbol specialTypeinfoSymbol = findTypeinfoUsingMangledString(mangledNamespace);
		if (specialTypeinfoSymbol == null) {
			Msg.debug(this, namespaceName + " typeinfo not found");
			return null;
		}

		return specialTypeinfoSymbol;

	}

	private GccTypeinfo createGccTypeinfo(Symbol typeinfoSymbol, boolean isSpecial) {

		Address typeinfoAddress = typeinfoSymbol.getAddress();
		boolean isExternal = typeinfoAddress.isExternalAddress() || inExternalBlock(typeinfoAddress);

		GccTypeinfo gccTypeinfo = new GccTypeinfo(typeinfoSymbol.getAddress(), typeinfoSymbol.getParentNamespace(),
				isSpecial, !isExternal);
		return gccTypeinfo;
	}

	private void setComponentOffset() {

		String processor = program.getLanguage().getProcessor().toString();
		if (processor.equals("x86") || processor.equals("MIPS") || processor.equals("PowerPC")
				|| processor.equals("RISCV")) {

			if (defaultPointerSize == 4) {
				componentOffset = 8;
				return;
			}
			if (defaultPointerSize == 8) {
				componentOffset = 16;
				return;
			}
		}
		if (processor.equals("AARCH64")) {
			componentOffset = 16;
			return;
		}
		if (processor.equals("ARM")) {
			componentOffset = 8;
			return;
		}

	}

	/**
	 * Method to set the global variable isGcc
	 */
	private boolean isGcc() {

		boolean isGcc;

		boolean isCompilerSpecGcc = program.getCompilerSpec().getCompilerSpecID().getIdAsString()
				.equalsIgnoreCase("gcc");
		if (isCompilerSpecGcc) {
			return true;
		}

		String compiler = program.getCompiler();
		if (compiler != null && compiler.contains("gcc")) {
			return true;
		}

		MemoryBlock commentBlock = program.getMemory().getBlock(".comment");
		if (commentBlock == null) {
			return false;
		}

		if (!commentBlock.isInitialized()) {
			return false;
		}

		// check memory bytes in block for GCC: bytes
		byte[] gccBytes = { (byte) 0x47, (byte) 0x43, (byte) 0x43, (byte) 0x3a };
		byte[] maskBytes = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

		Address found = program.getMemory().findBytes(commentBlock.getStart(), commentBlock.getEnd(), gccBytes,
				maskBytes, true, monitor);
		if (found == null) {
			isGcc = false;
		} else {
			isGcc = true;
		}

		return isGcc;
	}

	/**
	 * Method to check for at least one special RTTI vtable
	 * 
	 * @return true if the program has at least one special vtable, false if none
	 * @throws CancelledException           if cancelled
	 * @throws InvalidInputException        if bad characters creating labels
	 * @throws UnsupportedEncodingException
	 */
	private boolean hasSpecialTypeinfos()
			throws CancelledException, InvalidInputException, UnsupportedEncodingException {

		SymbolIterator symbolIterator = symbolTable.getSymbolIterator("*N10__cxxabiv117__class_type_infoE*", true);
		if (symbolIterator.hasNext()) {
			return true;
		}

		if (findSingleMangledString(MANGLED_CLASS_TYPEINFO_NAMESPACE) != null) {
			return true;
		}

		symbolIterator = symbolTable.getSymbolIterator("*N10__cxxabiv120__si_class_type_infoE*", true);
		if (symbolIterator.hasNext()) {
			return true;
		}

		if (findSingleMangledString("N10__cxxabiv120__si_class_type_infoE") != null) {
			return true;
		}

		symbolIterator = symbolTable.getSymbolIterator("*N10__cxxabiv121__vmi_class_type_infoE*", true);
		if (symbolIterator.hasNext()) {
			return true;
		}

		if (findSingleMangledString("N10__cxxabiv121__vmi_class_type_infoE") != null) {
			return true;
		}

		return false;

	}


	List<Symbol> getSpecialTypeinfoSymbols() {

		List<Symbol> symbols = new ArrayList<Symbol>();

		if (class_type_info != null) {
			Symbol symbol = symbolTable.getPrimarySymbol(class_type_info);
			if (symbol != null && symbol.getName().equals("typeinfo")) {
				symbols.add(symbol);
			}
		}
		if (si_class_type_info != null) {
			Symbol symbol = symbolTable.getPrimarySymbol(si_class_type_info);
			if (symbol != null && symbol.getName().equals("typeinfo")) {
				symbols.add(symbol);
			}
		}
		if (vmi_class_type_info != null) {
			Symbol symbol = symbolTable.getPrimarySymbol(vmi_class_type_info);
			if (symbol != null && symbol.getName().equals("typeinfo")) {
				symbols.add(symbol);
			}
		}

		return symbols;
	}

	//TODO: split out methods
	private void updateClassesWithParentsAndFlags(List<GccTypeinfo> typeinfos) throws CancelledException  {

		// add properties and parents to each class
		for(GccTypeinfo typeinfo : typeinfos) {

			monitor.checkCancelled();
			Address typeinfoAddress = typeinfo.getAddress();

			// skip the typeinfo symbols from the three special typeinfos
			if (typeinfo.isSpecialTypeinfo()) {
				continue;
			}

			Namespace classNamespace = typeinfo.getNamespace();

			RecoveredClass recoveredClass = getClass(classNamespace);

			if (recoveredClass == null) {
				throw new IllegalArgumentException("RecoveredClass should already exist for " + classNamespace.getName(true));
			}
			
			if (typeinfo.isClassTypeinfo()){
				recoveredClass.setHasSingleInheritance(true);
				recoveredClass.setHasMultipleInheritance(false);
				recoveredClass.setHasMultipleVirtualInheritance(false);
				recoveredClass.setInheritsVirtualAncestor(false);

				// no parents so just add empty order and parent maps to the class maps
				Map<Integer, RecoveredClass> orderToParentMap = new HashMap<Integer, RecoveredClass>();

				classToParentOrderMap.put(recoveredClass, orderToParentMap);

				Map<RecoveredClass, Long> parentToOffsetMap = new HashMap<RecoveredClass, Long>();

				classToParentOffsetMap.put(recoveredClass, parentToOffsetMap);
				continue;
			}

			// per docs those on this list are
			// classes containing only a single, public, non-virtual base at offset zero
			if (typeinfo.isSiClassTypeinfo()) {
				
				List<BaseTypeinfo> baseTypeinfos = typeinfo.getBaseTypeinfos();
				if(baseTypeinfos.size() != 1) {
					throw new IllegalArgumentException("SiClassTypeinfo " + classNamespace.getName(true) + " should have exactly one parent");
				}

				GccTypeinfo siParentTypeinfo = baseTypeinfos.get(0).getBaseTypeinfo();
				RecoveredClass parentClass = getClass(siParentTypeinfo.getNamespace());

				// parent isn't a known class - possibly is an external parent
				if (parentClass == null) {
					throw new IllegalArgumentException("RecoveredClass should already exist for " + siParentTypeinfo.getNamespace().getName(true));
				}

				updateClassWithParent(parentClass, recoveredClass);
				recoveredClass.setHasSingleInheritance(true);
				recoveredClass.setHasMultipleInheritance(false);
				recoveredClass.setHasMultipleVirtualInheritance(false);
				parentClass.setIsPublicClass(true);
				recoveredClass.addParentToBaseTypeMapping(parentClass, false);
				
				// TODO: make method to check all ancestors not just parent
				if(siParentTypeinfo.isVmiClassTypeinfo()) {
					recoveredClass.setInheritsVirtualAncestor(true);
				}

				// add order to parent and parent offset
				Map<Integer, RecoveredClass> orderToParentMap = new HashMap<Integer, RecoveredClass>();
				orderToParentMap.put(0, parentClass);
				classToParentOrderMap.put(recoveredClass, orderToParentMap);

				Map<RecoveredClass, Long> parentToOffsetMap = new HashMap<RecoveredClass, Long>();
				parentToOffsetMap.put(parentClass, 0L);

				classToParentOffsetMap.put(recoveredClass, parentToOffsetMap);

				continue;
			}

			if (typeinfo.isVmiClassTypeinfo()) {

				List<RecoveredClass> parents = addClassParentsAndFlagsForVmiClass(recoveredClass, typeinfo);

				if (parents.isEmpty()) {
					Msg.debug(this,
							"Could not get vmi parent from typeinfoAddress - removing class from list"
									+ typeinfoAddress.toString());
					recoveredClasses.remove(recoveredClass);
					continue;
				}

			}
		}

		return;

	}

	/**
	 * Method to process the primary vtable for each "vtable" label
	 * 
	 * @throws CancelledException    if cancelled
	 * @throws InvalidInputException if invalid symbol input
	 * 
	 * @throws Exception             if Data cannot be created
	 */
	private List<Vtable> processVtables(List<GccTypeinfo> typeinfos)
			throws CancelledException, InvalidInputException {

		List<Vtable> vtables = new ArrayList<Vtable>();

		if (typeinfos.isEmpty()) {
			return vtables;
		}

		for (GccTypeinfo typeinfo : typeinfos) {
			monitor.checkCancelled();

			Address typeinfoAddress = typeinfo.getAddress();
			Structure typeinfoStructure = getTypeinfoStructure(typeinfoAddress);

			if (typeinfoStructure == null) {
				Msg.error(this, "No structure at typeinfoAddress: " + typeinfoAddress);
				continue;
			}

			if (!isValidClassInfoStructure(typeinfoStructure)) {
				Msg.error(this, "No typeinfo structure at typeinfoAddress: " + typeinfoAddress);
				continue;
			}

			if (typeinfo.isSpecialTypeinfo) {
				Msg.debug(this, "Skipping special typeinfos -- vtables already processed");
				continue;
			}
			
			int numRefs = getNumberOfRefsByBaseTypeinfos(typeinfo, typeinfos);

			List<Address> constructionVtables = new ArrayList<Address>();
			Map<Address, GccTypeinfoRef> map = getVtablesUsingTypeinfo(typeinfo);
			Address mainVtable = findMainVtable(typeinfo, map, constructionVtables, numRefs);

			if (mainVtable != null) {

				Vtable vtable = processMainVtable(mainVtable, map.get(mainVtable));
				if (vtable == null) {
					Msg.debug(this,
							"MISSING expected vtable for simple class " + typeinfo.getNamespace().getName(true));
					continue;
				}

				vtables.add(vtable);
				applyVtableMarkup(vtable);

				
			}
			for (Address vtableAddress : constructionVtables) {

				Vtable constructionVtable = processVtable(vtableAddress, map.get(vtableAddress), true);
				if (constructionVtable == null || !constructionVtable.isValid()) {

					Msg.debug(this, "Invalid construction vtable at " + vtableAddress);
					continue;
				}
				vtables.add(constructionVtable);
				
				
			}

		}
		
		List<Vtt> vtts = findVtts(vtables);
		updateConstructionVtablesWithNamespace(vtts,vtables);
		//TODO:  update rest of vtt names my trying to match up with ones needing but missing VTT 

		return vtables;
	}
	
	private List<Vtt> findVtts(List<Vtable> vtables) throws CancelledException, InvalidInputException {

		List<Vtt> vtts = findVttsUsingSymbols();
		if (vtts.isEmpty()) {
		//	vtts = findVttsUsingReferences(vtables);
			
			 vtts = findVttsWithoutSymbols(vtables);
			
		}

		// check vtts for run of pointers to other vtables /vfunctions and self and
		// populate the vtt objects with the list of pointers in the vtt
		// if possible update vtt with correct namespace
		// TODO: add list of subVtt addrs to Vtt obj
		updataVttPointers(vtts, vtables);

		return vtts;
	}
	
	private void updateConstructionVtablesWithNamespace(List<Vtt> vtts, List<Vtable> vtables) throws CancelledException, InvalidInputException {
		for (Vtable vtable : vtables) {
			monitor.checkCancelled();

			if (vtable.isConstructionVtable()) {
				Vtt vtt = getVttContainingVtable(vtts, vtable);
				Namespace vttNamespace = globalNamespace;
				if (vtt != null) {
					vttNamespace = vtt.getNamespace();
				}
				else {
					Msg.debug(this, "Cannot find vtt for vtable at " + vtable.getAddress());
				}
				Namespace typeinfoNamespace = vtable.getReferencedTypeinfo().getNamespace();
				Namespace constructionNamespace = createConstructionNamespace(typeinfoNamespace, vttNamespace);
				if (constructionNamespace != null) {
					vtable.setNamespace(constructionNamespace);
				}
				else {
					Msg.debug(this, "Cannot create construction namespace for vtable at " + vtable.getAddress());
				}
				
			}
			applyVtableMarkup(vtable);
		}
	}
	
	private boolean isSelfReferencing(Address address) {
		Address referencedAddress = getReferencedAddress(address);
		if(referencedAddress == null) {
			return false;
		}
		if(referencedAddress.equals(address)) {
			return true;
		}
		return false;
	}
	
	private List<Vtt> findVttsUsingSymbols() throws CancelledException{
		
		List<Vtt> vtts = new ArrayList<Vtt>();
		SymbolIterator symbols = symbolTable.getSymbols("VTT");
		while(symbols.hasNext()) {
			monitor.checkCancelled();
			
			Symbol symbol = symbols.next();
			
			Vtt vtt = new Vtt(symbol.getAddress(), symbol.getParentNamespace());
			vtts.add(vtt);
		}
		
		return vtts;
	}
	
	private List<Vtt> findVttsWithoutSymbols(List<Vtable> vtables) throws CancelledException, InvalidInputException {

		
		List<Address> vttStarts = findVttStarts(vtables);
		
		List<Vtt> vtts = new ArrayList<Vtt>();
		for (Address vttAddress : vttStarts) {
			monitor.checkCancelled();
			
			Namespace namespace = getVttNamespace(vttAddress, vtables);
				
			
			Vtt vtt = new Vtt(vttAddress, namespace);
			vtts.add(vtt);
			symbolTable.createLabel(vttAddress, "VTT", namespace, SourceType.ANALYSIS);
			api.setPlateComment(vttAddress, "VTT for " + namespace.getName(true));
			
		}
		return vtts;
	}
	
	private Namespace getVttNamespace(Address vttAddress, List<Vtable> vtables) throws CancelledException {
		
		Namespace namespace = globalNamespace;
		
		Address referencedAddress = getReferencedAddress(vttAddress);
		if(referencedAddress == null) {
			throw new IllegalArgumentException("There should be a pointer here " + vttAddress);
		}
		
		Vtable referencedVtable = getVtableContaining(vtables,referencedAddress);
		if(referencedVtable != null && referencedVtable.isPrimary()) {
			namespace = referencedVtable.getNamespace();
		}
		return namespace;
	}
	
	private List<Address> findVttStarts(List<Vtable> vtables) throws CancelledException{
		
		List<Address> vttStarts = new ArrayList<Address>();
		
		List<Address> addressesToCheck = new ArrayList<Address>();
		
		// make a list of possible vtt starting addresses
		for(Vtable vtable : vtables) {
			
			monitor.checkCancelled();
			
			addressesToCheck.add(vtable.getAddress().add(vtable.getLength()));
			GccTypeinfo referencedTypeinfo = vtable.getReferencedTypeinfo();
			Address typeinfo = referencedTypeinfo.getAddress();
			Data typeinfoStruct = program.getListing().getDataAt(typeinfo);
			if(typeinfoStruct == null) {
				continue;
			}
			addressesToCheck.add(typeinfo.add(typeinfoStruct.getLength()));
		}
		
		boolean keepChecking = true;
		int numToCheck = addressesToCheck.size();
		while(keepChecking) {
			for(Address possibleVttStart : addressesToCheck) {
			
				monitor.checkCancelled();
			
				if(isPossibleVttStart(possibleVttStart, vtables, vttStarts)) {
					vttStarts.add(possibleVttStart);
				}
			}
		
			addressesToCheck.removeAll(vttStarts);
			if(addressesToCheck.size() == numToCheck) {
				keepChecking = false;
			}
			numToCheck = addressesToCheck.size();
		}
	
		return vttStarts;
		
	}

	private Vtt getVttContainingVtable(List<Vtt> vtts, Vtable vtable) throws CancelledException {

		for (Vtt vtt : vtts) {
			monitor.checkCancelled();

			if (vtt.containsPointer(vtable.getAddress())) {
				return vtt;
			}
			if (vtable.hasVfunctions() && vtt.containsPointer(vtable.getVfunctionTop())) {
				return vtt;
			}
		}
		return null;
	}

	private void updataVttPointers(List<Vtt> vtts, List<Vtable> vtables) throws CancelledException {

		// make list of all vtable tops and vftable tops
		List<Address> vtableAndVftableAddrs = getListOfVtableAndVftableTops(vtables);
		List<Address> vttStarts = getVttAddresses(vtts);
		

		// if vtt references one of the vtable or vftable tops OR if it references
		// itself add the ref'd addr to the list in vtt obj
		for (Vtt vtt : vtts) {
			monitor.checkCancelled();
			Address pointerAddress = vtt.getAddress();
			Address referencedAddress = getReferencedAddress(pointerAddress);
			while (referencedAddress != null && (vtableAndVftableAddrs.contains(referencedAddress)
					|| referencedAddress.equals(vtt.getAddress()) || isSelfReferencing(pointerAddress) || vttStarts.contains(referencedAddress))) {
				vtt.addPointerToList(referencedAddress);
				pointerAddress = pointerAddress.add(defaultPointerSize);
				referencedAddress = getReferencedAddress(pointerAddress);
			}
		}
	}
	
	private List<Address> getVtableAddresses(List<Vtable> vtables) throws CancelledException {
		List<Address> vtableStarts = new ArrayList<Address>();

		for (Vtable vtable : vtables) {
			monitor.checkCancelled();

			vtableStarts.add(vtable.getAddress());
		}
		return vtableStarts;
	}

	private List<Address> getVttAddresses(List<Vtt> vtts) throws CancelledException {
		List<Address> vttStarts = new ArrayList<Address>();

		for (Vtt vtt : vtts) {
			monitor.checkCancelled();

			vttStarts.add(vtt.getAddress());
		}
		return vttStarts;
	}
	
	
	private boolean isPossibleVttStart(Address address, List<Vtable> vtables, List<Address> knownVtts) throws CancelledException {
		
		// make list of all vtable tops and vftable tops
		List<Address> vtableAndVftableAddrs = getListOfVtableAndVftableTops(vtables);
		
		if(isSelfReferencing(address)) {
			return true;
		}
		
		Address referencedAddress = getReferencedAddress(address);
		if(referencedAddress != null && (vtableAndVftableAddrs.contains(referencedAddress) || knownVtts.contains(referencedAddress))){
			return true;
		}
		
		return false;
	
	}
private Address getReferencedAddress(Address address) {
		
		int addressSize = address.getSize();
		Memory memory = program.getMemory();
		try {
			
			if (addressSize == 32) {
				long offset32 = memory.getInt(address);
				Address newAddr = address.getNewAddress(offset32);
				if(memory.contains(newAddr)) {
					return newAddr;
				}
				return null;

			}
			else if (addressSize == 64) {

				long offset64 = memory.getLong(address);
				Address newAddr = address.getNewAddress(offset64);
				if(memory.contains(newAddr)) {
					return newAddr;
				}
				return null;

			}
			else {
				return null;
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	private List<Address> getListOfVtableAndVftableTops(List<Vtable> vtables) throws CancelledException {
		// make list of all vtable tops and vftable tops
		List<Address> vtableAndVftableAddrs = new ArrayList<Address>();
		for (Vtable vtable : vtables) {
			monitor.checkCancelled();

			vtableAndVftableAddrs.add(vtable.getAddress());
			if (vtable.hasVfunctions()) {
				vtableAndVftableAddrs.add(vtable.getVfunctionTop());
			}

			vtableAndVftableAddrs.addAll(getListOfVtableAndVftableTops(vtable.getInternalVtables()));
		}
		return vtableAndVftableAddrs;
	}

	private Vtable processMainVtable(Address vtableAddress, GccTypeinfoRef typeinfoRef) throws CancelledException {
		Vtable vtable = processVtable(vtableAddress, typeinfoRef, false);
		if (vtable == null || !vtable.isValid()) {

			Msg.debug(this, "Invalid vtable at " + vtableAddress);
			return null;
		}
		return vtable;
	}

	private void applyVtableMarkup(Vtable vtable) throws InvalidInputException {

		boolean hasKnownConstructionSymbol = false;
		if (vtable.isConstructionVtable()) {
			Symbol vtableSymbol = symbolTable.getPrimarySymbol(vtable.getAddress());
			if (vtableSymbol != null && !vtableSymbol.getParentNamespace().isGlobal()) {
				hasKnownConstructionSymbol = true;
				vtable.setNamespace(vtableSymbol.getParentNamespace());
			}
		}
		createVtableLabel(vtable);
		createVtableComment(vtable);
		createVfunctionSymbol(vtable);

		for (Vtable internalVtable : vtable.getInternalVtables()) {

			if (hasKnownConstructionSymbol) {
				internalVtable.setNamespace(vtable.getNamespace());
			}
			createVtableLabel(internalVtable);
			createVtableComment(internalVtable);
			createVfunctionSymbol(internalVtable);
		}
	}


	/**
	 * method to find the main vtable for the given typeinfo and if any, add the
	 * construction ones to the passed in list
	 * 
	 * @param typeinfo
	 * @param constructionVtables
	 * @return address of main vtable for this class
	 * @throws CancelledException
	 */

	private Address findMainVtable(GccTypeinfo typeinfo, Map<Address, GccTypeinfoRef> map,
			List<Address> constructionVtables, int numBaseRefs) throws CancelledException {

		List<Address> vtableList = new ArrayList<Address>(map.keySet());

		// if any have known symbols then return
		// can be single main vtable, main vtable and one or more construction vtables,
		// or no main vtable and one or
		// more construction vtables
		Address mainVtable = getMainVtableUsingSymbols(vtableList, constructionVtables);
		if (mainVtable != null || !constructionVtables.isEmpty()) {
			return mainVtable;
		}
		

		// no const vtables for this typeinfo if only one in list
		if (vtableList.size() == 1 && (typeinfo.isClassTypeinfo() || typeinfo.isSiClassTypeinfo())
				&& typeinfo.getNumDirectVirtualBases() == 0) {
			return vtableList.get(0);
		}

		// if more than one add all to the construction list then remove the main one
		// when found
		constructionVtables.addAll(vtableList);
		

		Map<Address, List<Address>> vtableRefsMap = createMapOfVtableRefs(vtableList);
		Map<Address, List<Address>> vftableRefsMap = createMapOfVftableRefs(vtableList, map);

		// if only one vtable has have all func refs it is main one
		mainVtable = findMainVtableOnlyFunctionRefs(vtableRefsMap, vftableRefsMap);
		if (mainVtable != null) {
			constructionVtables.remove(mainVtable);
			return mainVtable;
		}
		// if only one vtable has function refs then it is the main vtable
		mainVtable = findMainVtableUsingFunctionRefs(vtableRefsMap, vftableRefsMap);
		if (mainVtable != null) {
			constructionVtables.remove(mainVtable);
			return mainVtable;
		}
		// see if there are no refs for any of them - new way
		mainVtable = findMainVtableNoRefs(vtableRefsMap, vftableRefsMap);
		if (mainVtable != null) {
			constructionVtables.remove(mainVtable);
			return mainVtable;
		}
		

		if(vtableList.size() == 1) {
			if(numBaseRefs == 0) {
				return vtableList.get(0);
			}
			constructionVtables.add(vtableList.get(0));
			return null;
			
		}

		// if still no clear winner and there is only one on list try using internal vtables
		// make a temp vtable to pull out any internal vtables and try to test them
		if (vtableList.size() == 1) {
			Address vtableAddress = vtableList.get(0);
			GccTypeinfoRef typeinfoRef = map.get(vtableAddress);
			Vtable vtable = new Vtable(program, vtableAddress, typeinfoRef, false, false, false, monitor);
			if(!vtable.isValid()) {
				return null;
			}
			List<Vtable> internalVtables = vtable.getInternalVtables();
			List<Address> internalVtableAddrs = new ArrayList<Address>();
			for(Vtable internalVtable : internalVtables) {
				Address internalVtableAddress = internalVtable.getAddress();
				internalVtableAddrs.add(internalVtableAddress);
				
				Address internalTypinfoRef = internalVtable.getTypeinfoRefAddress();
				GccTypeinfoRef gccTypeinfoRef = map.get(internalVtableAddress);
				if (gccTypeinfoRef == null) {
					map.put(internalVtableAddress, new GccTypeinfoRef(internalTypinfoRef, typeinfo, true));
				} else {
					if (gccTypeinfoRef.getAddress().compareTo(internalTypinfoRef) > 0) {
						map.put(internalVtableAddress, new GccTypeinfoRef(internalTypinfoRef, typeinfo, true));
					}
				}
				
			}
			if (internalVtables.size() > 0) {
				Map<Address, List<Address>> internalVtableRefsMap = createMapOfVtableRefs(internalVtableAddrs);
				Map<Address, List<Address>> internalVftableRefsMap = createMapOfVftableRefs(internalVtableAddrs, map);
				
				// this isn't the mainVtable - just using to test if functions are ref
				mainVtable = findMainVtableUsingFunctionRefs(internalVtableRefsMap, internalVftableRefsMap);
				if (mainVtable != null) {
					mainVtable = vtableAddress;
					constructionVtables.remove(mainVtable);
					return mainVtable;
				}
			}
		}

		// no main vtable - all construction vtables
		return null;
	}
	
	
	private int getNumberOfRefsByBaseTypeinfos(GccTypeinfo typeinfo, List<GccTypeinfo> typeinfos) throws CancelledException {
		
		int numRefs = 0;
		for(GccTypeinfo typinfo : typeinfos) {
			monitor.checkCancelled();
			
			if(typinfo.isSpecialTypeinfo()) {
				continue;
			}
			
			if(!typinfo.isVmiClassTypeinfo()) {
				continue;
			}
			
			List<BaseTypeinfo> baseTypeinfos = typinfo.getBaseTypeinfos();
			for(BaseTypeinfo baseTypeinfo : baseTypeinfos) {
				monitor.checkCancelled();
				
				if(baseTypeinfo.getBaseTypeinfo().equals(typeinfo)){
					numRefs++;
				}
			}
		}
		return numRefs;
	}

	private Map<Address, List<Address>> createMapOfVtableRefs(List<Address> vtableList) throws CancelledException {

		Map<Address, List<Address>> map = new HashMap<Address, List<Address>>();
		for (Address vtableAddr : vtableList) {
			monitor.checkCancelled();

			map.put(vtableAddr, getAllReferencesTo(vtableAddr));
		}

		return map;
	}

	private Map<Address, List<Address>> createMapOfVftableRefs(List<Address> vtableList,
			Map<Address, GccTypeinfoRef> map) throws CancelledException {

		Map<Address, List<Address>> refmap = new HashMap<Address, List<Address>>();
		for (Address vtableAddr : vtableList) {
			monitor.checkCancelled();

			GccTypeinfoRef typeinfoRef = map.get(vtableAddr);
			Address topOfVfunctions = typeinfoRef.getAddress().add(defaultPointerSize);

			// null means no vfunctions for this vtable
			if (!isVirtualFunctionTable(topOfVfunctions)) {
				refmap.put(vtableAddr, null);
				continue;
			}

			refmap.put(vtableAddr, getAllReferencesTo(topOfVfunctions));
		}

		return refmap;
	}

	private Address findMainVtableOnlyFunctionRefs(Map<Address, List<Address>> vtableRefsMap,
			Map<Address, List<Address>> vftableRefsMap) throws CancelledException {

		List<Address> possibleMains = new ArrayList<Address>();

		Set<Address> vtables = vtableRefsMap.keySet();

		for (Address vtableAddr : vtables) {
			monitor.checkCancelled();

			List<Address> refsToVtable = vtableRefsMap.get(vtableAddr);

			if (hasAllFunctionRefs(refsToVtable)) {
				possibleMains.add(vtableAddr);
				continue;
			}

			// use typenfo ref to get top of vfunctions (if there are any)
			List<Address> refsToVftable = vftableRefsMap.get(vtableAddr);

			if (refsToVftable != null) { // null if no vftable for this vtable

				if (hasAllFunctionRefs(refsToVftable)) {
					possibleMains.add(vtableAddr);
					continue;
				}
			}
		}
		if (possibleMains.size() == 1) {
			return possibleMains.get(0);
		}

		return null;
	}

	private Address findMainVtableUsingFunctionRefs(Map<Address, List<Address>> vtableRefsMap,
			Map<Address, List<Address>> vftableRefsMap) throws CancelledException {

		List<Address> possibleMains = new ArrayList<Address>();

		Set<Address> vtables = vtableRefsMap.keySet();

		for (Address vtableAddr : vtables) {
			monitor.checkCancelled();

			List<Address> refsToVtable = vtableRefsMap.get(vtableAddr);

			if (hasAnyFunctionRefs(refsToVtable)) {
				possibleMains.add(vtableAddr);
				continue;
			}

			// use typenfo ref to get top of vfunctions (if there are any)
			List<Address> refsToVftable = vftableRefsMap.get(vtableAddr);

			if (refsToVftable != null) { // null if no vftable for this vtable

				if (hasAnyFunctionRefs(refsToVftable)) {
					possibleMains.add(vtableAddr);
					continue;
				}
			}
		}
		if (possibleMains.size() == 1) {
			return possibleMains.get(0);
		}

		return null;
	}

	private Address findMainVtableNoRefs(Map<Address, List<Address>> vtableRefsMap,
			Map<Address, List<Address>> vftableRefsMap) throws CancelledException {

		List<Address> possibleMains = new ArrayList<Address>();

		Set<Address> vtables = vtableRefsMap.keySet();

		for (Address vtableAddr : vtables) {
			monitor.checkCancelled();

			List<Address> refsToVtable = vtableRefsMap.get(vtableAddr);

			if (!refsToVtable.isEmpty()) {
				continue;
			}

			// use typenfo ref to get top of vfunctions (if there are any)
			List<Address> refsToVftable = vftableRefsMap.get(vtableAddr);

			if (refsToVftable == null || refsToVftable.isEmpty()) { // null if no vftable for this vtable
				possibleMains.add(vtableAddr);
				continue;

			}
		}
		if (possibleMains.size() == 1) {
			return possibleMains.get(0);
		}

		return null;
	}

	private boolean isVirtualFunctionTable(Address address) throws CancelledException {

		if (isPossibleFunctionPointer(address)) {
			return true;
		}

		MemoryBlock currentBlock = program.getMemory().getBlock(address);

		// may start with null pointers
		while (isPossibleNullPointer(address)) {
			monitor.checkCancelled();

			if (!currentBlock.contains(address)) {
				return false;
			}
			address = address.add(defaultPointerSize);
		}

		// if item directly after nulls is function ptr then is function table
		if (isPossibleFunctionPointer(address)) {
			return true;
		}
		return false;

	}

	private Address getMainVtableUsingSymbols(List<Address> vtableAddresses, List<Address> constructionVtables)
			throws CancelledException {

		List<Address> mainVtableCandidates = new ArrayList<Address>();
		for (Address vtableAddress : vtableAddresses) {
			monitor.checkCancelled();

			Symbol primarySymbol = symbolTable.getPrimarySymbol(vtableAddress);
			if (primarySymbol != null && primarySymbol.getName().equals(VTABLE_LABEL)) {
				mainVtableCandidates.add(vtableAddress);
			}
			if (primarySymbol != null && primarySymbol.getName().equals("construction-" + VTABLE_LABEL)) {
				constructionVtables.add(vtableAddress);
			}
		}

		if (mainVtableCandidates.size() != 1) {
			return null;
		}

		return mainVtableCandidates.get(0);
	}


	private Map<Address, GccTypeinfoRef> getVtablesUsingTypeinfo(GccTypeinfo typeinfo) throws CancelledException {

		Map<Address, GccTypeinfoRef> map = new HashMap<Address, GccTypeinfoRef>();
		Set<Address> typeinfoRefs = findTypeinfoRefsPossiblyInVtables(typeinfo);

		for (Address typeinfoRef : typeinfoRefs) {
			monitor.checkCancelled();

			// get top of vtable
			Address vtableAddress = getPrimaryVtableAddress(typeinfoRef);

			// no vtable associated with this typeinfo
			if (vtableAddress == null) {
				continue;
			}

			GccTypeinfoRef gccTypeinfoRef = map.get(vtableAddress);
			if (gccTypeinfoRef == null) {
				map.put(vtableAddress, new GccTypeinfoRef(typeinfoRef, typeinfo, true));
			} else {
				if (gccTypeinfoRef.getAddress().compareTo(typeinfoRef) > 0) {
					map.put(vtableAddress, new GccTypeinfoRef(typeinfoRef, typeinfo, true));
				}
			}

		}
		return map;
	}

	private boolean hasAllFunctionRefs(Collection<Address> refs) throws CancelledException {

		if (refs == null || refs.isEmpty()) {
			return false;
		}

		for (Address ref : refs) {
			monitor.checkCancelled();
			if (ref.isExternalAddress()) {
				continue;
			}
			Function function = functionManager.getFunctionContaining(ref);
			if (function == null) {
				return false;
			}
		}
		return true;
	}

	private boolean hasAnyFunctionRefs(Collection<Address> refs) throws CancelledException {

		if (refs == null || refs.isEmpty()) {
			return false;
		}
		for (Address ref : refs) {
			monitor.checkCancelled();

			if (ref.isExternalAddress()) {
				continue;
			}
			Function function = functionManager.getFunctionContaining(ref);
			if (function != null) {
				return true;
			}
		}
		return false;
	}

	private Vtable getVtable(List<Vtable> vtables, Namespace classNamespace) throws CancelledException {

		for (Vtable vtable : vtables) {
			monitor.checkCancelled();

			if (vtable.getNamespace().equals(classNamespace) && vtable.isPrimary() && !vtable.isConstructionVtable()) {
				return vtable;
			}
		}
		return null;
	}
	
	private Vtable getVtable(List<Vtable> vtables, Address address) throws CancelledException {

		for (Vtable vtable : vtables) {
			monitor.checkCancelled();

			if (vtable.getAddress().equals(address)) {
				return vtable;
			}
		}
		return null;
	}
	
	private Vtable getVtableContaining(List<Vtable> vtables, Address address) throws CancelledException {
		for (Vtable vtable : vtables) {
			
			monitor.checkCancelled();
			
			AddressSet vtableAddrs = new AddressSet(vtable.getAddress(), vtable.getAddress().add(vtable.getLength()));

			if (vtableAddrs.contains(address)) {
				return vtable;
			}
		}
		return null;
	}


	private void createVtableComment(Vtable vtable) {

		if (!vtable.isPrimary()) {
			return;
		}

		Address vtableAddress = vtable.getAddress();
		Namespace classNamespace = vtable.getNamespace();

		if (classNamespace == null) {
			return;
		}

		String plateComment = api.getPlateComment(vtableAddress);
		if (plateComment != null && plateComment.contains(VTABLE_LABEL)
				&& plateComment.contains(classNamespace.getName())) {
			return;
		}

		String constructionString = "";
		if (vtable.isConstructionVtable() != null && vtable.isConstructionVtable()) {
			constructionString = "construction-";
		}
		String vtableComment = VTABLE_LABEL;

		api.setPlateComment(vtableAddress, constructionString + vtableComment + " for " + classNamespace.getName(true));

	}

	private void createVtableLabel(Vtable vtable) throws InvalidInputException {

		Address vtableAddress = vtable.getAddress();

		Namespace classNamespace = vtable.getNamespace();

		if (classNamespace == null) {
			return;
		}

		String vtableLabel = VTABLE_LABEL;

		Symbol primarySymbol = symbolTable.getPrimarySymbol(vtableAddress);
		if (primarySymbol != null && primarySymbol.getName().contains(vtableLabel)
				&& primarySymbol.getParentNamespace().equals(classNamespace)) {
			return;
		}

		String constructionString = "";
		if (vtable.isConstructionVtable() != null && vtable.isConstructionVtable()) {
			constructionString = "construction-";
		}

		String internalString = "";
		if (!vtable.isPrimary()) {
			internalString = "internal_";
		}

		symbolTable.createLabel(vtableAddress, internalString + constructionString + VTABLE_LABEL, classNamespace,
				SourceType.ANALYSIS);

	}

	private void createVfunctionSymbol(Vtable vtable) throws InvalidInputException {

		if (!vtable.hasVfunctions()) {
			return;
		}

		Namespace classNamespace = vtable.getNamespace();

		if (classNamespace == null) {
			return;
		}

		String constructionString = "";
		if (vtable.isConstructionVtable() != null && vtable.isConstructionVtable()) {
			constructionString = "construction-";
		}

		String internalString = "";
		if (!vtable.isPrimary()) {
			internalString = "internal_";
		}

		symbolTable.createLabel(vtable.getVfunctionTop(), internalString + constructionString + VFTABLE_LABEL,
				classNamespace, SourceType.ANALYSIS);

	}

	List<Symbol> getTypeinfosByType(List<Symbol> typeinfoSymbols, String typeinfoType) throws CancelledException {

		List<Symbol> subsetByType = new ArrayList<Symbol>();

		for (Symbol symbol : typeinfoSymbols) {
			monitor.checkCancelled();

			String type = typeinfoToStructuretypeMap.get(symbol.getAddress());
			if (type.equals(typeinfoType)) {
				subsetByType.add(symbol);
			}
		}

		return subsetByType;
	}


	private Address getPrimaryVtableAddress(Address typeinfoRef) throws CancelledException {

		if (typeinfoRef == null) {
			return null;
		}
		// get the data containing the typeinfo reference
		Data dataContaining = extendedFlatAPI.getDataContaining(typeinfoRef);
		if (dataContaining != null) {

			// get the top address of the containing data
			Address dataAddress = dataContaining.getAddress();

			// if it has a vtable label then return the data address
			boolean hasVtableLabel = hasSymbolWithName(dataAddress, VTABLE_LABEL)
					|| hasSymbolWithName(dataAddress, CONSTRUCTION_VTABLE_LABEL);
			if (hasVtableLabel) {
				return dataAddress;
			}

			// if data has imported symbol and no symbols named vtable then it isn't a
			// vtable
			// checking this way checks both imported actual symbols and imported mangled
			// symbols with analysis demangled symbols
			if (hasImportedSymbol(dataAddress) && !hasVtableLabel) {
				return null;
			}

		}

		// check the long just before and if not a zero then continue since the rest
		// are internal vtables and will get processed when the main one does
		Address offsetToTop = getAddress(typeinfoRef, 0 - defaultPointerSize);


		// check for appropriately sized long that is value 0 to make sure the
		// vtable the typeinfo ref is in is the main one and skip otherwise since non-zero
		// ones are internal vtables that will get processed with the main one
		if (!extendedFlatAPI.hasNumZeros(offsetToTop, defaultPointerSize)) {
			return null;
		}

		// start with last verified part of possible vtable and continue going backwards
		// until top of vtable is found
		// stop if top of mem block
		// stop if bytes are an address
		// stop if referenced
		// are they ever zero - not that i have seen so far in the last vftable
		// if pointer to something or valid address or is in a structure
		Address vtableAddress = offsetToTop;
		MemoryBlock currentBlock = program.getMemory().getBlock(typeinfoRef);

		while (vtableAddress != null) {

			boolean hasVtableLabel = hasSymbolWithName(vtableAddress, VTABLE_LABEL)
					|| hasSymbolWithName(vtableAddress, CONSTRUCTION_VTABLE_LABEL);
			if (hasVtableLabel) {
				return vtableAddress;
			}

			// if address has imported symbol and no symbols named vtable then it isn't a
			// vtable
			// checking this way checks both imported actual symbols and imported mangled
			// symbols with analysis demangled symbols
			if (hasImportedSymbol(vtableAddress) && !hasVtableLabel) {
				return null;
			}

			if (getPointerToDefinedMemory(vtableAddress) != null) {
				return vtableAddress.add(defaultPointerSize);
			}

			MemoryBlock memoryBlock = program.getMemory().getBlock(vtableAddress);
			if (memoryBlock == null || !memoryBlock.equals(currentBlock)) {
				return vtableAddress.add(defaultPointerSize);
			}

			Data data = api.getDataContaining(vtableAddress);
			if (data != null && !data.getDataType().getName().contains("undefined")) {
				return vtableAddress.add(defaultPointerSize);
			}

			vtableAddress = getAddress(vtableAddress, 0 - defaultPointerSize);
		}

		return null;

	}

	private boolean hasImportedSymbol(Address address) throws CancelledException {

		Symbol[] symbols = symbolTable.getSymbols(address);
		for (Symbol symbol : symbols) {
			monitor.checkCancelled();
			if (symbol.getSource() == SourceType.IMPORTED) {
				return true;
			}
		}
		return false;
	}

	private boolean hasSymbolWithName(Address address, String name) throws CancelledException {

		Symbol[] symbols = symbolTable.getSymbols(address);
		for (Symbol symbol : symbols) {
			monitor.checkCancelled();
			if (symbol.getName().equals(name)) {
				return true;
			}
		}
		return false;
	}

	private Address getPointerToDefinedMemory(Address address) {

		Address pointer = extendedFlatAPI.getPointer(address);
		if (pointer == null) {
			return null;
		}

		if (program.getMemory().getAllInitializedAddressSet().contains(pointer)) {
			return pointer;
		}

		return null;

	}

	private boolean isValidClassInfoStructure(Structure typeinfoStructure) {
		String typeinfoStructureName = typeinfoStructure.getName();

		if (typeinfoStructureName.equals(CLASS_TYPE_INFO_STRUCTURE)) {
			return true;
		}
		if (typeinfoStructureName.equals(SI_CLASS_TYPE_INFO_STRUCTURE)) {
			return true;
		}
		if (typeinfoStructureName.contains(VMI_CLASS_TYPE_INFO_STRUCTURE)) {
			return true;
		}
		return false;
	}

	private Namespace createConstructionNamespace(Namespace namespaceIn, Namespace vttNamespace) {

		String name = namespaceIn.getName() + "-in-" + vttNamespace.getName(true);

		Namespace newNamespace;
		try {
			newNamespace = NamespaceUtils.createNamespaceHierarchy(name, namespaceIn.getParentNamespace(), program,
					SourceType.ANALYSIS);
		} catch (InvalidInputException e) {
			return null;
		}
		return newNamespace;
	}

	private Structure getTypeinfoStructure(Address typeinfoAddress) {

		Data data = api.getDataAt(typeinfoAddress);

		if (!isTypeinfoStruct(data)) {
			return null;
		}

		return (Structure) data.getBaseDataType();

	}

	public Map<Address, Set<Address>> findTypeinfoReferencesNotInTypeinfoStructsOld(List<Address> typeinfoAddresses)
			throws CancelledException {

		MemoryBytePatternSearcher searcher = new MemoryBytePatternSearcher("Typeinfo References");

		AddressSet searchSet = new AddressSet();
		AddressSetView initializedSet = program.getMemory().getAllInitializedAddressSet();
		AddressRangeIterator addressRanges = initializedSet.getAddressRanges();
		while (addressRanges.hasNext()) {
			monitor.checkCancelled();
			AddressRange addressRange = addressRanges.next();
			searchSet.add(addressRange.getMinAddress(), addressRange.getMaxAddress());
		}
		Map<Address, Set<Address>> validTypeinfoRefMap = new HashMap<Address, Set<Address>>();

		for (Address typeinfoAddress : typeinfoAddresses) {
			monitor.checkCancelled();

			// check direct refs to see if they are in undefined area or not in function
			byte[] bytes = ProgramMemoryUtil.getDirectAddressBytes(program, typeinfoAddress);

			addByteSearchPattern(searcher, validTypeinfoRefMap, typeinfoAddress, bytes, monitor);

		}
		searcher.search(program, searchSet, monitor);
		return validTypeinfoRefMap;
	}

	public Map<Address, Set<Address>> findAllDirectRefs() throws CancelledException {

		MemoryBytePatternSearcher searcher = new MemoryBytePatternSearcher("Direct References");

		AddressSet searchSet = new AddressSet();
		AddressSetView initializedSet = program.getMemory().getAllInitializedAddressSet();
		AddressRangeIterator addressRanges = initializedSet.getAddressRanges();
		while (addressRanges.hasNext()) {
			monitor.checkCancelled();
			AddressRange addressRange = addressRanges.next();

			searchSet.add(addressRange.getMinAddress(), addressRange.getMaxAddress());
		}
		Map<Address, Set<Address>> directRefMap = new HashMap<Address, Set<Address>>();

		AddressIterator addrIter = initializedSet.getAddresses(initializedSet.getMinAddress(), true);
		while (addrIter.hasNext()) {
			monitor.checkCancelled();
			Address address = addrIter.next();
			// check direct refs to see if they are in undefined area or not in function
			byte[] bytes = ProgramMemoryUtil.getDirectAddressBytes(program, address);

			addByteSearchPatternDirRefs(searcher, directRefMap, address, bytes, monitor);

		}
		searcher.search(program, searchSet, monitor);
		return directRefMap;
	}

	/**
	 * Method to add a search pattern, to the searcher, for the set of bytes
	 * representing a typeinfo address
	 * 
	 * @param searcher       the MemoryBytePatternSearcher
	 * @param typeinfoRefMap a map of typeinfoAddress to Set of typeinfo reference
	 *                       addresses that are not contained in a function,
	 *                       instruction, or a typeinfo structure
	 * @param address        the given typeinfo address
	 * @param bytes          the bytes to search for
	 * @param taskMonitor    a cancellable monitor
	 */
	private void addByteSearchPatternDirRefs(MemoryBytePatternSearcher searcher,
			Map<Address, Set<Address>> typeinfoRefMap, Address address, byte[] bytes, TaskMonitor taskMonitor) {

		// no pattern bytes.
		if (bytes == null) {
			return;
		}

		// Each time a match for this byte pattern ...
		GenericMatchAction<Address> action = new GenericMatchAction<Address>(address) {
			@Override
			public void apply(Program prog, Address addr, Match match) {

				Set<Address> dirRefs = typeinfoRefMap.get(address);
				if (dirRefs == null) {
					dirRefs = new HashSet<Address>();
				}
				dirRefs.add(addr);
				typeinfoRefMap.put(address, dirRefs);

			}

		};

		// create a Pattern of the bytes and the MatchAction to perform upon a match
		GenericByteSequencePattern<Address> genericByteMatchPattern = new GenericByteSequencePattern<>(bytes, action);

		searcher.addPattern(genericByteMatchPattern);

	}

	public Map<Address, Set<Address>> findTypeinfoReferencesNotInTypeinfoStructs(List<GccTypeinfo> typeinfos)
			throws CancelledException {

		MemoryBytePatternSearcher searcher = new MemoryBytePatternSearcher("Typeinfo References");

		AddressSet searchSet = new AddressSet();
		AddressSetView initializedSet = program.getMemory().getAllInitializedAddressSet();
		AddressRangeIterator addressRanges = initializedSet.getAddressRanges();
		while (addressRanges.hasNext()) {
			monitor.checkCancelled();
			AddressRange addressRange = addressRanges.next();
			searchSet.add(addressRange.getMinAddress(), addressRange.getMaxAddress());
		}
		Map<Address, Set<Address>> validTypeinfoRefMap = new HashMap<Address, Set<Address>>();

		for (GccTypeinfo typeinfo : typeinfos) {
			monitor.checkCancelled();
			Address typeinfoAddress = typeinfo.getAddress();
			// check direct refs to see if they are in undefined area or not in function
			byte[] bytes = ProgramMemoryUtil.getDirectAddressBytes(program, typeinfoAddress);

			addByteSearchPattern(searcher, validTypeinfoRefMap, typeinfoAddress, bytes, monitor);

		}
		searcher.search(program, searchSet, monitor);
		return validTypeinfoRefMap;
	}

	/**
	 * Method to find references to the given typeinfos that are possibly ref'd by
	 * vtables (ie not in functions, other data, etc... and create a map
	 * typeinfoAddress to Set<Address> refs possibly in vtable
	 * 
	 * @param typeinfos list of GccTypeinfo's
	 * @return map
	 * @throws CancelledException
	 */
	public Map<Address, Set<Address>> findTypeinfoRefsPossiblyInVtables(List<GccTypeinfo> typeinfos)
			throws CancelledException {

		Map<Address, Set<Address>> typeinfoRefMap = new HashMap<Address, Set<Address>>();

		for (GccTypeinfo typeinfo : typeinfos) {
			monitor.checkCancelled();

			Set<Address> typeinfoRefs = findTypeinfoRefsPossiblyInVtables(typeinfo);

			// don't add if no refs in possible vtables
			if (typeinfoRefs.isEmpty()) {
				continue;
			}
			typeinfoRefMap.put(typeinfo.getAddress(), typeinfoRefs);
		}
		return typeinfoRefMap;
	}

	public Set<Address> findTypeinfoRefsPossiblyInVtables(GccTypeinfo typeinfo) throws CancelledException {

		Address typeinfoAddr = typeinfo.getAddress();
		Set<Address> typeinfoRefsPossiblyInVtables = new HashSet<Address>();

		Set<Address> typeinfoRefs = directRefMap.get(typeinfoAddr);

		// return emtpy list if no entry in map for given typeinfoAddr
		if (typeinfoRefs == null) {
			return typeinfoRefsPossiblyInVtables;
		}

		for (Address typeinfoRef : typeinfoRefs) {

			Function functionContainingTypeinfoRef = program.getListing().getFunctionContaining(typeinfoRef);
			if (functionContainingTypeinfoRef != null) {
				continue;
			}

			Instruction instructionContainingAddr = program.getListing().getInstructionContaining(typeinfoRef);
			if (instructionContainingAddr != null) {
				continue;
			}
			
			Data dataContainingTypeinfoRef = program.getListing().getDefinedDataContaining(typeinfoRef);

			if (dataContainingTypeinfoRef == null
					|| (dataContainingTypeinfoRef != null && !isTypeinfoStruct(dataContainingTypeinfoRef))) {

				typeinfoRefsPossiblyInVtables.add(typeinfoRef);
			}
		}

		return typeinfoRefsPossiblyInVtables;
	}

	/**
	 * Method to add a search pattern, to the searcher, for the set of bytes
	 * representing a typeinfo address
	 * 
	 * @param searcher        the MemoryBytePatternSearcher
	 * @param typeinfoRefMap  a map of typeinfoAddress to Set of typeinfo reference
	 *                        addresses that are not contained in a function,
	 *                        instruction, or a typeinfo structure
	 * @param typeinfoAddress the given typeinfo address
	 * @param bytes           the bytes to search for
	 * @param taskMonitor     a cancellable monitor
	 */
	private void addByteSearchPattern(MemoryBytePatternSearcher searcher, Map<Address, Set<Address>> typeinfoRefMap,
			Address typeinfoAddress, byte[] bytes, TaskMonitor taskMonitor) {

		// no pattern bytes.
		if (bytes == null) {
			return;
		}

		// Each time a match for this byte pattern ...
		GenericMatchAction<Address> action = new GenericMatchAction<Address>(typeinfoAddress) {
			@Override
			public void apply(Program prog, Address addr, Match match) {

				Function functionContainingTypeinfoRef = prog.getListing().getFunctionContaining(addr);

				Data dataContainingTypeinfoRef = prog.getListing().getDefinedDataContaining(addr);

				Instruction instructionContainingAddr = prog.getListing().getInstructionContaining(addr);

				// check the direct references found with the searcher
				// if not in function but is an instruction then create the function
				// otherwise, add to the list to report to user
				boolean add = false;
				if (functionContainingTypeinfoRef == null && instructionContainingAddr == null
						&& dataContainingTypeinfoRef == null) {
					add = true;
				} else if (dataContainingTypeinfoRef != null && !isTypeinfoStruct(dataContainingTypeinfoRef)) {
					add = true;
				}
				if (add) {
					Set<Address> typeinfoRefs = typeinfoRefMap.get(typeinfoAddress);
					if (typeinfoRefs == null) {
						typeinfoRefs = new HashSet<Address>();
					}
					typeinfoRefs.add(addr);
					typeinfoRefMap.put(typeinfoAddress, typeinfoRefs);
				}

			}

		};

		// create a Pattern of the bytes and the MatchAction to perform upon a match
		GenericByteSequencePattern<Address> genericByteMatchPattern = new GenericByteSequencePattern<>(bytes, action);

		searcher.addPattern(genericByteMatchPattern);

	}


	/**
	 * Method to determine if the given data is a typeinfo structure
	 * 
	 * @param data the given data
	 * @return true if the given data is a typeinfo structure, else return false
	 */
	private boolean isTypeinfoStruct(Data data) {

		if (data == null) {
			return false;
		}

		DataType baseDataType = data.getBaseDataType();

		if (!(baseDataType instanceof Structure)) {
			return false;
		}

		// This has to be "contains" to get all types of class structures some begin and end
		// with other things
		Structure structure = (Structure) baseDataType;
		if (structure.getName().contains(CLASS_TYPE_INFO_STRUCTURE)) {
			return true;
		}
		return false;

	}

	/**
	 * Method to create an appropriate type of vtable (primary, internal, or
	 * construction) and an associated VTT, if applicable
	 * 
	 * @param vtableAddress the given vtable address
	 * @throws CancelledException if cancelled
	 */
	private Vtable processVtable(Address vtableAddress, GccTypeinfoRef typeinfoRef, Boolean isConstruction)
			throws CancelledException {

		Vtable vtable = null;
		boolean isSpecial = false;
		MemoryBlock externalBlock = getExternalBlock();
		boolean isExternal = false;
		if (externalBlock != null && externalBlock.contains(vtableAddress)) {
			isExternal = true;
		}

		if (vtableAddress.equals(class_type_info_vtable) || vtableAddress.equals(si_class_type_info_vtable)
				|| vtableAddress.equals(vmi_class_type_info_vtable)) {

			isSpecial = true;
		}

		if (isConstruction == null) {
			vtable = new Vtable(program, vtableAddress, typeinfoRef, isSpecial, isExternal, monitor);
		} else {

			vtable = new Vtable(program, vtableAddress, typeinfoRef, isSpecial, isExternal, isConstruction, monitor);
		}

		if (isExternal) {
			return vtable;
		}

		if (!vtable.isValid()) {
			return null;
		}

		return vtable;

	}

	// TODO: add this back in
	private List<Address> getSubVTTs(Address vttAddress) throws CancelledException {

		// keep getting next code unit and continue while in the VTT (check for
		// pointers)
		// if there is a reference inside the vtt then count it - it is a subVTT
		int offset = 0;
		List<Address> subVtts = new ArrayList<Address>();
		Address currentAddress = vttAddress;
		while (currentAddress != null && getPointerToDefinedMemory(currentAddress) != null) {
			if (offset > 0) {

				List<Address> referencesTo = getAllReferencesTo(currentAddress);
				// Reference[] referencesTo = api.getReferencesTo(currentAddress);
				// if (referencesTo.length > 0) {
				if (!referencesTo.isEmpty()) {
					subVtts.add(currentAddress);
				}
			}
			offset++;
			currentAddress = getAddress(vttAddress, defaultPointerSize * offset);
		}

		return subVtts;

	}

	public SpecialVtable createSpecialVtable(Address vtableAddress, GccTypeinfo specialTypeinfo) throws Exception {

		boolean isExternal = false;
		Address typeinfoRefAddress = null;
		// if vtable is in external block don't try to create it because the full table isn't there
		// but is partially in placeholder external memory block
		if (program.getMemory().getBlock(vtableAddress).getName().equals("EXTERNAL")) {
			isExternal = true;
		}

		// if vtable address points to external memory don't try to create because table is
		// in external library
		Address externalReference = getExternalReference(vtableAddress);
		if (externalReference != null) {
			isExternal = true;
		}

		// if external then there is no typeinfo ref in the vtable - it is in an external program
		// if internal then the typeinfo ref for special vtable is the second item in the vtable
		if (!isExternal) {
			typeinfoRefAddress = vtableAddress.add(defaultPointerSize);
		}

		GccTypeinfoRef typeinfoRef = new GccTypeinfoRef(typeinfoRefAddress, specialTypeinfo, true);

		Symbol vtableSymbol = symbolTable.getPrimarySymbol(vtableAddress);

		api.clearListing(vtableAddress);

		SpecialVtable specialVtable = new SpecialVtable(program, vtableAddress, typeinfoRef, isExternal,
				vtableSymbol.getParentNamespace(), monitor);
		return specialVtable;
	}

	public Address getExternalReference(Address address) {

		Reference[] referencesFrom = program.getReferenceManager().getReferencesFrom(address);

		// get only the address references at the given address (ie no stack refs, ...)
		List<Address> refFromAddresses = new ArrayList<Address>();
		for (Reference referenceFrom : referencesFrom) {
			if (referenceFrom.isExternalReference()) {
				refFromAddresses.add(referenceFrom.getToAddress());
			}
		}

		if (refFromAddresses.size() == 1) {
			return refFromAddresses.get(0);
		}

		return null;
	}

	/**
	 * Method to create and apply typeinfo structs of one of the three types used by
	 * rtti classes
	 * 
	 * @throws CancelledException if cancelled
	 * @throws Exception          if could not apply a type info structure
	 */
	private List<GccTypeinfo> createTypeinfoStructs(List<GccTypeinfo> specialTypeinfos,
			List<SpecialVtable> specialVtables) throws CancelledException, Exception {

		StructureDataType classTypeInfoStructure = createClassTypeInfoStructure();
		StructureDataType siClassTypeInfoStructure = createSiClassTypeInfoStructure(classTypeInfoStructure);
		StructureDataType baseClassTypeInfoStructure = createBaseClassTypeInfoStructure(classTypeInfoStructure);

		List<GccTypeinfo> typeinfos = new ArrayList<GccTypeinfo>(specialTypeinfos);

		// Apply typeinfo structs to special typeinfos if the typeinfo is not in
		// external mem block or external program
		for (GccTypeinfo specialTypeinfo : specialTypeinfos) {
			monitor.checkCancelled();

			if (specialTypeinfo.isInProgramMemory()) {
				applyTypeinfoStructure(siClassTypeInfoStructure, specialTypeinfo.getAddress());
				typeinfoToStructuretypeMap.put(specialTypeinfo.getAddress(), SI_CLASS_TYPE_INFO_STRUCTURE);
			}
		}

		AddressSetView executeSet = program.getMemory().getExecuteSet();
		MemoryBlock idataBlock = program.getMemory().getBlock(".idata");

		AddressSet specialTypeinfosAddrSet = getSpecialTypeinfosAddrSet();

		for (SpecialVtable specialVtable : specialVtables) {

			monitor.checkCancelled();

			Address typeinfoRefAddr = specialVtable.getVfunctionTop();
			if (typeinfoRefAddr == null) {
				typeinfoRefAddr = specialVtable.getAddress();
			}

			List<Address> refsToClassTypeinfo = getAllReferencesTo(typeinfoRefAddr);
			for (Address typeinfoAddress : refsToClassTypeinfo) {

				monitor.checkCancelled();

				if (executeSet.contains(typeinfoAddress)) {
					continue;
				}

				// check to see if the reference is in a special vtable or special typeinfo and
				// skip if so only looking to return the non-special typeinfos
				if (specialTypeinfosAddrSet.contains(typeinfoAddress)) {
					continue;
				}

				if (hasExistingTypeinfoStructure(typeinfoAddress)) {
					continue;
				}

				// skip if ref is in idata (windows gcc IAT)
				if (idataBlock != null && idataBlock.contains(typeinfoAddress)) {
					continue;
				}

				// test if creating the pointer at typeinfoAddress would overlap anything
				// else and skip if so
				if (!canContainPointer(typeinfoAddress)) {
					continue;
				}

				Data newStructure = null;
				String specialTypeinfoNamespaceName = null;

				// create a "no inheritance" struct here
				if (specialVtable.getNamespace().getName().equals(CLASS_TYPEINFO_NAMESPACE)) {
					specialTypeinfoNamespaceName = CLASS_TYPEINFO_NAMESPACE;
					typeinfoToStructuretypeMap.put(typeinfoAddress, CLASS_TYPE_INFO_STRUCTURE);
					newStructure = applyTypeinfoStructure(classTypeInfoStructure, typeinfoAddress);
				}

				// create a "single inheritance" struct here
				else if (specialVtable.getNamespace().getName().equals(SI_CLASS_TYPEINFO_NAMESPACE)) {
					specialTypeinfoNamespaceName = SI_CLASS_TYPEINFO_NAMESPACE;
					typeinfoToStructuretypeMap.put(typeinfoAddress, SI_CLASS_TYPE_INFO_STRUCTURE);
					newStructure = applyTypeinfoStructure(siClassTypeInfoStructure, typeinfoAddress);
				}

				// create a "virtual multip inheritance" struct here
				else if (specialVtable.getNamespace().getName().equals(VMI_CLASS_TYPEINFO_NAMESPACE)) {
					specialTypeinfoNamespaceName = VMI_CLASS_TYPEINFO_NAMESPACE;
					typeinfoToStructuretypeMap.put(typeinfoAddress, VMI_CLASS_TYPE_INFO_STRUCTURE);
					Structure vmiClassTypeinfoStructure = getOrCreateVmiTypeinfoStructure(typeinfoAddress,
							baseClassTypeInfoStructure);
					if (vmiClassTypeinfoStructure != null) {
						newStructure = applyTypeinfoStructure(vmiClassTypeinfoStructure, typeinfoAddress);
					}
				}

				if (newStructure == null) {
					// is a typeinfo that inherits a non class typeinfo so skip it
					continue;
				}

				// check for existing symbol and if none, demangle the name and apply
				Symbol typeinfoSymbol = api.getSymbolAt(typeinfoAddress);
				if (typeinfoSymbol == null || typeinfoSymbol.getSource() == SourceType.DEFAULT
						|| typeinfoSymbol.getName().startsWith(".rdata$")) {

					typeinfoSymbol = createDemangledTypeinfoSymbol(typeinfoAddress);
					if (typeinfoSymbol == null) {
						Msg.debug(this, "Could not create demangled typeinfo symbol at " + typeinfoAddress.toString());
						continue;
					}
				}

				if (typeinfoSymbol != null && typeinfoSymbol.getName().equals("typeinfo")) {
					promoteToClassNamespace(typeinfoSymbol.getParentNamespace());
					GccTypeinfo typeinfo = createGccTypeinfo(typeinfoSymbol, false);
					if (specialTypeinfoNamespaceName == null) {
						continue;
					}
					GccTypeinfo specialTypeinfo = getTypeinfo(specialTypeinfoNamespaceName, specialTypeinfos);
					typeinfo.setInheritedSpecialTypeinfo(specialTypeinfo);
					typeinfos.add(typeinfo);
					continue;
				}
			}
		}
		
		// remove typeinfos that do not inherit one of the three special typeinfos
		List<GccTypeinfo> typeinfosToRemove = new ArrayList<GccTypeinfo>();
		Map<Address, GccTypeinfo> typeinfoMap = new HashMap<Address, GccTypeinfo>();
		
		for (GccTypeinfo typeinfo : typeinfos) {
			monitor.checkCancelled();
			Address typeinfoAddress = typeinfo.getAddress();
			if (typeinfo.getInheritedSpecialTypeinfo() == null) {
						
				typeinfosToRemove.add(typeinfo);
				continue;
			}
			typeinfoMap.put(typeinfoAddress, typeinfo);
		}
		typeinfos.removeAll(typeinfosToRemove);

		// update typeinfos with their base classes
		updateTypeinfosWithBases(typeinfos, typeinfoMap);

		return typeinfos;
	}

	private GccTypeinfo getTypeinfo(String namespaceName, List<GccTypeinfo> typeinfos) throws CancelledException {

		for (GccTypeinfo typeinfo : typeinfos) {
			monitor.checkCancelled();

			if (typeinfo.getNamespace().getName().equals(namespaceName)) {
				return typeinfo;
			}
		}
		return null;

	}

	private void updateTypeinfosWithBases(List<GccTypeinfo> typeinfos, Map<Address, GccTypeinfo> typeinfoMap)
			throws CancelledException {

		List<GccTypeinfo> invalidTypeinfos = new ArrayList<GccTypeinfo>();
		for (GccTypeinfo typeinfo : typeinfos) {
			monitor.checkCancelled();

			if (typeinfo.isSpecialTypeinfo) {
				continue;
			}

			// can't process if in external block
			if (inExternalBlock(typeinfo.getAddress())) {
				invalidTypeinfos.add(typeinfo);
				continue;
			}

			// TODO: update the typeinfo with the correct namespace based on the structure

			String namespaceName = typeinfo.getInheritedSpecialTypeinfo().getNamespace().getName();

			// if typeinfo inherits class_type_info then no Base to update
			if (namespaceName.equals(CLASS_TYPEINFO_NAMESPACE)) {
				continue;
			}

			if (namespaceName.equals(SI_CLASS_TYPEINFO_NAMESPACE)) {
				if (!updateSiTypeinfo(typeinfo, typeinfoMap)) {
					invalidTypeinfos.add(typeinfo);
				}
				continue;
			}

			if (namespaceName.equals(VMI_CLASS_TYPEINFO_NAMESPACE)) {
				if (!updateVmiTypeinfo(typeinfo, typeinfoMap)) {
					invalidTypeinfos.add(typeinfo);
				}
			}
		}
		typeinfos.removeAll(invalidTypeinfos);

	}

	private boolean updateSiTypeinfo(GccTypeinfo typeinfo, Map<Address, GccTypeinfo> typeinfoMap)
			throws CancelledException {

		Data siTypeinfoStructure = api.getDataAt(typeinfo.getAddress());

		// SI_CLASS_TYPE_INFO_STRUCTURE
		if (siTypeinfoStructure == null || !siTypeinfoStructure.isStructure()) {
			throw new IllegalArgumentException(
					siTypeinfoStructure.getAddressString(false, false) + " is not a structure");
		}

		Data baseClassPointer = siTypeinfoStructure.getComponent(2);

		Address baseClassPointerAddress = baseClassPointer.getAddress();
		Address baseTypeinfoAddress = extendedFlatAPI.getReferencedAddress(baseClassPointerAddress, false);

		if (baseTypeinfoAddress == null) {
			Msg.debug(this, typeinfo.getAddress() + ": invalid typeinfo - cannot get address for baseTypeinfo");
			return false;
		}

		GccTypeinfo baseTypeinfo = typeinfoMap.get(baseTypeinfoAddress);
		if(baseTypeinfo == null) {
			return false;
		}

		// si_class_type_info by definition have single base that is public, not
		// virtual, and is at offset 0
		typeinfo.addBaseTypeinfo(baseTypeinfo, 0, true, false, 0);
		return true;
	}

	private boolean updateVmiTypeinfo(GccTypeinfo typeinfo, Map<Address, GccTypeinfo> typeinfoMap)
			throws CancelledException {

		Data vmiTypeinfoStructure = api.getDataAt(typeinfo.getAddress());

		// VMI_CLASS_TYPE_INFO_STRUCTURE
		if (vmiTypeinfoStructure == null || !vmiTypeinfoStructure.isStructure()) {
			throw new IllegalArgumentException(
					vmiTypeinfoStructure.getAddressString(false, false) + " is not a structure");
		}

		long inheritanceFlagValue = getVmiInheritanceFlag(vmiTypeinfoStructure);
		typeinfo.addInheritanceFlagValue(inheritanceFlagValue);

		int numBaseClasses = getVmiNumBaseClasses(vmiTypeinfoStructure);

		Data baseClassArray = vmiTypeinfoStructure.getComponent(4);

		for (int i = 0; i < numBaseClasses; i++) {
			monitor.checkCancelled();

			Data baseClassStructure = baseClassArray.getComponent(i);
			Address baseClassStructureAddress = baseClassStructure.getAddress();
			Address baseTypeinfoAddress = extendedFlatAPI.getReferencedAddress(baseClassStructureAddress, false);

			if (baseTypeinfoAddress == null) {
				Msg.debug(this,
						typeinfo.getAddress() + ": invalid typeinfo - cannot get address at baseTypeinfo[" + i + "]");
				return false;
			}

			GccTypeinfo baseTypeinfo = typeinfoMap.get(baseTypeinfoAddress);

			if (baseTypeinfo == null) {
				Msg.debug(this, typeinfo.getAddress()
						+ ": invalid typeinfo - no special classtypeinfo ref'd by baseTypeinfo[" + i + "]");
				return false;
			}

			// get public/virtual/offset flag
			Address flagAddress = baseClassStructureAddress.add(defaultPointerSize);
			long publicVirtualOffsetFlag = extendedFlatAPI.getLongValueAt(flagAddress);

			// The low-order byte of __offset_flags contains flags, as given by the masks
			// from the enumeration __offset_flags_masks:

			// 0x1: Base class is virtual
			// 0x2: Base class is public

			boolean isVirtual = false;
			boolean isPublic = false;

			long virtualMask = 0x1L;
			long publicMask = 0x2L;
			long offsetMask;
			if (defaultPointerSize == 4) {
				offsetMask = 0xffffff00L;

			} else {
				offsetMask = 0xffffffffffffff00L;
			}

			if ((publicVirtualOffsetFlag & virtualMask) == 1) {
				isVirtual = true;
			}

			if (((publicVirtualOffsetFlag & publicMask) >> 1) == 1) {
				isPublic = true;
			}

			long offset = (publicVirtualOffsetFlag & offsetMask) >> 8;

			typeinfo.addBaseTypeinfo(baseTypeinfo, i, isPublic, isVirtual, offset);

		}
		return true;

	}

	private long getVmiInheritanceFlag(Data vmiTypeinfoStructure) {

		// TODO: make a validate structure method and pass name
		if (vmiTypeinfoStructure == null || !vmiTypeinfoStructure.isStructure()) {
			throw new IllegalArgumentException(
					vmiTypeinfoStructure.getAddressString(false, false) + " is not a structure");
		}

		Data inheritanceFlagComponent = vmiTypeinfoStructure.getComponent(2);
		Address flagAddress = inheritanceFlagComponent.getAddress();
		DataType inheritanceFlagDataType = inheritanceFlagComponent.getDataType();
		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), flagAddress);
		Scalar scalar = (Scalar) inheritanceFlagDataType.getValue(buf, inheritanceFlagDataType.getDefaultSettings(),
				inheritanceFlagDataType.getLength());
		long inheritanceFlagValue = scalar.getUnsignedValue();
		return inheritanceFlagValue;
	}

	private int getVmiNumBaseClasses(Data vmiTypeinfoStructure) {

		// TODO: make a validate structure method and pass name
		if (vmiTypeinfoStructure == null || !vmiTypeinfoStructure.isStructure()) {
			throw new IllegalArgumentException(
					vmiTypeinfoStructure.getAddressString(false, false) + " is not a structure");
		}

		Data numBaseClassesComponent = vmiTypeinfoStructure.getComponent(3);
		Address numBaseClassesAddress = numBaseClassesComponent.getAddress();
		DataType numBaseClassesDataType = numBaseClassesComponent.getDataType();
		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), numBaseClassesAddress);
		Scalar scalar = (Scalar) numBaseClassesDataType.getValue(buf, numBaseClassesDataType.getDefaultSettings(),
				numBaseClassesDataType.getLength());
		int numBaseClasses = (int) scalar.getUnsignedValue();

		return numBaseClasses;
	}

	/**
	 * Method to determine whether a pointer can validly exist at this location
	 * 
	 * @param pointer
	 * @return true if a pointer can exist here, false if something exists that
	 *         would not indicate a valid ptr would be here
	 * @throws CancelledException
	 */
	private boolean canContainPointer(Address pointer) throws CancelledException {

		// return true if has a correcly sized ptr already -
		Data data = program.getListing().getDataAt(pointer);
		if (data != null && data.isPointer()) {
			return true;
		}

		// ok if has symbol at the actual addr so don't check it
		int offset = 1;

		while (offset < defaultPointerSize) {
			monitor.checkCancelled();
			Address addr = pointer.add(offset);
			data = program.getListing().getDataContaining(addr);
			if (data != null) {
				return false;
			}

			Symbol[] symbols = symbolTable.getSymbols(addr);
			if (symbols.length != 0) {
				return false;
			}
		}

		return true;

	}

	/**
	 * Method to determine if the given address has one of the ClassTypeinfoDataType
	 * types applied
	 * 
	 * @param address the given address
	 * @return true if already has a class data type applied or false if not
	 */
	private boolean hasExistingTypeinfoStructure(Address address) {

		Data dataAt = api.getDataAt(address);

		if (dataAt == null) {
			return false;
		}

		DataType dataType = dataAt.getDataType();

		if (!(dataType instanceof Structure)) {
			return false;
		}

		// This has to be "contains" to get all types of class structures some begin and
		// end
		// with other things
		if (!dataType.getName().contains(CLASS_TYPE_INFO_STRUCTURE)) {
			return false;
		}

		if (!dataType.getPathName().startsWith(DTM_CLASS_DATA_FOLDER_PATH)) {
			return false;
		}
		return true;

	}

	private Data applyTypeinfoStructure(Structure typeInfoStructure, Address typeinfoAddress)
			throws CancelledException, AddressOutOfBoundsException, Exception {

		api.clearListing(typeinfoAddress, typeinfoAddress.add(typeInfoStructure.getLength() - 1));
		Data newStructure = api.createData(typeinfoAddress, typeInfoStructure);

		return newStructure;
	}

	private Structure getOrCreateVmiTypeinfoStructure(Address typeinfoAddress,
			StructureDataType baseClassTypeInfoStructure) throws CancelledException {

		// get num base classes
		int offsetOfNumBases = 2 * defaultPointerSize + 4;
		int numBases;
		try {
			numBases = api.getInt(typeinfoAddress.add(offsetOfNumBases));
		}
		// if there isn't enough memory to get the int then return null
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}

		// get or create the vmiClassTypeInfoStruct
		Structure vmiClassTypeinfoStructure = (Structure) dataTypeManager.getDataType(classDataTypesCategoryPath,
				VMI_CLASS_TYPE_INFO_STRUCTURE + numBases);
		if (vmiClassTypeinfoStructure == null) {
			vmiClassTypeinfoStructure = createVmiClassTypeInfoStructure(baseClassTypeInfoStructure, numBases);
		}
		return vmiClassTypeinfoStructure;
	}

	private Symbol createDemangledTypeinfoSymbol(Address typeinfoAddress)
			throws DuplicateNameException, InvalidInputException, CancelledException {

		// TODO: 1. see if there is a mangled name that didn't get demangled at
		// TODO: 2 - refactor the three places that call this to just call getSymbolAt and
		// in that method check for regular symbol and return or check for mangled
		// symbol that didn't get demangled then return or
		// check for this scenario where you need to get the string out

		Address typeinfoNameAddress = getTypeinfoNameAddress(typeinfoAddress);

		if (typeinfoNameAddress == null) {
			return null;
		}

		String mangledTypeinfoString = getStringAtAddress(typeinfoNameAddress);

		if (mangledTypeinfoString == null) {
			Msg.debug(this, "Could not get typeinfo string from " + typeinfoAddress.toString());
			return null;
		}

		if (mangledTypeinfoString.startsWith("*")) {
			mangledTypeinfoString = mangledTypeinfoString.substring(1);
		}

		if (mangledTypeinfoString.startsWith(".rdata$")) {
			mangledTypeinfoString = mangledTypeinfoString.substring(7);
		}
		mangledTypeinfoString = "_ZTS" + mangledTypeinfoString;

		symbolTable.createLabel(typeinfoNameAddress, mangledTypeinfoString, globalNamespace, SourceType.ANALYSIS);

		// demangle the symbol
		DemanglerCmd cmd = new DemanglerCmd(typeinfoNameAddress, mangledTypeinfoString);
		cmd.applyTo(program, monitor);

		// get the newly created symbol to get the namespace
		Symbol typeinfoNameSymbol = symbolTable.getPrimarySymbol(typeinfoNameAddress);

		// TODO: need to account for rare case where there are more than one typeinfos with
		// exact same class and name so make two classes in this case - name second one dupe#
		// TODO: instead/also - eliminate the ones with no refs or just pick one?
		List<Symbol> symbols = symbolTable.getSymbols(typeinfoNameSymbol.getName(),
				typeinfoNameSymbol.getParentNamespace());
		if (symbols.size() > 1) {

			Msg.debug(this, "Duplicate typeinfo namespace: " + typeinfoNameSymbol.getParentNamespace().toString());
			for (Symbol symbol : symbols) {
				Msg.debug(this, symbol.getAddress());
			}
			Namespace newNamespace = symbolTable.getOrCreateNameSpace(globalNamespace,
					typeinfoNameSymbol.getParentNamespace().getName(true) + "DUPE", SourceType.ANALYSIS);
			try {
				typeinfoNameSymbol.setNamespace(newNamespace);
			} catch (DuplicateNameException e) {
				return null;
			} catch (InvalidInputException e) {
				return null;
			} catch (CircularDependencyException e) {
				return null;
			}

		}

		Namespace classNamespace = typeinfoNameSymbol.getParentNamespace();

		if (classNamespace.isGlobal()) {
			Msg.debug(this,
					typeinfoAddress.toString() + "Could not create a class namespace for demangled namespace string ");
			return null;
		}

		// create the new typeinfo symbol in the demangled namespace
		Symbol newSymbol = symbolTable.createLabel(typeinfoAddress, "typeinfo", classNamespace, SourceType.ANALYSIS);

		api.setPlateComment(typeinfoAddress, "typeinfo for " + classNamespace.getName(true));

		return newSymbol;
	}

	private Address getTypeinfoNameAddress(Address typeinfoAddress) {

		Data dataAt = api.getDataAt(typeinfoAddress);
		if (dataAt == null) {
			return null;
		}
		if (!(dataAt.getBaseDataType() instanceof Structure)) {
			return null;
		}

		Structure typeinfoStructure = (Structure) dataAt.getBaseDataType();
		if (!typeinfoStructure.getName().contains(CLASS_TYPE_INFO_STRUCTURE)) {
			return null;
		}
		DataTypeComponent typeinfoNameComponent = typeinfoStructure.getComponent(1);
		DataType typeinfoNameDatatype = typeinfoNameComponent.getDataType();
		if (!(typeinfoNameDatatype instanceof Pointer)) {
			return null;
		}

		Address typeinfoNameAddress = extendedFlatAPI
				.getSingleReferencedAddress(typeinfoAddress.add(typeinfoNameComponent.getOffset()));

		return typeinfoNameAddress;
	}

	String getStringAtAddress(Address address) throws CancelledException {

		Data stringData = api.getDataAt(address);
		if (stringData == null) {

			// account for randomly occurring bad strings sucking up the real expected
			// string
			Data dataContaining = api.getDataContaining(address);
			if (dataContaining != null) {
				api.clearListing(dataContaining.getAddress());
			}
			// create string
			try {
				stringData = api.createAsciiString(address);
			} catch (Exception e) {
				Msg.debug(this, "Could not create string at " + address);
				return null;
			}

			if (stringData == null) {
				return null;
			}

		}
		int stringLen = stringData.getLength();
		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), address);

		StringDataType sdt = new StringDataType();

		String str;

		str = (String) sdt.getValue(buf, sdt.getDefaultSettings(), stringLen);

		return str;
	}


	/**
	 * Method to check to see if there are any EXTERNAL block relocations
	 * 
	 * @return true if there are any EXTERNAL block relocations in the program,
	 *         false otherwise
	 * @throws CancelledException if cancelled
	 */
	private boolean hasExternalRelocations() throws CancelledException {
		// if no external block then there won't be any refernces to special typeinfo in external
		// block so return empty list
		if (!hasExternalBlock()) {
			return false;
		}
		Iterator<Bookmark> bookmarksIterator = program.getBookmarkManager().getBookmarksIterator(BookmarkType.WARNING);
		while (bookmarksIterator.hasNext()) {
			monitor.checkCancelled();
			Bookmark bookmark = bookmarksIterator.next();
			if (bookmark.getCategory().startsWith("EXTERNAL Relocation")) {
				return true;
			}
		}
		return false;
	}

	// TODO: update to not use global vars
	private AddressSet getSpecialTypeinfosAddrSet() {

		AddressSet addrSet = new AddressSet();

		Integer vtableSize = vtableToSizeMap.get(class_type_info_vtable);
		if (vtableSize != null) {
			addrSet.add(class_type_info_vtable, class_type_info_vtable.add(vtableSize));
		}

		vtableSize = vtableToSizeMap.get(si_class_type_info_vtable);
		if (vtableSize != null) {
			addrSet.add(si_class_type_info_vtable, si_class_type_info_vtable.add(vtableSize));
		}

		vtableSize = vtableToSizeMap.get(vmi_class_type_info_vtable);
		if (vtableSize != null) {
			addrSet.add(vmi_class_type_info_vtable, vmi_class_type_info_vtable.add(vtableSize));
		}

		if (class_type_info != null) {
			Data data = extendedFlatAPI.getDataContaining(class_type_info);
			if (data != null && data.getDataType().getName().contains(SI_CLASS_TYPE_INFO_STRUCTURE)) {
				addrSet.add(data.getAddress(), data.getAddress().add(data.getLength()));
			}
		}

		if (si_class_type_info != null) {
			Data data = extendedFlatAPI.getDataContaining(si_class_type_info);
			if (data != null && data.getAddress() == null) {
				Msg.debug(this, "si_class_type_info at " + si_class_type_info.toString() + " has null addr");
			}
			if (data != null && data.getDataType().getName().contains(SI_CLASS_TYPE_INFO_STRUCTURE)) {
				addrSet.add(data.getAddress(), data.getAddress().add(data.getLength()));
			}
		}

		if (vmi_class_type_info != null) {
			Data data = extendedFlatAPI.getDataContaining(vmi_class_type_info);
			if (data != null && data.getDataType().getName().contains(SI_CLASS_TYPE_INFO_STRUCTURE)) {
				addrSet.add(data.getAddress(), data.getAddress().add(data.getLength()));
			}
		}

		return addrSet;

	}

	/**
	 * Method to call the various methods to determine whether the functions that
	 * make references to the vftables are constructors, destructors, deleting
	 * destructors, clones, or vbase functions
	 * 
	 * @throws CancelledException     if cancelled
	 * @throws InvalidInputException  if issues setting function return
	 * @throws DuplicateNameException if try to create same symbol name already in
	 *                                namespace
	 * @Exception if issues making labels
	 */
	private void processConstructorAndDestructors()
			throws CancelledException, InvalidInputException, DuplicateNameException, Exception {

		assignConstructorsAndDestructorsUsingExistingNameNew(recoveredClasses);

		// find gcc destructors in top of vftables
		findVftableDestructors(recoveredClasses);

		// figure out which are inlined and put on separate list to be processed later
		separateInlinedConstructorDestructors(recoveredClasses);

		// figure out which member functions are constructors and which are destructors
		// using the order their parents are called
		processRegularConstructorsAndDestructorsUsingCallOrder(recoveredClasses);

		// determine which of the inlines are constructors and which are destructors
		processInlinedConstructorsAndDestructors(recoveredClasses);

		findConstructorsAndDestructorsUsingAncestorClassFunctions(recoveredClasses);

		findInlineConstructorsAndDestructorsUsingRelatedClassFunctions(recoveredClasses);

		// use the load/store information from decompiler to figure out as many of the
		// ones that could not be determined in earlier stages
		processRemainingIndeterminateConstructorsAndDestructors(recoveredClasses);

		// use the known constructors and known vfunctions to figure out
		// clone functions
		// findCloneFunctions(recoveredClasses);

		// This has to be here. It needs all the info from the previously run methods to
		// do this.
		// Finds the constructors that have multiple basic blocks, reference the vftable
		// not in the
		// first block, and call non-parent constructors and non operator new before the
		// vftable ref
		// findMoreInlinedConstructors(recoveredClasses);

		// findDestructorsWithNoParamsOrReturn(recoveredClasses);

		// use vftables with references to all the same function (except possibly one
		// deleting
		// destructor)to find the purecall function
		// identifyPureVirtualFunction(recoveredClasses);

		// findRealVBaseFunctions(recoveredClasses);

		// make constructors and destructors this calls
		makeConstructorsAndDestructorsThiscalls(recoveredClasses);

	}

	public void assignConstructorsAndDestructorsUsingExistingNameNew(List<RecoveredClass> recoveredClasses)
			throws CancelledException, InvalidInputException, DuplicateNameException, CircularDependencyException {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCancelled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();

			Namespace classNamespace = recoveredClass.getClassNamespace();
			String name = classNamespace.getName();
			SymbolIterator classSymbols = symbolTable.getSymbols(classNamespace);

			while (classSymbols.hasNext()) {
				monitor.checkCancelled();

				Symbol classSymbol = classSymbols.next();

				Function function = api.getFunctionAt(classSymbol.getAddress());
				if (function == null) {
					continue;
				}

				if (classSymbol.getName().equals(name)) {

					addConstructorToClass(recoveredClass, function);
					removeFromIndeterminateLists(recoveredClasses, function);
					continue;
				}
				if (classSymbol.getName().equals("~" + name)) {
					addDestructorToClass(recoveredClass, function);
					removeFromIndeterminateLists(recoveredClasses, function);
					continue;
				}
			}

		}
	}

	private void findVftableDestructors(List<RecoveredClass> recoveredClasses) throws CancelledException {

		for (RecoveredClass recoveredClass : recoveredClasses) {

			monitor.checkCancelled();

			List<Address> vftableAddresses = recoveredClass.getVftableAddresses();

			for (Address vftableAddress : vftableAddresses) {
				monitor.checkCancelled();

				List<Function> virtualFunctions = recoveredClass.getVirtualFunctions(vftableAddress);

				if (virtualFunctions.size() < 2) {
					continue;
				}

				Function firstVfunction = virtualFunctions.get(0);
				Function secondVfunction = virtualFunctions.get(1);

				Address callingAddressOfFirstVfunction = getCallingAddress(secondVfunction, firstVfunction);
				if (callingAddressOfFirstVfunction == null) {
					continue;
				}

				// TODO: eventually work into new op delete discovery
				Address callingAddrOfOpDelete = getCallingAddress(secondVfunction, "operator.delete");
				if (callingAddrOfOpDelete == null) {
					continue;
				}

				// if firsrVfunction is called before op delete then valid set of
				// destructor/deleting destructor
				if (callingAddrOfOpDelete.getOffset() > callingAddressOfFirstVfunction.getOffset()) {
					recoveredClass.addDestructor(firstVfunction);
					recoveredClass.addDeletingDestructor(secondVfunction);
				}

			}
		}
	}

	private Address getCallingAddress(Function function, Function expectedCalledFunction) throws CancelledException {

		InstructionIterator instructions = function.getProgram().getListing().getInstructions(function.getBody(), true);

		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			if (instruction.getFlowType().isCall()) {

				Function calledFunction = extendedFlatAPI.getReferencedFunction(instruction.getMinAddress(), false);

				if (calledFunction == null) {
					continue;
				}
				if (calledFunction.equals(expectedCalledFunction)) {
					return instruction.getAddress();
				}
			}
		}
		return null;

	}

	private Address getCallingAddress(Function function, String expectedCalledFunctionName) throws CancelledException {

		InstructionIterator instructions = function.getProgram().getListing().getInstructions(function.getBody(), true);

		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			if (instruction.getFlowType().isCall()) {

				Function calledFunction = extendedFlatAPI.getReferencedFunction(instruction.getMinAddress(), false);
				if (calledFunction.getName().equals(expectedCalledFunctionName)) {
					return instruction.getAddress();
				}
			}
		}
		return null;

	}

	private void removeFromIndeterminateLists(List<RecoveredClass> recoveredClasses, Function function)
			throws CancelledException {

		for (RecoveredClass recoveredClass : recoveredClasses) {
			monitor.checkCancelled();

			recoveredClass.getIndeterminateInlineList().remove(function);
			recoveredClass.getIndeterminateList().remove(function);
		}
	}

	private StructureDataType createClassTypeInfoStructure() throws CancelledException {

		StructureDataType classTypeInfoStructure = new StructureDataType(classDataTypesCategoryPath,
				CLASS_TYPE_INFO_STRUCTURE, 0, dataTypeManager);

		CharDataType characterDT = new CharDataType();

		if (hasExternalRelocations()) {
			PointerTypedef classTypeInfoPtr = new PointerTypedef(null, null, -1, program.getDataTypeManager(),
					componentOffset);
			classTypeInfoStructure.add(classTypeInfoPtr, "classTypeinfoPtr", null);

		}
		else {
			PointerTypedef classTypeInfoPtr = new PointerTypedef(null, PointerDataType.dataType, -1,
					program.getDataTypeManager(), 0);
			classTypeInfoStructure.add(classTypeInfoPtr, "classTypeinfoPtr", null);
		}

		DataType charPointer = dataTypeManager.getPointer(characterDT);
		classTypeInfoStructure.add(charPointer, "typeinfoName", null);

		classTypeInfoStructure.setPackingEnabled(true);

		return classTypeInfoStructure;
	}

	private StructureDataType createSiClassTypeInfoStructure(StructureDataType classTypeInfoStructure)
			throws CancelledException {

		StructureDataType siClassTypeInfoStructure = new StructureDataType(classDataTypesCategoryPath,
				SI_CLASS_TYPE_INFO_STRUCTURE, 0, dataTypeManager);

		CharDataType characterDT = new CharDataType();

	
		PointerTypedef classTypeInfoPtr = new PointerTypedef(null, null, -1, program.getDataTypeManager(),
				componentOffset);
		siClassTypeInfoStructure.add(classTypeInfoPtr, "classTypeinfoPtr", null);

		DataType charPointer = dataTypeManager.getPointer(characterDT);

		siClassTypeInfoStructure.add(charPointer, "typeinfoName", null);

		DataType pointerToClassTypeInfoStruct = dataTypeManager.getPointer(classTypeInfoStructure);
		siClassTypeInfoStructure.add(pointerToClassTypeInfoStruct, "baseClassTypeInfoPtr", null);

		siClassTypeInfoStructure.setPackingEnabled(true);

		return siClassTypeInfoStructure;
	}

	private StructureDataType createBaseClassTypeInfoStructure(StructureDataType classTypeInfoStructure)
			throws InvalidDataTypeException {

		StructureDataType baseclassTypeInfoStructure = new StructureDataType(classDataTypesCategoryPath,
				BASE_CLASS_TYPE_INFO_STRUCTURE, 0, dataTypeManager);

		DataType classTypeInfoPointer = dataTypeManager.getPointer(classTypeInfoStructure);

		int offsetBitSize = 24;
		DataType dataType = new LongDataType();
		if (defaultPointerSize == 8) {
			offsetBitSize = 56;
			dataType = new LongLongDataType();
		}

		baseclassTypeInfoStructure.add(classTypeInfoPointer, "classTypeinfoPtr", null);

		if (program.getMemory().isBigEndian()) {
			baseclassTypeInfoStructure.addBitField(dataType, offsetBitSize, "baseClassOffset", "baseClassOffset");
			baseclassTypeInfoStructure.addBitField(dataType, 1, "isPublicBase", "isPublicBase");
			baseclassTypeInfoStructure.addBitField(dataType, 1, "isVirtualBase", "isVirtualBase");
			baseclassTypeInfoStructure.addBitField(dataType, 6, "unused", "unused");
		} else {
			baseclassTypeInfoStructure.addBitField(dataType, 1, "isVirtualBase", "isVirtualBase");
			baseclassTypeInfoStructure.addBitField(dataType, 1, "isPublicBase", "isPublicBase");
			baseclassTypeInfoStructure.addBitField(dataType, 6, "unused", "unused");
			baseclassTypeInfoStructure.addBitField(dataType, offsetBitSize, "baseClassOffset", "baseClassOffset");
		}

		baseclassTypeInfoStructure.setPackingEnabled(true);

		return baseclassTypeInfoStructure;

	}

	private StructureDataType createVmiClassTypeInfoStructure(StructureDataType baseClassTypeInfoStructure,
			int numBaseClasses) throws CancelledException {

		StructureDataType vmiClassTypeInfoStructure = new StructureDataType(classDataTypesCategoryPath,
				VMI_CLASS_TYPE_INFO_STRUCTURE + numBaseClasses, 0, dataTypeManager);

		CharDataType characterDT = new CharDataType();
		UnsignedIntegerDataType unsignedIntDT = new UnsignedIntegerDataType();

		
		PointerTypedef classTypeInfoPtr = new PointerTypedef(null, null, -1, program.getDataTypeManager(),
				componentOffset);
		vmiClassTypeInfoStructure.add(classTypeInfoPtr, "classTypeinfoPtr", null);

		DataType charPointer = dataTypeManager.getPointer(characterDT);

		vmiClassTypeInfoStructure.add(charPointer, "typeinfoName", null);
		vmiClassTypeInfoStructure.add(unsignedIntDT, "flags", null);
		vmiClassTypeInfoStructure.add(unsignedIntDT, "numBaseClasses", null);

		// make array of base class type info structs
		ArrayDataType baseClassArray = new ArrayDataType(baseClassTypeInfoStructure, numBaseClasses,
				baseClassTypeInfoStructure.getLength());
		try {
			vmiClassTypeInfoStructure.add(baseClassArray, "baseClassPtrArray", null);
		} catch (IllegalArgumentException e) {
			Msg.debug(baseClassArray, e);
		}

		vmiClassTypeInfoStructure.setPackingEnabled(true);

		return vmiClassTypeInfoStructure;
	}
	
	
	/**
	 * Method to add parents to the given class
	 * 
	 * @param recoveredClass  the given class
	 * @param typeinfoAddress the address of the typeinfo
	 * @return list of parents for the given class
	 * @throws CancelledException 
	 * @throws Exception if cannot access the given typeinfo structure, one of its
	 *                   components, or it is not a vmi structure
	 */
	private List<RecoveredClass> addClassParentsAndFlagsForVmiClass(RecoveredClass recoveredClass, GccTypeinfo typeinfo) throws CancelledException{
			

		long inheritanceFlagValue = typeinfo.getInheritanceFlagValue();

		// 0x01: class has non-diamond repeated inheritance
		// 0x02: class is diamond shaped
		// add flag for non-diamond repeated and diamond shape types
		if (inheritanceFlagValue == 1) {
			if (DEBUG) {
				Msg.debug(this, "from typeinfo at address " + typeinfo.getAddress().toString() + " "
						+ recoveredClass.getClassNamespace().getName(true) + " has non-diamond repeated inheritance");
			}
		}
		if (inheritanceFlagValue == 2) {
			recoveredClass.setIsDiamondShaped(true);
		}

		// process the base classes
		// create parent maps
		Map<Integer, RecoveredClass> orderToParentMap = new HashMap<Integer, RecoveredClass>();
		Map<RecoveredClass, Long> parentToOffsetMap = new HashMap<RecoveredClass, Long>();

		List<BaseTypeinfo> baseTypeinfos = typeinfo.getBaseTypeinfos();
		int numBaseClasses = baseTypeinfos.size();
		
		boolean hasVirtualInheritance = false;
		if(typeinfo.getNumAllVirtualBases() > 0) {
			hasVirtualInheritance = true;
		}

		if (numBaseClasses > 1) {
			recoveredClass.setHasMultipleInheritance(true);
			recoveredClass.setHasSingleInheritance(false);
		} else {
			recoveredClass.setHasMultipleInheritance(false);
			recoveredClass.setHasSingleInheritance(true);
			recoveredClass.setHasMultipleVirtualInheritance(hasVirtualInheritance);
		}
		
		List<RecoveredClass> parentClassList = new ArrayList<RecoveredClass>();

		int parentNum = 0;
		for(BaseTypeinfo baseTypeinfo : baseTypeinfos) {
			monitor.checkCancelled();

			GccTypeinfo vmiParentTypeinfo = baseTypeinfo.getBaseTypeinfo();
			
			RecoveredClass parentClass = getClass(vmiParentTypeinfo.getNamespace());
			
			if (parentClass == null) {
				throw new IllegalArgumentException("RecoveredClass should already exist for " + vmiParentTypeinfo.getNamespace().getName(true));
			}
			
			updateClassWithParent(parentClass, recoveredClass);
			parentClassList.add(parentClass);

			recoveredClass.addParentToBaseTypeMapping(parentClass, baseTypeinfo.isVirtualBase());

			recoveredClass.setInheritsVirtualAncestor(hasVirtualInheritance);
			parentClass.setIsPublicClass(baseTypeinfo.isPublicBase());
		
			orderToParentMap.put(parentNum++, parentClass);
			parentToOffsetMap.put(parentClass, baseTypeinfo.getOffset());
		}

		classToParentOrderMap.put(recoveredClass, orderToParentMap);
		classToParentOffsetMap.put(recoveredClass, parentToOffsetMap);

		return parentClassList;

	}
	
	

	private Address findSpecialVtable(GccTypeinfo specialTypeinfo, List<GccTypeinfo> specialTypeinfos)
			throws CancelledException {

		String namespaceName = specialTypeinfo.getNamespace().getName();
		String mangledNamespaceString = specialTypeinfo.getMangledNamespaceString();

		// try finding with normal symbol name and namespace
		Symbol vtableSymbol = getSymbolInNamespaces(SPECIAL_CLASS_NAMESPACE, namespaceName, VTABLE_LABEL);
		if (vtableSymbol == null) {
			// then try finding with mangled symbol
			vtableSymbol = findAndReturnDemangledSymbol(MANGLED_VTABLE_PREFIX + mangledNamespaceString,
					SPECIAL_CLASS_NAMESPACE, namespaceName, VTABLE_LABEL);

			// then try finding top of special vtable by finding ref to special typeinfo
			if (vtableSymbol == null) {
				Address vtableAddress = findSpecialVtableUsingSpecialTypeinfo(specialTypeinfo.getAddress(),
						specialTypeinfos);

				if (vtableAddress == null) {
					return null;
				}

				try {
					vtableSymbol = symbolTable.createLabel(vtableAddress, VTABLE_LABEL, specialTypeinfo.getNamespace(),
							SourceType.ANALYSIS);
					api.setPlateComment(vtableAddress, "vtable for " + specialTypeinfo.getNamespace());

				} catch (InvalidInputException e) {
					vtableSymbol = null;
				}

			}
		}
		if (vtableSymbol != null) {
			return vtableSymbol.getAddress();
		}
		return null;
	}

	private List<SpecialVtable> findSpecialVtables(List<GccTypeinfo> specialTypeinfos) throws Exception {

		List<SpecialVtable> specialVtables = new ArrayList<SpecialVtable>();

		for (GccTypeinfo specialTypeinfo : specialTypeinfos) {
			monitor.checkCancelled();

			Address vtableAddress = findSpecialVtable(specialTypeinfo, specialTypeinfos);

			if (vtableAddress == null) {
				continue;
			}

			SpecialVtable specialVtable = createSpecialVtable(vtableAddress, specialTypeinfo);
			if (specialVtable != null) {
				specialVtables.add(specialVtable);
				specialTypeinfo.setVtableAddress(vtableAddress);
				if (!specialVtable.isExternal()) {
					specialVtable.applyVtableData();
					vtableToSizeMap.put(specialVtable.getAddress(), specialVtable.getLength());
					createVtableLabel(specialVtable);
					createVtableComment(specialVtable);
					createVfunctionSymbol(specialVtable);
				}
			}

		}
		return specialVtables;
	}

	/*
	 * Method to find special vtable using special typeinfo references. This
	 * assumption that vtable is defaultPtrSize above ref to single specialTypeinfo
	 * ref only works for special typeinfos/vtables. Regular ones can have variable
	 * len between the two
	 */
	private Address findSpecialVtableUsingSpecialTypeinfo(Address typeinfoAddress, List<GccTypeinfo> specialTypeinfos)
			throws CancelledException {

		List<Address> referencesTo = getAllReferencesTo(typeinfoAddress);

		if (referencesTo.isEmpty()) {
			return null;
		}

		// special typeinfos are all 3 * defaultPtrSize long if they are contained in
		// internal memory otherwise they are 1 defaultPointerSize long
		int specialTypeinfoLen = 3 * defaultPointerSize;

		// create an address set containing addresses of the special typeinfos
		AddressSet specialTypeinfoAddrSet = new AddressSet();
		for (GccTypeinfo specialTypeinfo : specialTypeinfos) {
			Address start = specialTypeinfo.getAddress();
			Address end = start.add(defaultPointerSize);
			if (specialTypeinfo.isInProgramMemory()) {
				end = start.add(specialTypeinfoLen);
			}
			specialTypeinfoAddrSet.add(start, end);

		}

		// use the address set created to weed out references to the given typeinfo from special 
		// typeinofs we only want references to the given typeinfo from its associated vtable
		List<Address> possibleRefsInVtable = new ArrayList<Address>();

		for (Address refTo : referencesTo) {
			monitor.checkCancelled();

			if (specialTypeinfoAddrSet.contains(refTo)) {
				continue;
			}

			// all special vtables have zeros just before the ref to typeinfo
			Address vtableAddress = refTo.subtract(defaultPointerSize);
			if (!isPossibleNullPointer(vtableAddress)) {
				continue;
			}

			possibleRefsInVtable.add(refTo);
		}
		if (possibleRefsInVtable.size() != 1) {
			return null;
		}

		Address typeinfoRef = possibleRefsInVtable.get(0);
		Address vtableAddress = typeinfoRef.subtract(defaultPointerSize);
		return vtableAddress;
	}

	private Symbol findTypeinfoUsingMangledString(String mangledNamespaceString) throws CancelledException {

		Address findSingleMangledString = findSingleMangledString(mangledNamespaceString);
		if (findSingleMangledString == null) {
			return null;
		}

		// get single reference to it
		Address typeinfoNameRef = getSingleReferenceTo(findSingleMangledString);

		if (typeinfoNameRef == null) {
			return null;
		}

		Address typeinfoAddress = typeinfoNameRef.subtract(defaultPointerSize);

		mangledNamespaceString = MANGLED_STRING_PREFIX + mangledNamespaceString;

		try {
			symbolTable.createLabel(findSingleMangledString, mangledNamespaceString, globalNamespace,
					SourceType.ANALYSIS);
		} catch (InvalidInputException e) {

			Msg.debug(this, "Could not make symbol for mangled string at " + findSingleMangledString);
			return null;
		}

		// demangle the symbol
		DemanglerCmd cmd = new DemanglerCmd(findSingleMangledString, mangledNamespaceString);
		cmd.applyTo(program, monitor);

		// get the newly created symbol to get the namespace
		Symbol typeinfoNameSymbol = symbolTable.getPrimarySymbol(findSingleMangledString);
		Namespace namespace = typeinfoNameSymbol.getParentNamespace();

		Symbol typeinfoSymbol;
		try {
			typeinfoSymbol = symbolTable.createLabel(typeinfoAddress, "typeinfo", namespace, SourceType.ANALYSIS);
			api.setPlateComment(typeinfoAddress, "typeinfo for " + namespace);
		} catch (InvalidInputException e) {
			Msg.debug(this, "Could not make typeinfo symbol at " + typeinfoAddress);
			return null;
		}

		return typeinfoSymbol;
	}

	private Address findSingleMangledString(String mangledString) {

		Address[] findBytes = extendedFlatAPI.findBytes(null, mangledString, 1);
		if (findBytes.length != 1) {
			return null;
		}
		return findBytes[0];

	}

	private Address getSingleReferenceTo(Address address) throws CancelledException {

		Set<Address> refs = new HashSet<Address>();

		ReferenceManager referenceManager = program.getReferenceManager();
		ReferenceIterator referencesTo = referenceManager.getReferencesTo(address);
		while (referencesTo.hasNext()) {
			monitor.checkCancelled();

			Reference next = referencesTo.next();

			Address ref = next.getFromAddress();

			// skip refs without an address
			if (ref == Address.EXT_FROM_ADDRESS) {
				continue;
			}

			refs.add(ref);
		}

		// look for direct refs now
		if (!address.isExternalAddress()) {
			Set<Address> dirRefSet = directRefMap.get(address);
			if (dirRefSet != null) {
				List<Address> directRefs = new ArrayList<Address>(dirRefSet);
				refs.addAll(directRefs);
			}
		}

		List<Address> refList = new ArrayList<Address>(refs);

		if (refList.size() == 1) {
			return refList.get(0);
		}

		return null;

	}

	private List<Address> getAllReferencesTo(Address address) throws CancelledException {

		Set<Address> refs = new HashSet<Address>();

		ReferenceManager referenceManager = program.getReferenceManager();
		ReferenceIterator referencesTo = referenceManager.getReferencesTo(address);
		while (referencesTo.hasNext()) {
			monitor.checkCancelled();

			Reference next = referencesTo.next();

			// if external relocations there will be offset ref and that's ok
			// the ones to skip are offset in the middle of defined data
			if (!inExternalBlock(address) && next.isOffsetReference()) {
				continue;
			}
			if (next.isEntryPointReference()) {
				continue;
			}

			Address ref = next.getFromAddress();

			// skip refs without an address
			if (ref == Address.EXT_FROM_ADDRESS) {
				continue;
			}

			refs.add(ref);
		}

		// look for direct refs now
		Set<Address> directRefs = directRefMap.get(address);
		if (directRefs != null) {
			refs.addAll(directRefs);
		}

		List<Address> refList = new ArrayList<Address>(refs);

		return refList;

	}

	List<Address> findDirectRefsTo(Address address) throws CancelledException {

		byte[] bytes = ProgramMemoryUtil.getDirectAddressBytes(program, address);
		List<Address> foundRefs = new ArrayList<Address>();

		Address start = program.getMinAddress();
		while (start.compareTo(program.getMaxAddress()) < 0) {

			monitor.checkCancelled();

			Address found = program.getMemory().findBytes(start, bytes, null, true, monitor);
			if (found == null) {
				break;
			}
			foundRefs.add(found);

			start = found.add(defaultPointerSize);

		}

		return foundRefs;
	}

	/**
	 * Create a map of addresses to a set of addresses that reference each address
	 * 
	 * @param refPairs list of reference address pairs
	 * @throws CancelledException if cancelled
	 */
	public void createGlobalDirectRefMap(List<ReferenceAddressPair> refPairs) throws CancelledException {

		for (ReferenceAddressPair refPair : refPairs) {
			monitor.checkCancelled();

			Address referencedAddress = refPair.getDestination();
			Address fromAddress = refPair.getSource();
			Set<Address> dirRefs = directRefMap.get(referencedAddress);
			if (dirRefs == null) {
				dirRefs = new HashSet<Address>();
			}
			dirRefs.add(fromAddress);
			directRefMap.put(referencedAddress, dirRefs);
		}

	}

	private void createClassesFromTypeinfos(List<GccTypeinfo> typeinfos) throws CancelledException {

		for (GccTypeinfo typeinfo : typeinfos) {

			monitor.checkCancelled();

			Address typeinfoAddress = typeinfo.getAddress();

			Namespace classNamespace = typeinfo.getNamespace();

			RecoveredClass recoveredClass = getClass(classNamespace);

			// we don't know yet if this class has vftable so just add without for now
			if (recoveredClass == null) {
				recoveredClass = createNewClass(classNamespace, false);
				recoveredClasses.add(recoveredClass);

				classToTypeinfoMap.put(recoveredClass, typeinfoAddress);
			}

			if (recoveredClass != null && !classToTypeinfoMap.containsKey(recoveredClass)) {
				classToTypeinfoMap.put(recoveredClass, typeinfoAddress);
			}

			if (!recoveredClasses.contains(recoveredClass)) {
				recoveredClasses.add(recoveredClass);
			}

			String typeinfoStructureType = typeinfoToStructuretypeMap.get(typeinfoAddress);
			if (typeinfoStructureType == null) {

				// skip if not a class type info struct
				Msg.debug(this, typeinfoAddress + " has no structure type mapping");
				continue;
			}

			// per docs those on this list have no bases (ie parents), and is also a base type
			// for the other two class type representations ie (si and vmi)
			if (typeinfoStructureType.equals(CLASS_TYPE_INFO_STRUCTURE)) {
				nonInheritedClasses.add(recoveredClass);
				recoveredClass.setHasSingleInheritance(true);
				recoveredClass.setHasParentClass(false);
				recoveredClass.setInheritsVirtualAncestor(false);
				continue;
			}

			// per docs those on this list are
			// classes containing only a single, public, non-virtual base at offset zero
			if (typeinfoStructureType.equals(SI_CLASS_TYPE_INFO_STRUCTURE)) {
				singleInheritedClasses.add(recoveredClass);
				recoveredClass.setHasSingleInheritance(true);
				recoveredClass.setInheritsVirtualAncestor(false);
				continue;
			}

			// not necessarily multiple - maybe just a single virtual ancestor or maybe a
			// single non-public one
			if (typeinfoStructureType.equals(VMI_CLASS_TYPE_INFO_STRUCTURE)) {
				multiAndOrVirtuallyInheritedClasses.add(recoveredClass);
			}
		}
	}
	
	private void updateClassWithVfunctions(List<RecoveredClass> recoveredClasses, List<Vtable> vtables) throws Exception {
		
		for (RecoveredClass recoveredClass : recoveredClasses) {

			monitor.checkCancelled();
			Namespace classNamespace = recoveredClass.getClassNamespace();

			Vtable classVtable = getVtable(vtables, classNamespace);

			if (classVtable == null) {
				Msg.debug(this, "No vtable for class: " + classNamespace.getName());
				return;
			}

			Address vftableAddress = classVtable.getVfunctionTop();
			if (vftableAddress == null) {
				return;
			}

			Symbol vftableSymbol = symbolTable.getPrimarySymbol(vftableAddress);

			updateClassWithVftable(recoveredClass, vftableSymbol, true, false);

			// For now just assume simple case
			// will have to refactor helper to handle gcc better
			recoveredClass.addClassOffsetToVftableMapping(0, vftableAddress);
		}
	}

	/**
	 * Use information from RTTI Base class Arrays to create class hierarchy lists
	 * and maps
	 * 
	 * @throws CancelledException if cancelled
	 */
	private void createClassHierarchyListAndMap() throws CancelledException, Exception {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCancelled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();
			List<RecoveredClass> classHierarchyList = new ArrayList<RecoveredClass>();

			// no parent case
			if (nonInheritedClasses.contains(recoveredClass)) {
				classHierarchyList = getNoClassHierarchy(recoveredClass);
				recoveredClass.setClassHierarchy(classHierarchyList);
				continue;
			}

			// case where there is all single inheritance in a class ancestry chain
			if (singleInheritedClasses.contains(recoveredClass)) {
				classHierarchyList = getSingleClassHierarchy(recoveredClass);
				recoveredClass.setClassHierarchy(classHierarchyList);
				continue;
			}

		}

		recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCancelled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();
			List<RecoveredClass> classHierarchyList = new ArrayList<RecoveredClass>();

			// once all the non and single inheritance ones are created, create the multi ones
			// case where there is multi-inheritance somewhere in the chain
			if (multiAndOrVirtuallyInheritedClasses.contains(recoveredClass)) {
				classHierarchyList = getMultiClassHierarchy(recoveredClass);
				recoveredClass.setClassHierarchy(classHierarchyList);
			}
		}

		// create parent class hierarchy maps
		recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCancelled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();
			List<RecoveredClass> parentList = recoveredClass.getParentList();
			Iterator<RecoveredClass> parentIterator = parentList.iterator();
			while (parentIterator.hasNext()) {
				monitor.checkCancelled();
				RecoveredClass parentClass = parentIterator.next();
				recoveredClass.addClassHierarchyMapping(parentClass, parentClass.getClassHierarchy());
			}
		}

		// update the inherits virtual ancestor flag using ancestors - previously was only done for
		// parents but now have all classes with flag set for direct parent so can get the other
		// ancestors too
		recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCancelled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();

			// if we already know it then skip
			if (recoveredClass.inheritsVirtualAncestor()) {
				continue;
			}

			// if hasn't been set yet - check the other ancestors besides parents
			if (hasVirtualAncestor(recoveredClass)) {
				recoveredClass.setInheritsVirtualAncestor(true);
			}
		}

	}

	private boolean hasVirtualAncestor(RecoveredClass recoveredClass) throws CancelledException {

		List<RecoveredClass> classHierarchy = recoveredClass.getClassHierarchy();
		Iterator<RecoveredClass> classIterator = classHierarchy.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCancelled();
			RecoveredClass ancestor = classIterator.next();
			if (ancestor.inheritsVirtualAncestor()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Create the class hierarchy list for a class with no inheritance
	 * 
	 * @param recoveredClass the given class
	 * @return the class hierarchy list for the given class with no inheritance
	 */
	private List<RecoveredClass> getNoClassHierarchy(RecoveredClass recoveredClass) {
		List<RecoveredClass> classHierarchyList = new ArrayList<RecoveredClass>();
		classHierarchyList.add(recoveredClass);
		return classHierarchyList;
	}

	/**
	 * Create the class hierarchy for a class with only single inheritance parents
	 * 
	 * @param recoveredClass the given class
	 * @return the class hierarchy for the given class with only single inheritance
	 *         parents
	 * @throws CancelledException if cancelled
	 */
	List<RecoveredClass> getSingleClassHierarchy(RecoveredClass recoveredClass) throws CancelledException {

		List<RecoveredClass> classHierarchyList = new ArrayList<RecoveredClass>();

		RecoveredClass currentClass = recoveredClass;
		classHierarchyList.add(currentClass);

		while (currentClass.hasParentClass()) {
			monitor.checkCancelled();
			currentClass = currentClass.getParentList().get(0);
			classHierarchyList.add(currentClass);
		}
		return classHierarchyList;
	}

	/**
	 * Create the class hierarchy list for a class with multiple inheritance
	 * 
	 * @param recoveredClass the given class
	 * @return the class hierarchy list for the given class with multiple
	 *         inheritance
	 * @throws CancelledException if cancelled
	 */
	List<RecoveredClass> getMultiClassHierarchy(RecoveredClass recoveredClass) throws CancelledException {

		List<RecoveredClass> classHierarchyList = new ArrayList<RecoveredClass>();

		classHierarchyList.add(recoveredClass);

		List<RecoveredClass> parentList = recoveredClass.getParentList();
		Iterator<RecoveredClass> parentIterator = parentList.iterator();
		while (parentIterator.hasNext()) {
			monitor.checkCancelled();

			RecoveredClass parentClass = parentIterator.next();
			if (nonInheritedClasses.contains(parentClass)) {
				classHierarchyList.addAll(parentClass.getClassHierarchy());
				continue;
			}
			if (singleInheritedClasses.contains(parentClass)) {
				classHierarchyList.addAll(parentClass.getClassHierarchy());
				continue;
			}
			if (multiAndOrVirtuallyInheritedClasses.contains(parentClass)) {
				classHierarchyList.addAll(getMultiClassHierarchy(parentClass));
			}
		}
		return classHierarchyList;

	}

	/**
	 * Method to get address at address + offset
	 * 
	 * @param address the given address
	 * @param offset  the given offset
	 * @return the address at address + offset or null if it doesn't exist
	 */
	private Address getAddress(Address address, int offset) {
		try {
			Address newAddress = address.add(offset);
			return newAddress;
		} catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	/**
	 * Method to determine if there are enough zeros to make a null poihnter and no
	 * references into or out of the middle
	 * 
	 * @param address the given address
	 * @return true if the given address could be a valid null pointer, false if not
	 */
	private boolean isPossibleNullPointer(Address address) throws CancelledException {
		if (!extendedFlatAPI.hasNumZeros(address, defaultPointerSize)) {
			return false;
		}
		return true;
	}

	/**
	 * Method to determine if the given address contains a possible function pointer
	 * 
	 * @param address the given address
	 * @return true if the given address contains a possible function pointer or
	 *         false otherwise
	 * @throws CancelledException if cancelled
	 */
	private boolean isPossibleFunctionPointer(Address address) throws CancelledException {

		// TODO: make one that works for all casea in helper

		long longValue = extendedFlatAPI.getLongValueAt(address);

		Register lowBitCodeMode = program.getRegister("LowBitCodeMode");
		if (lowBitCodeMode != null) {
			longValue = longValue & ~0x1;
		}

		Address possibleFunctionPointer = null;

		try {
			possibleFunctionPointer = address.getNewAddress(longValue);
		} catch (AddressOutOfBoundsException e) {
			return false;
		}

		if (possibleFunctionPointer == null) {
			return false;
		}

		Function function = api.getFunctionAt(possibleFunctionPointer);
		if (function != null) {
			return true;
		}

		AddressSetView executeSet = program.getMemory().getExecuteSet();

		if (!executeSet.contains(possibleFunctionPointer)) {
			return false;
		}

		Instruction instruction = api.getInstructionAt(possibleFunctionPointer);
		if (instruction != null) {
			api.createFunction(possibleFunctionPointer, null);
			return true;

		}

		boolean disassemble = api.disassemble(possibleFunctionPointer);
		if (disassemble) {

			// check for the case where there is conflicting data at the thumb offset function
			// pointer and if so clear the data and redisassemble and remove the bad bookmark
			long originalLongValue = extendedFlatAPI.getLongValueAt(address);
			if (originalLongValue != longValue) {
				Address offsetPointer = address.getNewAddress(originalLongValue);
				if (api.getDataAt(offsetPointer) != null) {
					api.clearListing(offsetPointer);
					disassemble = api.disassemble(address);

					Bookmark bookmark = getBookmarkAt(possibleFunctionPointer, BookmarkType.ERROR, "Bad Instruction",
							"conflicting data");
					if (bookmark != null) {
						api.removeBookmark(bookmark);
					}
				}
			}

			api.createFunction(possibleFunctionPointer, null);
			return true;
		}
		return false;
	}

	private Bookmark getBookmarkAt(Address address, String bookmarkType, String category, String commentContains)
			throws CancelledException {

		Bookmark[] bookmarks = program.getBookmarkManager().getBookmarks(address);

		for (Bookmark bookmark : bookmarks) {
			monitor.checkCancelled();

			if (bookmark.getType().getTypeString().equals(bookmarkType) && bookmark.getCategory().equals(category)
					&& bookmark.getComment().contains(commentContains)) {
				return bookmark;
			}
		}
		return null;
	}

	/**
	 * Method to call create and apply class structures method starting with top
	 * parent classes and non-virtual classes then the children and their children
	 * until all classes are processed.
	 * 
	 * @throws CancelledException when cancelled
	 * @throws Exception          if issue creating data
	 */
	private void createAndApplyClassStructures() throws CancelledException, Exception {

		List<RecoveredClass> listOfClasses = new ArrayList<RecoveredClass>(recoveredClasses);

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		// first process all the classes with no parents
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCancelled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();

			if (recoveredClass.hasMultipleInheritance()) {
				continue;
			}

			if (recoveredClass.hasParentClass()) {
				continue;
			}

			if (!recoveredClass.hasVftable()) {
				createClassStructureWhenNoParentOrVftable(recoveredClass);
				listOfClasses.remove(recoveredClass);
				continue;
			}

			processDataTypes(recoveredClass);
			listOfClasses.remove(recoveredClass);

		}

		// now process the classes that have all parents processed
		// continue looping until all classes are processed
		int numLoops = 0;

		while (!listOfClasses.isEmpty()) {
			monitor.checkCancelled();

			// put in stop gap measure in case some classes never get all
			// parents processed for some reason
			if (numLoops == 100) {
				return;
			}
			numLoops++;

			recoveredClassIterator = recoveredClasses.iterator();
			while (recoveredClassIterator.hasNext()) {

				RecoveredClass recoveredClass = recoveredClassIterator.next();

				monitor.checkCancelled();
				if (!listOfClasses.contains(recoveredClass)) {
					continue;
				}

				if (!allAncestorDataHasBeenCreated(recoveredClass)) {
					continue;
				}

				processDataTypes(recoveredClass);
				listOfClasses.remove(recoveredClass);

			}
		}
	}

	/**
	 * Method to create all the class data types for the current class, name all the
	 * class functions, and put them all into the class namespace
	 * 
	 * @param recoveredClass current class
	 * @throws CancelledException when cancelled
	 * @throws Exception          naming exception
	 */
	private void processDataTypes(RecoveredClass recoveredClass) throws CancelledException, Exception {

		// if recovered class is a special typeinfo class skip it
		if (recoveredClass.getName().endsWith("_class_type_info")) {
			Msg.debug(this, "Not creating class data type for " + recoveredClass.getClassNamespace().getName(true)
					+ " because it is one of the special typeinfo classes.");
			return;
		}

		// can't handle creating class data types for classes with virtual parents yet
		if (recoveredClass.inheritsVirtualAncestor()) {
			Msg.debug(this, "Cannot create class data type for " + recoveredClass.getClassNamespace().getName(true)
					+ " because it has virtual ancestors and we don't yet handle that use case.");
			return;
		}

		// skip any classes that have special typeinfo class parents
		if (recoveredClass.hasParentClass()) {
			List<RecoveredClass> parentList = recoveredClass.getParentList();
			for (RecoveredClass parent : parentList) {
				monitor.checkCancelled();
				if (parent.getName().endsWith("_class_type_info")) {
					Msg.debug(this,
							"Not creating class data type for " + recoveredClass.getClassNamespace().getName(true)
									+ " because it has a parent that is one of the special typeinfo classes.");
					return;
				}
			}
		}

		// can't handle creating class data types for diamond shaped classes yet
		if (recoveredClass.isDiamondShaped()) {
			Msg.debug(this, "Cannot create class data type for " + recoveredClass.getClassNamespace().getName(true)
					+ " because it is diamond shaped and we don't yet handle that use case.");
			return;
		}

		if (!recoveredClass.hasVftable()) {
			createSimpleClassStructure(recoveredClass, null);
			// return in this case because if there is no vftable for a class the script cannot
			// identify any member functions so there is no need to process the rest of this
			// method
			return;
		}

		// create pointers to empty vftable structs so they can be added to the class data type
		// then filled in later
		Map<Address, DataType> vfPointerDataTypes = createEmptyVfTableStructs(recoveredClass);

		// create current class structure and add pointer to vftable, all parent member data
		// structures, and class member data structure
		Structure classStruct = createSimpleClassStructure(recoveredClass, vfPointerDataTypes);

		// Now that we have a class data type
		// name constructor and destructor functions and put into the class namespace
		addConstructorsToClassNamespace(recoveredClass, classStruct);
		addDestructorsToClassNamespace(recoveredClass, classStruct);
		// TODO:
//			addNonThisDestructorsToClassNamespace(recoveredClass);
//			addVbaseDestructorsToClassNamespace(recoveredClass);
//			addVbtableToClassNamespace(recoveredClass);
		// TODO:
//			// add secondary label on functions with inlined constructors or destructors
//			createInlinedConstructorComments(recoveredClass);
//			createInlinedDestructorComments(recoveredClass);
//			createIndeterminateInlineComments(recoveredClass);

		// add label on constructor destructor functions that could not be determined
		createIndeterminateLabels(recoveredClass, classStruct);

		// This is done after the class structure is created and added to the dtmanager
		// because if done before the class structures are created
		// then empty classes will get auto-created in the wrong place
		// when the vfunctions are put in the class

		fillInAndApplyVftableStructAndNameVfunctions(recoveredClass, vfPointerDataTypes, classStruct);

	}

	private Structure createSimpleClassStructure(RecoveredClass recoveredClass,
			Map<Address, DataType> vfPointerDataTypes) throws Exception {

		String className = recoveredClass.getName();

		CategoryPath classPath = recoveredClass.getClassPath();

		// get either existing structure if prog has a structure created by pdb or computed
		// structure from decompiled construtor(s) info
		Structure classStructure;
		if (recoveredClass.hasExistingClassStructure()) {
			classStructure = recoveredClass.getExistingClassStructure();
		} else {
			classStructure = recoveredClass.getComputedClassStructure();
		}

		int structLen = 0;
		if (classStructure != null) {
			structLen = addAlignment(classStructure.getLength());
		}

		Structure classStructureDataType = new StructureDataType(classPath, className, structLen, dataTypeManager);

		// if no inheritance - add pointer to class vftable structure
		if (nonInheritedClasses.contains(recoveredClass) && vfPointerDataTypes != null) {

			// the size was checked before calling this method so we know there is one and only
			// one for this simple case
			Address vftableAddress = recoveredClass.getVftableAddresses().get(0);
			DataType classVftablePointer = vfPointerDataTypes.get(vftableAddress);

			// simple case the offset for vftablePtr is 0
			// if can fit or grow structure, add the vftablePtr to it
			EditStructureUtils.addDataTypeToStructure(classStructureDataType, 0, classVftablePointer,
					CLASS_VTABLE_PTR_FIELD_EXT, monitor);
		}
		// if single inheritance or multi non-virtual (wouldn't have called this method if
		// it were virtually inherited) put parent struct and data into class struct
		else {

			Map<Integer, RecoveredClass> orderToParentMap = classToParentOrderMap.get(recoveredClass);
			if (orderToParentMap == null || orderToParentMap.isEmpty()) {
				throw new Exception("Vmi class " + recoveredClass.getClassNamespace().getName(true)
						+ " should have a parent in the classToParentOrderMap but doesn't");
			}

			Map<RecoveredClass, Long> parentToOffsetMap = classToParentOffsetMap.get(recoveredClass);
			if (parentToOffsetMap.isEmpty()) {
				throw new Exception("Vmi class " + recoveredClass.getClassNamespace().getName(true)
						+ " should have a parent in the classToParentOffsetMap but doesn't");
			}

			int numParents = orderToParentMap.keySet().size();
			for (int i = 0; i < numParents; i++) {
				RecoveredClass parent = orderToParentMap.get(i);

				Long parentOffsetLong = parentToOffsetMap.get(parent);
				if (parentOffsetLong == null) {
					throw new Exception("Can't get parent offset for " + parent.getClassNamespace().getName(true));
				}
				int parentOffset = parentOffsetLong.intValue();

				Structure baseClassStructure = getClassStructureFromDataTypeManager(parent);
				// if we can't get the parent throw exception because it shouldn't get here if the
				// parent doesn't exist
				if (baseClassStructure == null) {
					throw new Exception(
							parent.getClassNamespace().getName(true) + " : structure should exist but doesn't.");
				}

				// if it fits at offset or is at the end and class structure can be grown,
				// copy the whole baseClass structure to the class Structure at the given offset
				EditStructureUtils.addDataTypeToStructure(classStructureDataType, parentOffset, baseClassStructure,
						baseClassStructure.getName(), monitor);
			}

		}

		// figure out class data, if any, create it and add to class structure
		int dataOffset = getDataOffset(recoveredClass, classStructureDataType);
		int dataLen = UNKNOWN;
		if (dataOffset != NONE) {
			dataLen = EditStructureUtils.getNumberOfUndefinedsStartingAtOffset(classStructureDataType, dataOffset,
					monitor);
		}

		if (dataLen != UNKNOWN && dataLen > 0) {

			Structure recoveredClassDataStruct = createClassMemberDataStructure(recoveredClass, classStructureDataType,
					dataLen, dataOffset);

			if (recoveredClassDataStruct != null) {
				// if it fits at offset or is at the end and class structure can be grown,
				// copy the whole baseClass structure to the class Structure at the given offset
				EditStructureUtils.addDataTypeToStructure(classStructureDataType, dataOffset, recoveredClassDataStruct,
						"data", monitor);
			}

		}

		classStructureDataType = addClassVftables(classStructureDataType, recoveredClass, vfPointerDataTypes);

		// unused at this point until something figures out how to create them and where to
		// put them
		classStructureDataType = addVbtableToClassStructure(recoveredClass, classStructureDataType, true);

		if (classStructureDataType.getNumComponents() == classStructureDataType.getNumDefinedComponents()) {
			classStructureDataType.setPackingEnabled(true);
		}

		classStructureDataType.setDescription(createParentStringBuffer(recoveredClass).toString());

		classStructureDataType = (Structure) dataTypeManager.addDataType(classStructureDataType,
				DataTypeConflictHandler.DEFAULT_HANDLER);

		return classStructureDataType;
	}

	private MemoryBlock getExternalBlock() {
		return program.getMemory().getBlock("EXTERNAL");
	}

	private boolean hasExternalBlock() {

		MemoryBlock externalBlock = getExternalBlock();

		if (externalBlock == null) {
			return false;
		}
		return true;
	}

	private boolean inExternalBlock(Address address) {

		MemoryBlock externalBlock = getExternalBlock();
		if (externalBlock == null) {
			return false;
		}
		if (externalBlock.contains(address)) {
			return true;
		}
		return false;

	}

}
