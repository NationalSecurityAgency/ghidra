package ghidra.app.plugin.prototype;

import java.util.*;

import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.framework.options.Options;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.data.rtti.gcc.*;
import ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.app.cmd.data.rtti.*;

import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;
import static ghidra.app.cmd.data.rtti.gcc.GccUtils.PURE_VIRTUAL_FUNCTION_NAME;

public class GccRttiAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "GCC RTTI Analyzer";
	private static final String DESCRIPTION =
		"This analyzer finds and creates all of the RTTI structures and their associated vtables.";

	private static final String OPTION_FUNDAMENTAL_NAME = "Find Fundamental Types";
	private static final boolean OPTION_DEFAULT_FUNDAMENTAL = false;
	private static final String OPTION_FUNDAMENTAL_DESCRIPTION =
		"Turn on to scan for __fundamental_type_info and its derivatives.";
	private static final String ERROR_MESSAGE = "RTTI not detected";
	private static final String CLANG_ERROR_MESSAGE = "Null data at clang relocation";

	private boolean fundamentalOption;
	private Program program;
	private TaskMonitor monitor;
	private CancelOnlyWrappingTaskMonitor dummy;

	// The only one excluded is BaseClassTypeInfoModel
	private static final Set<String> CLASS_TYPESTRINGS = Collections.unmodifiableSet(
		Set.of(
			ClassTypeInfoModel.ID_STRING,
			SiClassTypeInfoModel.ID_STRING,
			VmiClassTypeInfoModel.ID_STRING
			));

	private static final String[] FUNDAMENTAL_TYPESTRINGS = new String[]{
		FundamentalTypeInfoModel.ID_STRING,
		PBaseTypeInfoModel.ID_STRING,
		PointerToMemberTypeInfoModel.ID_STRING,
		PointerTypeInfoModel.ID_STRING,
		ArrayTypeInfoModel.ID_STRING,
		EnumTypeInfoModel.ID_STRING,
		FunctionTypeInfoModel.ID_STRING,
		IosFailTypeInfoModel.ID_STRING
	};

	private ArrayList<ClassTypeInfo> classes;
	private boolean relocatable;

	// if a typename contains this, vftable components index >= 2 point to __cxa_pure_virtual
	private static final String PURE_VIRTUAL_CONTAINING_STRING = "abstract_base";

	/**
	 * Constructs a GccRttiAnalyzer.
	 */
	public GccRttiAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before().before());
		setDefaultEnablement(true);
	}

	@Override
	@SuppressWarnings("hiding")
	public boolean canAnalyze(Program program) {
		return GccUtils.isGnuCompiler(program);
	}

	@Override
	@SuppressWarnings("hiding")
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
		throws CancelledException {
			this.program = program;
			this.monitor = monitor;
			this.relocatable = program.getRelocationTable().isRelocatable();
			
			dummy = new CancelOnlyWrappingTaskMonitor(monitor);
			classes = new ArrayList<>();
			for (String typeString : CLASS_TYPESTRINGS) {
				if (!getDynamicReferences(typeString).isEmpty()) {
					relocatable = true;
					break;
				}
			}
			if (!relocatable) {
				if (TypeInfoUtils.findTypeInfo(
					program, set, TypeInfoModel.ID_STRING, dummy) == null) {
						log.appendMsg(this.getName(), ERROR_MESSAGE);
						return false;
					}
			}

			try {
				/* Create the vmi replacement base to prevent a
				   placeholder struct from being generated  */
				addDataTypes();
				applyTypeInfoTypes(TypeInfoModel.ID_STRING);
				if (fundamentalOption) {
					for (String typeString : FUNDAMENTAL_TYPESTRINGS) {
						applyTypeInfoTypes(typeString);
					}
				}
				for (String typeString : CLASS_TYPESTRINGS) {
					applyTypeInfoTypes(typeString);
				}
				createVtables();
				return true;
			} catch (CancelledException e) {
				throw e;
			} catch (Exception e) {
				log.appendException(e);
				return false;
			}
	}

	@Override
	@SuppressWarnings("hiding")
	public void analysisEnded(Program program) {
		// Not sure if this an appropriate way of cleaning up.
		this.program = null;
		this.monitor = null;
		this.classes = null;
		super.analysisEnded(program);
	}

	private void addDataTypes() {
		DataTypeManager dtm = program.getDataTypeManager();
		dtm.resolve(VmiClassTypeInfoModel.getDataType(dtm), REPLACE_HANDLER);
	}

	private boolean checkTableAddresses(Function[][] functionTables) {
		if (functionTables.length == 0 || functionTables[0].length < 3) {
			return false;
		}
		if (functionTables[0].length >= 3) {
			// sanity check. This is only possible for __cxa_pure_virtual
			return functionTables[0][2].equals(functionTables[0][3]);
		}
		return false;
	}

	private Function getPureVirtualFunction() throws CancelledException,
		InvalidDataTypeException {
			for (ClassTypeInfo type : classes) {
				if (type.getTypeName().contains(PURE_VIRTUAL_CONTAINING_STRING)) {
					Vtable vtable = type.getVtable(dummy);
					try {
						vtable.validate();
					} catch (InvalidDataTypeException e) {
						continue;
					}
					Function[][] functionTables = vtable.getFunctionTables();
					if (checkTableAddresses(functionTables)) {
						return functionTables[0][2];
					}
				}
			}
			return null;
	}

	private void findAndCreatePureVirtualFunction() throws CancelledException,
		InvalidDataTypeException {
			monitor.setMessage("Locating "+PURE_VIRTUAL_FUNCTION_NAME);
			Function pureVirtual = getPureVirtualFunction();
			try {
				pureVirtual.setName(PURE_VIRTUAL_FUNCTION_NAME, SourceType.IMPORTED);
				pureVirtual.setNoReturn(true);
				pureVirtual.setReturnType(VoidDataType.dataType, SourceType.IMPORTED);
				pureVirtual.setCallingConvention(
					GenericCallingConvention.stdcall.getDeclarationName());
			} catch (Exception e) {
				return;
			}
	}

	private void createVtable(VtableModel vtable) throws Exception {
		CreateVtableBackgroundCmd vtableCmd = new CreateVtableBackgroundCmd(vtable);
		vtableCmd.applyTo(program, dummy);
		markDataAsConstant(vtable.getAddress());
		if (!vtable.getTypeInfo().isAbstract()) {
			for (Address tableAddress : vtable.getTableAddresses()) {
				markDataAsConstant(tableAddress);
			}
		}
		locateVTT(vtable);
		monitor.incrementProgress(1);
	}

	private void markDataAsConstant(Address address) {
		Data data = program.getListing().getDataAt(address);
		if (data == null) {
			return;
		}
		SettingsDefinition[] settings = data.getDataType().getSettingsDefinitions();
		for (SettingsDefinition setting : settings) {
			if (setting instanceof MutabilitySettingsDefinition) {
				MutabilitySettingsDefinition mutabilitySetting =
					(MutabilitySettingsDefinition) setting;
				mutabilitySetting.setChoice(data, MutabilitySettingsDefinition.CONSTANT);
			}
		}
	}

	private void locateVTT(Vtable vtable) throws Exception {
		ClassTypeInfo type = vtable.getTypeInfo();
		if (!CLASS_TYPESTRINGS.contains(type.getTypeName())) {
			VttModel vtt = VtableUtils.getVttModel(program, (VtableModel) vtable);
			if (vtt.isValid()) {
				createVtt(type, vtt);
			}
		}
	}

	private void createVtt(ClassTypeInfo type, VttModel vtt) {
		CreateVttBackgroundCmd cmd =
			new CreateVttBackgroundCmd(vtt, type);
		cmd.applyTo(program, dummy);
	}

	private void createVtables() throws Exception {
		findAndCreatePureVirtualFunction();
		monitor.setMessage("Sorting Classes...");
		ClassTypeInfoUtils.sortByMostDerived(program, classes);
		Collections.reverse(classes);
		monitor.initialize(classes.size());
		monitor.setMessage("Finding vtables");
		for (ClassTypeInfo type : classes) {
			monitor.checkCanceled();
			VtableModel vtable = (VtableModel) type.getVtable();
			if (vtable == null) {
				monitor.incrementProgress(1);
				continue;
			}
			try {
				vtable.validate();
			} catch (InvalidDataTypeException e) {
				monitor.incrementProgress(1);
				continue;
			}
			createVtable(vtable);
		}
	}

	private Set<Address> getStaticReferences(String typeString) throws CancelledException {
		try {
			ClassTypeInfo typeinfo = (ClassTypeInfo) TypeInfoUtils.findTypeInfo(
				program, typeString, dummy);
			Vtable vtable = typeinfo.getVtable(dummy);
			return GccUtils.getDirectDataReferences(
				program, vtable.getTableAddresses()[0], dummy);
		} catch (NullPointerException | InvalidDataTypeException e) {
			return Collections.emptySet();
		}
	}

	private Set<Address> getClangDynamicReferences(Relocation reloc) throws CancelledException {
		Data data = program.getListing().getDataContaining(reloc.getAddress());
		if (data == null) {
			Msg.error(this, CLANG_ERROR_MESSAGE);
			return null;
		}
		int start = 0;
		int ptrdiffSize = GccUtils.getPtrDiffSize(program.getDataTypeManager());
		Set<Address> result = new HashSet<>();
		while (start < data.getLength()) {
			result.addAll(GccUtils.getDirectDataReferences(
				program, data.getAddress().add(start), dummy));
			start += ptrdiffSize;
		}
		return result;
	}

	private Set<Address> getDynamicReferences(String typeString) throws CancelledException {
		Iterator<Relocation> relocations = program.getRelocationTable().getRelocations();
		Set<Address> result = new LinkedHashSet<>();
		while (relocations.hasNext()) {
			Relocation reloc = relocations.next();
			String name = reloc.getSymbolName();
			if (name == null) {
				continue;
			}
			if (name.equals(VtableModel.MANGLED_PREFIX+typeString)) {
				if (reloc.getType() == GccUtils.UNSUPPORTED_RELOCATION) {
					return getClangDynamicReferences(reloc);
				}
				result.add(reloc.getAddress());
			}
		} return result;
	}

	private Set<Address> getReferences(String typeString) throws CancelledException {
		if (relocatable) {
			return getDynamicReferences(typeString);
		}
		return getStaticReferences(typeString);
	}

	private void applyTypeInfoTypes(String typeString) throws Exception {
		boolean isClass = CLASS_TYPESTRINGS.contains(typeString);
		Set<Address> types = getReferences(typeString);
		if (types.isEmpty()) {
			return;
		}
		if (isClass) {
			classes.ensureCapacity(classes.size() + types.size());
		}
		Namespace typeClass = TypeInfoUtils.getNamespaceFromTypeName(program, typeString);
		monitor.initialize(types.size());
		monitor.setMessage("Creating "+typeClass.getName()+" structures");
		for (Address reference : types) {
			monitor.checkCanceled();
			TypeInfo type = TypeInfoFactory.getTypeInfo(program, reference);
			if (type == null) {
				monitor.incrementProgress(1);
				continue;
			}
			try {
				type.validate();
				if (isClass) {
					ClassTypeInfo classType = ((ClassTypeInfo) type);
					classType.getGhidraClass();
					classes.add(classType);
				}
				CreateTypeInfoBackgroundCmd cmd = new CreateTypeInfoBackgroundCmd(type);
				cmd.applyTo(program, dummy);
				markDataAsConstant(type.getAddress());
			} catch (InvalidDataTypeException e) {}
			monitor.incrementProgress(1);
		}
	}

	
	@Override
	@SuppressWarnings("hiding")
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
		options.registerOption(OPTION_FUNDAMENTAL_NAME, OPTION_DEFAULT_FUNDAMENTAL, null,
			OPTION_FUNDAMENTAL_DESCRIPTION);

		fundamentalOption =
			options.getBoolean(OPTION_FUNDAMENTAL_NAME, OPTION_DEFAULT_FUNDAMENTAL);
	}
}
