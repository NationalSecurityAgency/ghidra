package ghidra.app.plugin.prototype;

import java.util.Set;
import java.util.List;
import java.util.Optional;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;

import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.framework.options.Options;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.address.AddressSetView;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.CreateTypeInfoBackgroundCmd;
import ghidra.app.cmd.data.rtti.gcc.CreateVtableBackgroundCmd;
import ghidra.app.cmd.data.rtti.gcc.CreateVttBackgroundCmd;
import ghidra.app.cmd.data.rtti.gcc.GccUtils;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.app.cmd.data.rtti.gcc.VtableUtils;
import ghidra.app.cmd.data.rtti.gcc.VttModel;
import ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory;

import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;
import static ghidra.app.cmd.data.rtti.gcc.GccUtils.PURE_VIRTUAL_FUNCTION_NAME;

public class GccRttiAnalyzer extends AbstractAnalyzer {

    private static final String NAME = "GCC RTTI Analyzer";
    private static final String DESCRIPTION =
        "This analyzer finds and creates all of the RTTI metadata structures and their associated vtables.";

    private static final String OPTION_FUNDAMENTAL_NAME = "Find Fundamental Types";
    private static final boolean OPTION_DEFAULT_FUNDAMENTAL = false;
    private static final String OPTION_FUNDAMENTAL_DESCRIPTION =
        "Turn on to scan for __fundamental_type_info and its derivatives.";

    private boolean fundamentalOption;

    private Program program;
    private TaskMonitor monitor;
    private CancelOnlyWrappingTaskMonitor dummy;

    // The only one excluded is BaseClassTypeInfoModel
    private static final List<String> CLASS_TYPESTRINGS = Arrays.asList(new String[]{
        ClassTypeInfoModel.ID_STRING,
        SiClassTypeInfoModel.ID_STRING,
        VmiClassTypeInfoModel.ID_STRING
    });

    private static final String[] FUNDAMENTAL_TYPESTRINGS = new String[] {
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
     * Constructs an RttiAnalyzer.
     */
    public GccRttiAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        setSupportsOneTimeAnalysis();
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before().before());
        setDefaultEnablement(true);
        setPrototype();
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
                        log.appendMsg(this.getName(), "RTTI not detected");
                        return false;
                    }
            }

            try {
                /* Create the vmi replacement base to prevent a
                   placeholder struct from being generated  */
                addDataTypes();
                if (fundamentalOption) {
                    for (String typeString : FUNDAMENTAL_TYPESTRINGS) {
                        applyTypeInfoTypes(typeString);
                    }
                }
                applyTypeInfoTypes(TypeInfoModel.ID_STRING);
                for (String typeString : CLASS_TYPESTRINGS) {
                    applyTypeInfoTypes(typeString);
                }
                createVtables();
                return true;
            } catch (CancelledException e) {
                throw e;
            } catch (Exception e) {
                e.printStackTrace();
                log.appendException(e);
                return false;
            }
    }

    @Override
    @SuppressWarnings("hiding")
    public void analysisEnded(Program program) {
        classes = null;
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
	
	private static boolean isPureVirtualType(ClassTypeInfo type) {
		return type.getTypeName().contains(PURE_VIRTUAL_CONTAINING_STRING);
	}

    private Function getPureVirtualFunction() throws CancelledException {
		try {
			final Optional<Function[][]> function =
				classes.stream()
					   .filter(GccRttiAnalyzer::isPureVirtualType)
					   .map(ClassTypeInfo::getVtable)
					   .filter(Vtable::isValid)
					   .map(Vtable::getFunctionTables)
					   .filter(this::checkTableAddresses)
					   .findFirst();
			if (function.isPresent()) {
				// pre checked
				return function.get()[0][2];
			}
		} catch (RuntimeException e) {
			if (e.getCause() instanceof CancelledException) {
				throw (CancelledException) e.getCause();
			}
			throw e;
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

    public final void markDataAsConstant(Address address) {
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
        ClassTypeInfoUtils.sortByMostDerived(program, classes, monitor);
        Collections.reverse(classes);
        monitor.initialize(classes.size());
        monitor.setMessage("Finding vtables");
        for (ClassTypeInfo type : classes) {
            monitor.checkCanceled();
            VtableModel vtable = (VtableModel) type.getVtable();
            if (Vtable.isValid(vtable)) {
				createVtable(vtable);
            }
            monitor.incrementProgress(1);
        }
    }

    private Set<Address> getStaticReferences(String typeString) throws CancelledException {
        try {
            ClassTypeInfo typeinfo = (ClassTypeInfo) TypeInfoUtils.findTypeInfo(
                program, typeString, dummy);
            Vtable vtable = typeinfo.getVtable(dummy);
            return GccUtils.getDirectDataReferences(
                program, vtable.getTableAddresses()[0], dummy);
        } catch (NullPointerException e) {
            return Collections.emptySet();
        }
    }

    private Set<Address> getClangDynamicReferences(Relocation reloc) throws CancelledException {
        Data data = program.getListing().getDataContaining(reloc.getAddress());
        if (data == null) {
            Msg.error(this, "Null data at clang relocation");
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
        } return getStaticReferences(typeString);
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
        monitor.setMessage(
                "Creating "+typeClass.getName()+" structures");
        for (Address reference : types) {
            monitor.checkCanceled();
            TypeInfo type = TypeInfoFactory.getTypeInfo(program, reference);
            if (type == null) {
                monitor.incrementProgress(1);
                continue;
            }
			if (isClass) {
				ClassTypeInfo classType = ((ClassTypeInfo) type);
				classType.getGhidraClass();
				classes.add(classType);
			}
			CreateTypeInfoBackgroundCmd cmd = new CreateTypeInfoBackgroundCmd(type);
			cmd.applyTo(program, dummy);
			markDataAsConstant(type.getAddress());
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
