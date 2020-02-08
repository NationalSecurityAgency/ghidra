package ghidra.app.cmd.data.rtti.gcc;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import ghidra.program.model.listing.Data;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Pointer;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.data.DataUtilities.ClearDataMode;

public class CreateVttBackgroundCmd extends BackgroundCommand {

    private static final String NAME = CreateVttBackgroundCmd.class.getSimpleName();

    private VttModel vtt;
    private ClassTypeInfo child;
    private TaskMonitor monitor;
    private Program program;

    private static final String PREFIX = "_ZTT";
    private static final String VTT = "VTT";
    private static final DemanglerOptions OPTIONS = new DemanglerOptions();

    public CreateVttBackgroundCmd(VttModel vtt, ClassTypeInfo child) {
        super(NAME, true, true, false);
        this.vtt = vtt;
        this.child = child;
    }

    @Override
    public final boolean applyTo(DomainObject obj, TaskMonitor taskMonitor) {
        try {
            if (!vtt.isValid()) {
                return false;
            } else if (!(obj instanceof Program)) {
                String message = "Can only apply a vtable data type to a program.";
                Msg.error(this, message);
                return false;
            }
            program = (Program) obj;
            monitor = taskMonitor;
            return doApplyTo();
        } catch (CancelledException e) {
            setStatusMsg("User cancelled " + getName() + ".");
            return false;
        }
    }

    private boolean doApplyTo() throws CancelledException {
        try {
            monitor.checkCanceled();
            Data data = program.getListing().getDataContaining(vtt.getAddress());
            if (data != null && data.isArray()) {
                Array array = (Array) data.getDataType();
                if (array.getDataType() instanceof Pointer) {
                    if (array.getNumElements() > vtt.getElementCount()) {
                        return createAssociatedData();
                    }
                }
            }
            createData(vtt.getAddress(), vtt.getDataType());
            return createAssociatedData();
        } catch (CodeUnitInsertionException | InvalidDataTypeException e) {
            Msg.trace(this, e);
            return false;
        }
    }

    private Data createData(Address address, DataType dt) throws CodeUnitInsertionException {
        return DataUtilities.createData(program, address, dt, 0, false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
    }

    private boolean createAssociatedData() throws InvalidDataTypeException {
        SymbolTable table = program.getSymbolTable();
        for (VtableModel model : vtt.getConstructionVtableModels()) {
            Address vtableAddress = ((VtableModel) model.getTypeInfo().getVtable()).getAddress();
            if (!model.getAddress().equals(vtableAddress)) {
                    CreateConstructionVtableBackgroundCmd cmd =
                    new CreateConstructionVtableBackgroundCmd(model, child);
                    if (!cmd.applyTo(program, monitor)) {
                        return false;
                    }
            } else {
                CreateVtableBackgroundCmd cmd =
                new CreateVtableBackgroundCmd(model);
                if (!cmd.applyTo(program, monitor)) {
                    return false;
                }
            }
        }
        Symbol primarySymbol = table.getPrimarySymbol(vtt.getAddress());
        if (primarySymbol != null && primarySymbol.getName().equals(VTT)) {
            return true;
        }
        try {
            DemangledObject demangled = DemanglerUtil.demangle(program, PREFIX+child.getTypeName());
            if (!demangled.applyTo(program, vtt.getAddress(), OPTIONS, monitor)) {
                return false;
            }
            Symbol[] symbols = table.getSymbols(vtt.getAddress());
            for (Symbol symbol : symbols) {
                if (symbol.getName(true).equals(demangled.getDemangledName())) {
                    symbol.setPrimary();
                }
            }
            return true;
        } catch (Exception e) {
            Msg.error(this, e);
            return false;
        }
    }
}
