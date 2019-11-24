package ghidra.app.cmd.data.rtti.gcc;

import java.util.List;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.util.exception.CancelledException;

import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.data.DataUtilities.ClearDataMode;

public abstract class AbstractCreateVtableBackgroundCmd extends BackgroundCommand {

	private VtableModel vtable;
	private TaskMonitor monitor;
	private Program program;

	private static final String ERROR_MESSAGE = "Can only apply a vtable data type to a program.";
	private static final DemanglerOptions OPTIONS = new DemanglerOptions();

	protected AbstractCreateVtableBackgroundCmd(VtableModel vtable, String name) {
		super(name, true, true, false);
		this.vtable = vtable;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor taskMonitor) {
		try {
			if (!(obj instanceof Program)) {
				Msg.error(this, ERROR_MESSAGE);
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
			createData(vtable.getDataTypes());
			return createAssociatedData();
		} catch (CodeUnitInsertionException e) {
			Msg.error(this, e);
			return false;
		}
	}

	private void createData(List<DataType> dataTypes) throws CodeUnitInsertionException {
		Listing listing = program.getListing();
		DataTypeManager dtm = program.getDataTypeManager();
		Address currentAddress = vtable.getAddress();
		for (DataType dt : dataTypes) {
			dt = dtm.resolve(dt, DataTypeConflictHandler.KEEP_HANDLER);
			Data data = listing.getDataContaining(currentAddress);
			if (data != null && data.getDataType().equals(dt)) {
				currentAddress = currentAddress.add(data.getLength());
				continue;
			}
			DataUtilities.createData(
				program, currentAddress, dt, 0,
				false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			currentAddress = currentAddress.add(dt.getLength());
		}
	}

	protected abstract String getMangledString() throws InvalidDataTypeException;
	protected abstract String getSymbolName();

	private boolean createAssociatedData() {
		try {
			DemangledObject demangled = DemanglerUtil.demangle(program, getMangledString());
			return demangled.applyTo(program, vtable.getAddress(), OPTIONS, monitor);
		} catch (Exception e) {
			return false;
		}
	}
}
