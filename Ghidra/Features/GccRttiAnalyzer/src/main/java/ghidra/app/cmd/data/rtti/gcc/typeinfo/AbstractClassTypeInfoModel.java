package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import java.util.Collections;
import java.util.Set;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.AbstractTypeInfoModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import static ghidra.app.cmd.data.rtti.gcc.GccUtils.PURE_VIRTUAL_FUNCTION_NAME;

/**
 * Base Model for __class_type_info and its derivatives.
 */
public abstract class AbstractClassTypeInfoModel extends AbstractTypeInfoModel implements ClassTypeInfo {

	protected VtableModel vtable = null;

	/**
	 * Constructs a new AbstractClassTypeInfoModel.
	 * 
	 * @param program the program containing the AbstractClassTypeInfoModel.
	 * @param address the address of the AbstractClassTypeInfoModel.
	 */
	protected AbstractClassTypeInfoModel(Program program, Address address) {
		super(program, address);
	}

	private static String getUniqueTypeName(ClassTypeInfo type) throws InvalidDataTypeException {
		StringBuilder builder = new StringBuilder(type.getTypeName());
		for (ClassTypeInfo parent : type.getParentModels()) {
			builder.append(parent.getTypeName());
		}
		return builder.toString();
	}

	@Override
	public String getUniqueTypeName() throws InvalidDataTypeException {
		return getUniqueTypeName(this);
	}

	@Override
	public final Structure getClassDataType() throws InvalidDataTypeException {
		return VariableUtilities.findOrCreateClassStruct(
			getGhidraClass(), program.getDataTypeManager());
	}

	@Override
	public VtableModel getVtable(TaskMonitor monitor) throws InvalidDataTypeException {
		if (vtable != null) {
			return vtable;
		}
		SymbolTable table = program.getSymbolTable();
		for (Symbol symbol : table.getSymbols(VtableModel.SYMBOL_NAME, getGhidraClass())) {
				vtable = new VtableModel(program, symbol.getAddress(), this);
				try {
					vtable.validate();
					return vtable;
				} catch (InvalidDataTypeException e) {
					continue;
				}
		}
		try {
			vtable = (VtableModel) ClassTypeInfoUtils.findVtable(program, address, monitor);
		} catch (CancelledException e) {
			vtable = VtableModel.NO_VTABLE;
		}
		return vtable;
	}

	@Override
	public boolean isAbstract() throws InvalidDataTypeException {
		validate();
		try {
			for (Function[] functionTable : getVtable().getFunctionTables()) {
				for (Function function : functionTable) {
					if (function == null || function.getName().equals(PURE_VIRTUAL_FUNCTION_NAME)) {
						return true;
					}
				}
			}
		} catch (InvalidDataTypeException e) {}
		return false;
	}

	@Override
	public GhidraClass getGhidraClass() throws InvalidDataTypeException {
		validate();
		if (!(namespace instanceof GhidraClass)) {
			try {
				if (namespace.getSymbol().checkIsValid()) {
					namespace = NamespaceUtils.convertNamespaceToClass(namespace);
				} else {
					namespace = TypeInfoUtils.getNamespaceFromTypeName(program, typeName);
					namespace = NamespaceUtils.convertNamespaceToClass(namespace);
				}
			} catch (InvalidInputException e) {
				Msg.error(this, e);
				return null;
			}
		} return (GhidraClass) namespace;
	}

	@Override
	public Set<ClassTypeInfo> getVirtualParents() throws InvalidDataTypeException {
		return Collections.emptySet();
	}

}