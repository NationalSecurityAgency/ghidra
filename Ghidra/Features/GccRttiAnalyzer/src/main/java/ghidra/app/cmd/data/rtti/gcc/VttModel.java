package ghidra.app.cmd.data.rtti.gcc;

import java.util.*;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

public class VttModel {

	public static final String SYMBOL_NAME = "VTT";
	public static final VttModel INVALID = new VttModel();
	private static final String ERROR_MESSAGE = "Error fetching base parent models.";

	private Program program;
	private Address address;
	private int elementCount = -1;
	private DataType dataType;
	private ClassTypeInfo typeinfo;
	private int pointerSize;
	private List<VtableModel> constructionModels;
	private Set<Address> validAddresses;

	private VttModel() {
		this.elementCount = 0;
	}

	/**
	 * Constructs a VttModel.
	 * 
	 * @param program
	 * @param address
	 */
	public VttModel(Program program, Address address) {
		this.program = program;
		this.address = address;
		this.pointerSize = program.getDefaultPointerSize();
		if (GccUtils.isValidPointer(program, address)) {
			Address pointee = getAbsoluteAddress(program, address).subtract(pointerSize);
			if (!TypeInfoUtils.isTypeInfoPointer(program, pointee)) {
				elementCount = 0;
			} else {
				pointee =  getAbsoluteAddress(program, pointee);
				this.typeinfo = (ClassTypeInfo) TypeInfoFactory.getTypeInfo(program, pointee);
				if (!typeinfo.hasParent()) {
					elementCount = 0;
				}
				validAddresses = new HashSet<>();
				try {
					for (ClassTypeInfo base : typeinfo.getParentModels()) {
						validAddresses.add(base.getAddress());
					}
					validAddresses.add(typeinfo.getAddress());
				} catch (InvalidDataTypeException e) {
					Msg.error(this, ERROR_MESSAGE, e);
				}
			}
		} else {
			elementCount = 0;
		}
	}

	@Override
	public int hashCode() {
		if (isValid()) {
			return getAddress().hashCode();
		}
		return super.hashCode();
	}

	@Override
	public boolean equals(Object object) {
		if (!(object instanceof VttModel)) {
			return false;
		}
		return ((VttModel) object).getAddress().equals(address);
	}

	/**
	 * Gets the address of this VttModel.
	 * 
	 * @return the address of this VttModel.
	 */
	public Address getAddress() {
		return address;
	}

	/**
	 * Checks if this VttModel is valid.
	 * 
	 * @return true if valid.
	 */
	public boolean isValid() {
		int count = getElementCount();
		return count > 0;
	}

	/**
	 * Gets the VtableModel at the specified ordinal.
	 * 
	 * @param ordinal
	 * @return the VtableModel at the specified ordinal.
	 */
	public Vtable getVtableModel(int ordinal) {
		Address pointee = getElementPointee(ordinal);
		return pointee != null ? getVtableContaining(pointee) : VtableModel.NO_VTABLE;
	}

	/**
	 * Gets the ClassTypeInfo at the specified ordinal.
	 * 
	 * @param ordinal
	 * @return the ClassTypeInfo at the specified ordinal or null if none exists.
	 */
	public ClassTypeInfo getTypeInfo(int ordinal) {
		Address pointee = getElementPointee(ordinal);
		if (pointee != null) {
			Address typeAddress = getAbsoluteAddress(program, pointee);
			return (ClassTypeInfo) TypeInfoFactory.getTypeInfo(program, typeAddress);
		}
		return null;
	}

	private Address getElementPointee(int ordinal) {
		if (ordinal >= getElementCount()) {
			return null;
		}
		Address currentAddress = address.add(ordinal * pointerSize);
		return getAbsoluteAddress(program, currentAddress).subtract(pointerSize);
	}

	private static boolean vtableContainsAddress(VtableModel vtable, Address a) {
		Address startAddress = vtable.getAddress();
		AddressSet set = new AddressSet(startAddress, startAddress.add(vtable.getLength()));
		return set.contains(a);
	}

	private VtableModel getVtableContaining(Address a) {
		for (VtableModel vtable : constructionModels) {
			if (vtableContainsAddress(vtable, a)) {
				return vtable;
			}
		}
		try {
			VtableModel vtable = (VtableModel) typeinfo.getVtable();
			if (vtableContainsAddress(vtable, a)) {
				return vtable;
			}
		} catch (InvalidDataTypeException e) {
			Msg.error(this, e);
		}
		return null;
	}

	/**
	 * Gets the construction vtable models in this VttModel.
	 * 
	 * @return the construction vtable models in this VttModel.
	 */
	public VtableModel[] getConstructionVtableModels() {
		if (!isValid()) {
			return new VtableModel[0];
		}
		return constructionModels.toArray(new VtableModel[constructionModels.size()]);
	}

	private Address getTIAddress(Address pointerAddress) {
		try {
			Address pointer = getTIPointer(pointerAddress);
			return pointer.equals(Address.NO_ADDRESS) ? pointer
				: getAbsoluteAddress(program, pointer);
		} catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	private Address getTIPointer(Address pointerAddress) {
		Address pointee = getAbsoluteAddress(program, pointerAddress);
		if (pointee != null) {
			Address pointer = pointee.subtract(pointerSize);
			if (!TypeInfoUtils.isTypeInfoPointer(program, pointer)) {
				return Address.NO_ADDRESS;
			} return pointer;
		}
		return Address.NO_ADDRESS;
	}

	private int getSubTableCount(Address startAddress) {
		int i = 0;
		Address tiAddress = getTIAddress(startAddress);
		Address currentTIAddress = tiAddress;
		while (tiAddress.equals(currentTIAddress)) {
			if (!GccUtils.isValidPointer(program, startAddress)) {
				break;
			}
			if(!validAddresses.contains(tiAddress)) {
				break;
			}
			currentTIAddress = getTIAddress(startAddress.add(++i * pointerSize));
		} return i;
	}

	private int getVTTableCount() {
		int tableSize = 0;
		Address currentAddress = address;
		Set<ClassTypeInfo> validTypes;
		try {
			validTypes = new HashSet<>(Arrays.asList(typeinfo.getParentModels()));
			Set<ClassTypeInfo> vParents = typeinfo.getVirtualParents();
			if (!validTypes.containsAll(vParents)) {
				for (ClassTypeInfo parent : new HashSet<>(validTypes)) {
					validTypes.addAll(Arrays.asList(parent.getParentModels()));
				}
				validTypes.addAll(vParents);
			}
			validTypes.add(typeinfo);
			validTypes.forEach((a) -> validAddresses.add(a.getAddress()));
		} catch (InvalidDataTypeException e) {
			return 0;
		}
		constructionModels = new ArrayList<>();
		while (true) {
			if (!GccUtils.isValidPointer(program, currentAddress)) {
				break;
			}
			Address tiAddress = getTIAddress(currentAddress);
			if (tiAddress == null || tiAddress.equals(Address.NO_ADDRESS)) {
				break;
			}
			ClassTypeInfo currentType =
				(ClassTypeInfo) TypeInfoFactory.getTypeInfo(program, tiAddress);
			if (!validTypes.contains((currentType))) {
				break;
			}
			int subCount = getSubTableCount(currentAddress);
			if(tiAddress.equals(typeinfo.getAddress())) {
				tableSize += subCount;
				currentAddress = address.add(tableSize * pointerSize);
				continue;
			}
			VtableModel cvtable = new VtableModel(
				program, getTIPointer(currentAddress), currentType, subCount, true);
			tableSize += subCount;
			currentAddress = address.add(tableSize * pointerSize);
			constructionModels.add(cvtable);
		} return tableSize;
	}
	
	/**
	 * Gets the number of elements in this VttModel.
	 * 
	 * @return the number of VTable Table elements or 0 if invalid.
	 */
	public int getElementCount() {
		if (elementCount == -1) {
			elementCount = getVTTableCount();
		}
		return elementCount;
	}

	/**
	 * Gets the DataType for this VttModel.
	 * 
	 * @return the DataType for this VttModel.
	 */
	public DataType getDataType() {
		if (dataType == null) {
			DataTypeManager dtm = program.getDataTypeManager();
			PointerDataType pointerDt = new PointerDataType(dtm);
			dataType = new ArrayDataType(pointerDt, getElementCount(), pointerSize, dtm);
		}
		return dataType;
	}

}
