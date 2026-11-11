
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
// Script ensures that the PASCAL calling convention replaces STDCALL
// on function parameters and changes the stack reference for left-to-
// right stacking.  On the way, it also ensures that all Thunks are
// also converted.  This applies to Windows 16-bit apps.
//
//@category Repair
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.pcodeCPort.sleighbase.address_set;
import ghidra.program.database.symbol.VariableSymbolDB;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DynamicDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class _SetFunctonNameFromLPSTR extends GhidraScript {

	private int cntConvertionTotal;
	private int cntConvertionChanged;

	private List<String> warningMessages = new ArrayList<String>();

	@Override
	public void run() throws Exception {

		// reset for this run
		cntConvertionTotal = 0;
		cntConvertionChanged = 0;

		warningMessages.clear();

		Listing listing = currentProgram.getListing();

		if (currentAddress != null) {
			AddressSetView view = currentSelection;
			if ((view == null) || (view.isEmpty())) {
				doRun(currentAddress, listing);
			}
			else {
				AddressIterator iterAddr = view.getAddresses(true);

				Address lastArrayAddress = null;
				while (iterAddr.hasNext()) {
					if (monitor.isCancelled()) {
						break;
					}

					Address address = iterAddr.next();
					if ((null != lastArrayAddress) && (lastArrayAddress.compareTo(address) > 0)) {
						continue;
					}
					doRun(address, listing);
				}
			}

			// build popup information
			String buf = "Update " + cntConvertionChanged + " function names out of " + cntConvertionTotal + ".";
			if (!warningMessages.isEmpty()) {
				buf = buf + "\n\n" + String.join("\n\n", warningMessages);
			}

			popup(buf);
		}
	}

	private Address doRun(Address address, Listing listing)
			throws AddressFormatException, DuplicateNameException, InvalidInputException {
		Address lastArrayAddress = address;
		Data data = listing.getDataAt(address);
		if (null != data) {
			DataType dt = data.getDataType();
			if (dt instanceof Array) {
				Array adt = (Array) dt;
				dt = adt.getDataType();
				cntConvertionTotal += adt.getNumElements();
				for (int i=0; i<adt.getNumElements(); ++i) {
					if (updateFunctionNamesFromStrings(dt, lastArrayAddress, listing)) {
						++cntConvertionChanged;
					};
					lastArrayAddress = lastArrayAddress.add(adt.getElementLength());
				}

			} else if (dt instanceof Structure) {
				++cntConvertionTotal;
				if (updateFunctionNamesFromStrings(dt, address, listing)) {
					++cntConvertionChanged;
				};
			}
		}
		return lastArrayAddress;
	}

	private boolean updateFunctionNamesFromStrings(DataType dt, Address address, Listing listing)
			throws AddressFormatException, DuplicateNameException, InvalidInputException {
		if (!(dt instanceof Structure)) return false;
		Structure structDt = (Structure) dt;

		if (!"DgnTaskFnList_t".equals(structDt.getName())) return false;

		Memory memory = currentProgram.getMemory();

		MemBuffer buf = new DumbMemBufferImpl(memory, address);
		DataTypeComponent comp = getComponent(structDt, 0, buf); // points to a string
		Address addrDatum = getRefAtPointer32(comp, address, buf);
		if (null == addrDatum) return false;

		Data dataString = listing.getDataAt(addrDatum);
		if (null == dataString) return false;
		String fnName = (String) dataString.getValue();

		buf = new DumbMemBufferImpl(memory, address.add(4));
		comp = getComponent(structDt, 1, buf); // points to a function pointer
		addrDatum = getRefAtPointer32(comp, address, buf);
		if (null == addrDatum) return false;
		Function func = listing.getFunctionAt(addrDatum);
		if (null == func) {
			func = createFunction(addrDatum, fnName);
			writer.println("Created functon '" + func.getName() + "' at " + addrDatum);
		}
		else {
			StringBuffer sb = new StringBuffer("Renamed function '" + func.getName() + "' to '");
			func.setName(fnName, SourceType.USER_DEFINED);
			sb.append(func.getName() + "' at " + addrDatum);
			writer.println(sb.toString());
		}
		return true;
	}

	private DataType getPointer32(DataTypeComponent comp, Address address, MemBuffer memBuf) {
		DataType dt = comp.getDataType();
		if (dt instanceof Union) {
			Union unionDt = (Union) dt;
			for (int i = 0; i < unionDt.getNumComponents(); i++) {
				comp = unionDt.getComponent(i);
				dt = comp.getDataType();
				if ((dt instanceof Pointer) && (4 == dt.getLength())) {
					return dt;
				}
				else if (dt instanceof Union || dt instanceof Structure) {
					dt = getPointer32(comp, address, memBuf);
				}
			}
		}
		else if (dt instanceof Structure) {
			Structure structDt = (Structure) dt;
			for (int i = 0; i < structDt.getNumComponents(); i++) {
				comp = structDt.getComponent(i);
				dt = comp.getDataType();
				if ((dt instanceof Pointer) && (4 == dt.getLength())) {
					return dt;
				}
				else if (dt instanceof Union || dt instanceof Structure) {
					dt = getPointer32(comp, address, memBuf);
				}
			}
		}
		else if ((dt instanceof Pointer) && (4 == dt.getLength())) {
			return dt;
		}
		return null;
	}

	private Address getRefAtPointer32(DataTypeComponent comp, Address address, MemBuffer memBuf) throws AddressFormatException {
		DataType dt = getPointer32(comp, address, memBuf);
		if (null == dt) return null;
		Object dataAddress = dt.getValue(memBuf, dt.getDefaultSettings(), dt.getLength());
		Address addrDatum = address.getAddress(dataAddress.toString());
		return addrDatum;
	}

	private static Address getComponentAddress(DataTypeComponent comp, MemBuffer memBuffer) {
		int offset = comp.getOffset();
		Address minAddress = memBuffer.getAddress();
		try {
			return minAddress.add(offset);
		}
		catch (AddressOutOfBoundsException e) {
			throw new IllegalArgumentException("Can't get component " + comp.getOrdinal() +
				" from memory buffer for data type " + comp.getParent().getName() + ".", e);
		}
	}

	private static DataTypeComponent getComponent(DataType dataType, int componentOrdinal,
			MemBuffer memBuffer) {
		if (dataType == null) {
			throw new IllegalArgumentException("Data type cannot be null.");
		}
		if (dataType instanceof DynamicDataType) {
			DynamicDataType dynamicDt = (DynamicDataType) dataType;
			return dynamicDt.getComponent(componentOrdinal, memBuffer);
		}
		if (dataType instanceof TypeDef) {
			dataType = ((TypeDef) dataType).getBaseDataType();
		}
		if (dataType instanceof Union) {
			Union unionDt = (Union) dataType;
			return unionDt.getComponent(componentOrdinal);
		}
		if (!(dataType instanceof Structure)) {
			throw new IllegalArgumentException("Data type " + dataType.getName() +
				" must be a structure or a typedef on a structure.");
		}
		Structure struct = (Structure) dataType;
		return struct.getComponent(componentOrdinal);
	}
}