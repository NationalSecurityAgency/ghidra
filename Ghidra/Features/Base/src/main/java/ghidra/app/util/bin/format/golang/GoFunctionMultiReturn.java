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
package ghidra.app.util.bin.format.golang;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.bin.format.dwarf4.next.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataTypeConflictHandler.ConflictResult;
import ghidra.program.model.lang.Register;

/**
 * Handles creating a Ghidra structure to represent multiple return values returned from a golang
 * function.
 * <p>
 * Assigning custom storage for the return value is complicated by:
 * <ul>
 *  <li>golang storage allocations depend on the formal ordering of the return values
 * 	<li>stack storage must be last in a list of varnodes
 * 	<li>the decompiler maps a structure's contents to the list of varnodes in an endian-dependent
 * 	manner.
 * </ul>
 * To meet these complications, the structure's layout is modified to put all items that were
 * marked as being stack parameters to either the front or back of the structure.
 * <p>
 * To allow this artificial structure to adjusted by the user and reused at some later time
 * to re-calculate the correct storage, the items in the structure are tagged with the original
 * ordinal of that item as a text comment of each structure field, so that the correct ordering
 * of items can be re-created when needed.
 * <p>
 * If the structure layout is modified to conform to an arch's requirements, the structure's
 * name will be modified to include that arch's description at the end (eg. "_x86_64") 
 */
public class GoFunctionMultiReturn {
	public static final String MULTIVALUE_RETURNTYPE_SUFFIX = "_multivalue_return_type";
	private static final String ORDINAL_PREFIX = "ordinal: ";

	// match a substring that is "ordinal: NN", marking the number portion as group 1
	private static final Pattern ORDINAL_REGEX =
		Pattern.compile(".*" + ORDINAL_PREFIX + "([\\d]+)[^\\d]*");

	public static boolean isMultiReturnDataType(DataType dt) {
		return dt instanceof Structure && dt.getName().endsWith(MULTIVALUE_RETURNTYPE_SUFFIX);
	}

	public static GoFunctionMultiReturn fromStructure(DataType dt, DataTypeManager dtm,
			GoParamStorageAllocator storageAllocator) {
		return isMultiReturnDataType(dt)
				? new GoFunctionMultiReturn((Structure) dt, dtm, storageAllocator)
				: null;
	}

	private Structure struct;
	private List<DataTypeComponent> normalStorageComponents = new ArrayList<>();
	private List<DataTypeComponent> stackStorageComponents = new ArrayList<>();

	public GoFunctionMultiReturn(List<DWARFVariable> returnParams, DWARFFunction dfunc,
			DataTypeManager dtm, GoParamStorageAllocator storageAllocator) {

		Structure newStruct = mkStruct(dfunc.name.getParentCP(), dfunc.name.getName(), dtm);
		int ordinalNum = 0;
		for (DWARFVariable dvar : returnParams) {
			newStruct.add(dvar.type, dvar.name.getName(), ORDINAL_PREFIX + ordinalNum);
			ordinalNum++;
		}
		
		regenerateMultireturnStruct(newStruct, dtm, storageAllocator);
	}

	public GoFunctionMultiReturn(CategoryPath categoryPath, String funcName, List<DataType> types,
			DataTypeManager dtm, GoParamStorageAllocator storageAllocator) {

		Structure newStruct = mkStruct(categoryPath, funcName, dtm);
		int ordinalNum = 0;
		for (DataType dt : types) {
			newStruct.add(dt, "~r%d".formatted(ordinalNum), ORDINAL_PREFIX + ordinalNum);
			ordinalNum++;
		}

		regenerateMultireturnStruct(newStruct, dtm, storageAllocator);
	}

	private static Structure mkStruct(CategoryPath cp, String baseName, DataTypeManager dtm) {
		String structName = baseName + MULTIVALUE_RETURNTYPE_SUFFIX;
		Structure newStruct = new StructureDataType(cp, structName, 0, dtm);
		newStruct.setPackingEnabled(true);
		newStruct.setExplicitPackingValue(1);
		newStruct.setDescription("Artificial data type to hold a function's return values");
		return newStruct;
	}

	public GoFunctionMultiReturn(Structure struct, DataTypeManager dtm,
			GoParamStorageAllocator storageAllocator) {
		regenerateMultireturnStruct(struct, dtm, storageAllocator);
	}

	public Structure getStruct() {
		return struct;
	}

	public List<DataTypeComponent> getNormalStorageComponents() {
		return normalStorageComponents;
	}

	public List<DataTypeComponent> getStackStorageComponents() {
		return stackStorageComponents;
	}

	private record StackComponentInfo(DataTypeComponent dtc, int ordinal, String comment) {}

	private void regenerateMultireturnStruct(Structure struct, DataTypeManager dtm,
			GoParamStorageAllocator storageAllocator) {
		if (storageAllocator == null) {
			this.struct = struct;
			for (DataTypeComponent dtc : getComponentsInOriginalOrder(struct)) {
				stackStorageComponents.add(dtc);
			}
			return;
		}

		Structure adjustedStruct =
			new StructureDataType(
				struct.getCategoryPath(), getBasename(struct.getName()) +
					MULTIVALUE_RETURNTYPE_SUFFIX + "_" + storageAllocator.getArchDescription(),
				0, dtm);
		adjustedStruct.setPackingEnabled(true);
		adjustedStruct.setExplicitPackingValue(1);

		storageAllocator = storageAllocator.clone();
		List<StackComponentInfo> stackResults = new ArrayList<>();
		int compNum = 0;
		for (DataTypeComponent dtc : getComponentsInOriginalOrder(struct)) {
			List<Register> regs = storageAllocator.getRegistersFor(dtc.getDataType());
			if (regs == null || regs.isEmpty()) {
				long stackOffset = storageAllocator.getStackAllocation(dtc.getDataType());
				String comment = "stack[%d] %s%d".formatted(stackOffset, ORDINAL_PREFIX, compNum);
				stackResults.add(new StackComponentInfo(dtc, compNum, comment));
			}
			else {
				String comment = "%s %s%d".formatted(regs, ORDINAL_PREFIX, compNum);
				DataTypeComponent newDTC =
					adjustedStruct.add(dtc.getDataType(), dtc.getFieldName(), comment);
				normalStorageComponents.add(newDTC);
			}
			compNum++;
		}

		// add the stack items to the struct last or first, depending on endianness
		for (int i = 0; i < stackResults.size(); i++) {
			StackComponentInfo sci = stackResults.get(i);
			DataTypeComponent dtc = sci.dtc;
			DataTypeComponent newDTC;
			if (storageAllocator.isBigEndian()) {
				newDTC = adjustedStruct.add(dtc.getDataType(), dtc.getFieldName(), sci.comment);
			}
			else {
				newDTC =
					adjustedStruct.insert(i, dtc.getDataType(), -1, dtc.getFieldName(),
						sci.comment);
			}
			stackStorageComponents.add(newDTC);
		}
		
		boolean isEquiv = DWARFDataTypeConflictHandler.INSTANCE.resolveConflict(adjustedStruct,
			struct) == ConflictResult.USE_EXISTING;
		this.struct = isEquiv ? struct : adjustedStruct;
	}

	private static String getBasename(String structName) {
		int i = structName.indexOf(MULTIVALUE_RETURNTYPE_SUFFIX);
		return i > 0 ? structName.substring(0, i) : structName;
	}

	private static int getOrdinalNumber(DataTypeComponent dtc) {
		String comment = Objects.requireNonNullElse(dtc.getComment(), "");
		Matcher m = ORDINAL_REGEX.matcher(comment);
		try {
			return m.matches() ? Integer.parseInt(m.group(1)) : -1;
		}
		catch (NumberFormatException nfe) {
			return -1;
		}
	}

	private static List<DataTypeComponent> getComponentsInOriginalOrder(Structure struct) {
		List<DataTypeComponent> dtcs = new ArrayList<>(List.of(struct.getDefinedComponents()));
		Collections.sort(dtcs,
			(dtc1, dtc2) -> Integer.compare(getOrdinalNumber(dtc1), getOrdinalNumber(dtc2)));
		return dtcs;
	}

}
