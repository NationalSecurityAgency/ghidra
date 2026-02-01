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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import ghidra.app.util.bin.format.dwarf.DWARFDataTypeConflictHandler;
import ghidra.app.util.bin.format.dwarf.DWARFFunction;
import ghidra.app.util.bin.format.dwarf.DWARFVariable;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataTypeConflictHandler.ConflictResult;
import ghidra.program.model.lang.Register;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

/**
 * Handles creating a Ghidra structure to represent multiple return values returned from a golang
 * function.
 * <p>
 * Assigning custom storage for the return value is complicated by:
 * <ul>
 *  <li>golang storage allocations depend on the formal ordering of the return values</li>
 * 	<li>stack storage must be last in a list of varnodes</li>
 * 	<li>the decompiler maps a structure's contents to the list of varnodes in an endian-dependent
 * 	manner.</li>
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
	public static final String SHORT_MULTIVALUE_RETURNTYPE_PREFIX = "multireturn{";
	public static final String SHORT_MULTIVALUE_RETURNTYPE_SUFFIX = "}";
	private static final String ORDINAL_PREFIX = "ordinal: ";
	private static final String TMP_NAME = "--TEMP_NAME_REPLACE_ASAP--";

	// match a substring that is "ordinal: NN", marking the number portion as group 1
	private static final Pattern ORDINAL_REGEX =
		Pattern.compile(".*" + ORDINAL_PREFIX + "([\\d]+)[^\\d]*");

	public static boolean isMultiReturnDataType(DataType dt) {
		return dt instanceof Structure && (dt.getName().endsWith(MULTIVALUE_RETURNTYPE_SUFFIX) ||
			dt.getName().startsWith(SHORT_MULTIVALUE_RETURNTYPE_PREFIX));
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

	public GoFunctionMultiReturn(CategoryPath categoryPath, List<DWARFVariable> returnParams,
			DWARFFunction dfunc, DataTypeManager dtm, GoParamStorageAllocator storageAllocator) {

		Structure newStruct = mkStruct(categoryPath, dtm);
		int ordinalNum = 0;
		for (DWARFVariable dvar : returnParams) {
			newStruct.add(dvar.type, dvar.name.getName(), ORDINAL_PREFIX + ordinalNum);
			ordinalNum++;
		}

		regenerateMultireturnStruct(newStruct, dtm, storageAllocator);
	}

	public GoFunctionMultiReturn(CategoryPath categoryPath, List<DataType> types,
			DataTypeManager dtm, GoParamStorageAllocator storageAllocator) {

		Structure newStruct = mkStruct(categoryPath, dtm);
		int ordinalNum = 0;
		for (DataType dt : types) {
			newStruct.add(dt, "~r%d".formatted(ordinalNum), ORDINAL_PREFIX + ordinalNum);
			ordinalNum++;
		}

		regenerateMultireturnStruct(newStruct, dtm, storageAllocator);
	}

	public GoFunctionMultiReturn(CategoryPath categoryPath, ParameterDefinition[] returnParams,
			DataTypeManager dtm, GoParamStorageAllocator storageAllocator) {

		Structure newStruct = mkStruct(categoryPath, dtm);
		int ordinalNum = 0;
		for (ParameterDefinition pd : returnParams) {
			String retParamName = pd.getName() != null && !pd.getName().isBlank() ? pd.getName()
					: "~r%d".formatted(ordinalNum);
			newStruct.add(pd.getDataType(), retParamName, ORDINAL_PREFIX + ordinalNum);
			ordinalNum++;
		}

		regenerateMultireturnStruct(newStruct, dtm, storageAllocator);
	}

	private Structure mkStruct(CategoryPath cp, DataTypeManager dtm) {
		Structure newStruct = new StructureDataType(cp, TMP_NAME, 0, dtm);
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

	public List<DataTypeComponent> getComponentsInOriginalOrder() {
		return getComponentsInOriginalOrder(struct);
	}

	private record StackComponentInfo(DataTypeComponent dtc, int ordinal, String comment) {}

	private void regenerateMultireturnStruct(Structure newStruct, DataTypeManager dtm,
			GoParamStorageAllocator storageAllocator) {

		String name = getComponentsInOriginalOrder(newStruct).stream()
				.map(dtc -> dtc.getDataType().getName())
				.collect(Collectors.joining(";", SHORT_MULTIVALUE_RETURNTYPE_PREFIX,
					SHORT_MULTIVALUE_RETURNTYPE_SUFFIX));

		if (newStruct.getName().equals(TMP_NAME)) {
			try {
				newStruct.setName(name);
			}
			catch (InvalidNameException | DuplicateNameException e) {
				// should not happen
			}
		}

		if (storageAllocator == null) {
			this.struct = newStruct;
			for (DataTypeComponent dtc : getComponentsInOriginalOrder(newStruct)) {
				stackStorageComponents.add(dtc);
			}
			return;
		}


		Structure adjustedStruct = new StructureDataType(newStruct.getCategoryPath(),
			name + "_" + storageAllocator.getArchDescription(), 0, dtm);
		adjustedStruct.setPackingEnabled(true);
		adjustedStruct.setExplicitPackingValue(1);

		storageAllocator = storageAllocator.clone();
		List<StackComponentInfo> stackResults = new ArrayList<>();
		int compNum = 0;
		for (DataTypeComponent dtc : getComponentsInOriginalOrder(newStruct)) {
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

		// add the stack items to the struct first (LE) or last (BE), depending on endianness
		for (int i = 0; i < stackResults.size(); i++) {
			StackComponentInfo sci = stackResults.get(i);
			DataTypeComponent dtc = sci.dtc;
			DataTypeComponent newDTC = storageAllocator.isBigEndian()
					? adjustedStruct.add(dtc.getDataType(), dtc.getFieldName(), sci.comment)
					: adjustedStruct.insert(i, dtc.getDataType(), -1, dtc.getFieldName(),
						sci.comment);
			stackStorageComponents.add(newDTC);
		}

		boolean isEquiv = DWARFDataTypeConflictHandler.INSTANCE.resolveConflict(adjustedStruct,
			newStruct) == ConflictResult.USE_EXISTING;
		this.struct = isEquiv ? newStruct : adjustedStruct;
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
