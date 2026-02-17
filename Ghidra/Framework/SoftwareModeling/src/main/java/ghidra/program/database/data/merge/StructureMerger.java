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
package ghidra.program.database.data.merge;

import java.util.List;

import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * DataType merger for structures.
 */
public class StructureMerger extends DataTypeMerger<Structure> {

	public StructureMerger(Structure struct1, Structure struct2) {
		super(struct1, struct2);
	}

	@Override
	public void doMerge() throws DataTypeMergeException {
		checkSizes();
		mergeDescription();

		if (working.isPackingEnabled()) {
			mergePacked();
		}
		else {
			mergeUnpacked();
		}
	}

	private void checkSizes() {
		int resultLength = working.getLength();
		int otherLength = other.getLength();
		if (resultLength != otherLength) {
			warning("Structures are not the same size.");
		}
		if (resultLength < otherLength) {
			working.growStructure(otherLength - resultLength);
		}
	}

	private void mergeUnpacked() throws DataTypeMergeException {
		if (other.isPackingEnabled()) {
			warning("Merging packed structure into an unpacked structure.");
		}
		DataTypeComponent[] otherComponents = other.getDefinedComponents();

		for (DataTypeComponent comp : otherComponents) {
			DataTypeComponent workingComp = findCorrespondingResultComponent(comp);
			if (workingComp != null) {
				processFieldNames(workingComp, comp);
				processComments(workingComp, comp);
			}
			else {
				copyCompToWorking(comp);
			}
		}
	}

	private void copyCompToWorking(DataTypeComponent comp) throws DataTypeMergeException {
		int offset = comp.getOffset();
		int length = comp.getLength();

		DataTypeComponent workingComp = working.getComponentAt(offset);
		if (workingComp != null && workingComp.getDataType() != DataType.DEFAULT) {
			// datatypes are different or else we would have handled in calling method
			// so we can either merge them or we will throw an error
			tryMergingDataTypes(workingComp, comp);
		}
		else if (hasUndefinedSpace(offset, length)) {
			DataType dt = comp.getDataType();
			String name = comp.getFieldName();
			String comment = comp.getComment();
			working.replaceAtOffset(offset, dt, dt.getLength(), name, comment);
		}
		else if (working.getComponentAt(offset) == null) {
			error("Conflict at offset " + offset + ". Existing component extends to this offset.");
		}
		else {
			error("Conflict at offset " + offset + ". Not enough undefined bytes to insert here.");
		}
	}

	private void tryMergingDataTypes(DataTypeComponent workingComp, DataTypeComponent comp)
			throws DataTypeMergeException {
		DataType workingDt = workingComp.getDataType();
		DataType otherDt = comp.getDataType();

		DataType mergedDt = pickBestTypeForMerge(workingDt, otherDt);
		if (mergedDt == null) {
			error("Conflict at offset " + comp.getOffset() +
				". Incompatible datatype already defined here.");
		}
		int offset = workingComp.getOffset();
		warning("Merging '%s' and '%s' at offset %d to '%s'.".formatted(workingDt.getName(),
			otherDt.getName(), offset, mergedDt.getName()));

		processFieldNames(workingComp, comp);  	// checks for conflicts and handles null field names
		String name = workingComp.getFieldName();
		String comment = join(workingComp.getComment(), comp.getComment());
		int length = workingComp.getLength();
		working.replaceAtOffset(offset, mergedDt, length, name, comment);
	}

	private boolean hasUndefinedSpace(int offset, int length) {
		for (int i = 0; i < length; i++) {
			DataTypeComponent componentAt = working.getComponentAt(offset + i);
			if (componentAt == null || componentAt.getDataType() != DataType.DEFAULT) {
				return false;
			}
		}
		return true;
	}

	private DataTypeComponent findCorrespondingResultComponent(DataTypeComponent comp) {
		int offset = comp.getOffset();
		List<DataTypeComponent> otherComps = other.getComponentsContaining(offset);
		List<DataTypeComponent> workingComps = working.getComponentsContaining(offset);

		if (workingComps.isEmpty()) {
			return null;
		}

		if (workingComps.get(0).getDataType() == DataType.DEFAULT) {
			return null;
		}

		if (otherComps.size() == workingComps.size()) {
			int index = otherComps.indexOf(comp);
			DataTypeComponent workingComp = workingComps.get(index);
			if (isSameComponent(comp, workingComp)) {
				return workingComp;
			}
		}
		return null;
	}

	private boolean isSameComponent(DataTypeComponent comp, DataTypeComponent workingComp) {
		if (comp.getOffset() != workingComp.getOffset()) {
			return false;
		}
		if (!comp.getDataType().equals(workingComp.getDataType())) {
			return false;
		}
		return true;
	}

	private void mergePacked() throws DataTypeMergeException {
		// merging packed is much more restricted. The only thing we are merging are defined
		// field names against undefined field names and field comments. All component
		// datatypes must match exactly.

		if (!working.isPackingEnabled()) {
			error("Can't merge an unpacked structure into a packed structure");
		}

		DataTypeComponent[] otherComps = other.getComponents();
		DataTypeComponent[] workingComps = working.getComponents();
		if (otherComps.length != workingComps.length) {
			error("Packed structures must have same size.");
		}
		for (int i = 0; i < otherComps.length; i++) {
			DataTypeComponent fromComp = otherComps[i];
			DataTypeComponent workingComp = workingComps[i];
			checkDataType(workingComp, fromComp);
			checkOffsets(workingComp, fromComp);
			processFieldNames(workingComp, fromComp);
			processComments(workingComp, fromComp);
		}
	}

	private void checkDataType(DataTypeComponent workingComp, DataTypeComponent comp)
			throws DataTypeMergeException {

		DataType resultDt = workingComp.getDataType();
		DataType dt = comp.getDataType();
		if (!resultDt.equals(dt)) {
			error("Packed components have conflicting datatypes at ordinal" +
				workingComp.getOrdinal() + ", offset " + comp.getOffset());
		}
	}

	private void checkOffsets(DataTypeComponent comp1, DataTypeComponent comp2)
			throws DataTypeMergeException {
		int offset1 = comp1.getOffset();
		int offset2 = comp2.getOffset();
		if (offset1 != offset2) {
			error("Packed components have different offsets at ordinal " + comp1.getOrdinal() +
				"struct1 = " + offset1 + ", struct2 = " + offset2);
		}
	}

	private void processFieldNames(DataTypeComponent workingComp, DataTypeComponent otherComp)
			throws DataTypeMergeException {
		String workingName = workingComp.getFieldName();
		String otherName = otherComp.getFieldName();
		if (workingName != null & otherName != null && !workingName.equals(otherName)) {
			error(
				"Components have conflicting field names at ordinal %d, offset %d. Names: %s vs %s"
						.formatted(workingComp.getOrdinal(), workingComp.getOffset(), workingName,
							otherName));
		}
		if (workingName == null && otherName != null) {
			try {
				workingComp.setFieldName(otherName);
			}
			catch (DuplicateNameException e) {
				// This exception is going away soon, so ignore it for now
			}
		}
	}

	private void processComments(DataTypeComponent workingComp, DataTypeComponent otherComp) {
		String resultComment = workingComp.getComment();
		String otherComment = otherComp.getComment();
		workingComp.setComment(join(resultComment, otherComment));
	}

}
