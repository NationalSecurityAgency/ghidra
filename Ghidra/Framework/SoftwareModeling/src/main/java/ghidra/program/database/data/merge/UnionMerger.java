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

import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Datatype merger for Unions
 */
public class UnionMerger extends DataTypeMerger<Union> {

	public UnionMerger(Union union1, Union union2) {
		super(union1, union2);
	}

	@Override
	public void doMerge() throws DataTypeMergeException {
		mergeDescription();

		DataTypeComponent[] components = other.getComponents();
		for (DataTypeComponent component : components) {
			if (component.getFieldName() != null) {
				processNamedComponent(component);
			}
			else {
				processUnnamedComponent(component);
			}
		}
	}

	private void processUnnamedComponent(DataTypeComponent component) {
		DataTypeComponent[] existingComps = working.getComponents();
		DataType dt = component.getDataType();
		if (!hasComponentWithDatatype(existingComps, dt)) {
			working.add(dt, component.getLength());
		}
	}

	private boolean hasComponentWithDatatype(DataTypeComponent[] existingComps, DataType dt) {
		for (DataTypeComponent component : existingComps) {
			if (component.getDataType().equals(dt)) {
				return true;
			}
		}
		return false;
	}

	private void processNamedComponent(DataTypeComponent component) throws DataTypeMergeException {
		DataTypeComponent[] resultComps = working.getComponents();

		DataTypeComponent resultComp = findByName(resultComps, component.getFieldName());
		if (resultComp != null) {
			applySameNamedComponent(resultComp, component);
			return;
		}

		resultComp = findUnnamedByType(resultComps, component.getDataType());
		if (resultComp != null) {
			appySameTypeComponent(resultComp, component);
		}
		working.add(component.getDataType(), component.getLength(), component.getFieldName(),
			component.getComment());
	}

	private void appySameTypeComponent(DataTypeComponent resultComp, DataTypeComponent component) {
		try {
			resultComp.setFieldName(component.getFieldName());
			resultComp.setComment(join(resultComp.getComment(), component.getComment()));
		}
		catch (DuplicateNameException e) {
			// can't happen, we already looked for a component with the same name
		}
	}

	private void applySameNamedComponent(DataTypeComponent comp1, DataTypeComponent comp2)
			throws DataTypeMergeException {
		DataType dt1 = comp1.getDataType();
		DataType dt2 = comp2.getDataType();
		if (dt1.equals(dt2)) {
			comp1.setComment(join(comp1.getComment(), comp2.getComment()));
			return;
		}

		DataType mergedDt = pickBestTypeForMerge(dt1, dt2);

		if (mergedDt != null && comp2.getLength() == comp1.getLength()) {
			int ordinal = comp1.getOrdinal();
			working.delete(ordinal);
			String comment = join(comp1.getComment(), comp2.getComment());
			working.insert(ordinal, mergedDt, comp2.getLength(), comp2.getFieldName(), comment);
			warning("Merging '%s' and '%s' to '%s' for member '%s'.".formatted(dt1.getName(),
				dt2.getName(), mergedDt.getName(), comp1.getFieldName()));
			return;
		}
		error("Unions have conflicting components named " + comp1.getFieldName());
	}

	private DataTypeComponent findByName(DataTypeComponent[] components, String name) {
		for (DataTypeComponent component : components) {
			if (name.equals(component.getFieldName())) {
				return component;
			}
		}
		return null;
	}

	private DataTypeComponent findUnnamedByType(DataTypeComponent[] components,
			DataType dataType) {
		for (DataTypeComponent component : components) {
			if (component.getFieldName() == null && component.getDataType().equals(dataType)) {
				return component;
			}
		}
		return null;
	}
}
