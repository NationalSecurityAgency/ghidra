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
package ghidra.app.util.bin.format.golang.rtti.types;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.format.dwarf4.DWARFUtil;
import ghidra.app.util.bin.format.golang.rtti.GoName;
import ghidra.app.util.bin.format.golang.rtti.GoSlice;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * Golang type information about a specific structure type.
 */
@StructureMapping(structureName = "runtime.structtype")
public class GoStructType extends GoType {

	@FieldMapping
	@MarkupReference
	private long pkgPath;	// name

	@FieldMapping
	private GoSlice fields;

	public GoStructType() {
		// empty
	}

	/**
	 * Returns the package path of this structure type.
	 * 
	 * @return package path of this structure type
	 * @throws IOException if error reading
	 */
	@Markup
	public GoName getPkgPath() throws IOException {
		return programContext.getGoName(pkgPath);
	}

	/**
	 * Returns the package path of this structure type
	 *  
	 * @return package path of this structure type, as a string
	 */
	@Override
	public String getPackagePathString() {
		String s = super.getPackagePathString(); // from uncommontype
		if (s == null || s.isEmpty()) {
			try {
				GoName structPP = getPkgPath();
				if (structPP != null) {
					s = structPP.getName();
				}
			}
			catch (IOException e) {
				// fall thru, return existing s
			}
		}
		return s;
	}

	/**
	 * Returns the fields defined by this struct type.
	 * 
	 * @return list of fields defined by this struct type
	 * @throws IOException if error reading
	 */
	public List<GoStructField> getFields() throws IOException {
		return fields.readList(GoStructField.class);
	}

	@Override
	public long getEndOfTypeInfo() throws IOException {
		return fields.getArrayEnd(GoStructField.class);
	}

	@Override
	public void additionalMarkup(MarkupSession session) throws IOException, CancelledException {
		super.additionalMarkup(session);
		fields.markupArray(getStructureLabel() + "_fields", getStructureNamespace(),
			GoStructField.class, false, session);
		fields.markupArrayElements(GoStructField.class, session);
	}

	@Override
	public String getTypeDeclString() throws IOException {

		String pps = getPackagePathString();
		if (pps == null || pps.isEmpty()) {
			pps = "<None>";
		}

		return """
				// size: %d
				// package: %s
				type %s struct {
				%s}""".formatted(
			typ.getSize(),
			pps,
			typ.getName(),
			getFieldListString().indent(2));
	}

	private String getFieldListString() throws IOException {
		StringBuilder sb = new StringBuilder();
		for (GoStructField field : getFields()) {
			if (!sb.isEmpty()) {
				sb.append("\n");
			}
			long offset = field.getOffset();
			long fieldSize = field.getType().getBaseType().getSize();
			sb.append("%s %s // %d..%d".formatted(field.getName(),
				field.getType().getName(), offset, offset + fieldSize));
		}
		return sb.toString();
	}

	@Override
	public DataType recoverDataType() throws IOException {
		StructureDataType struct =
			new StructureDataType(programContext.getRecoveredTypesCp(getPackagePathString()),
				getUniqueTypename(), (int) typ.getSize(), programContext.getDTM());

		// pre-push an empty struct into the cache to prevent endless recursive loops
		programContext.cacheRecoveredDataType(this, struct);

		List<GoStructField> skippedFields = new ArrayList<>();
		List<GoStructField> fieldList = getFields();
		for (int i = 0; i < fieldList.size(); i++) {
			GoStructField field = fieldList.get(i);
			GoStructField nextField = i < fieldList.size() - 1 ? fieldList.get(i + 1) : null;
			long availSpace = nextField != null
					? nextField.getOffset() - field.getOffset()
					: typ.getSize() - field.getOffset();

			GoType fieldType = field.getType();
			long fieldSize = fieldType.getBaseType().getSize();

			if (fieldSize == 0) {
				skippedFields.add(field);
				continue;
			}

			try {
				DataType fieldDT = programContext.getRecoveredType(fieldType);
				struct.replaceAtOffset((int) field.getOffset(), fieldDT, (int) fieldSize,
					field.getName(), null);
			}
			catch (IllegalArgumentException e) {
				Msg.warn(this,
					"Failed to add field to go recovered struct: %s".formatted(getDebugId()), e);
			}
		}
		for (GoStructField skippedField : skippedFields) {
			DataTypeComponent dtc =
				struct.getDefinedComponentAtOrAfterOffset((int) skippedField.getOffset());
			GoType skippedFieldType = skippedField.getType();
			if (dtc != null) {
				String comment = dtc.getComment();
				comment = comment == null ? "" : (comment + "\n");
				comment += "Omitted zero-len field: %s=%s".formatted(skippedField.getName(),
					skippedFieldType.getName());
				dtc.setComment(comment);
			}
		}

		DWARFUtil.packCompositeIfPossible(struct, programContext.getDTM());
		return struct;
	}

	@Override
	public boolean discoverGoTypes(Set<Long> discoveredTypes) throws IOException {
		if (!super.discoverGoTypes(discoveredTypes)) {
			return false;
		}
		for (GoStructField field : getFields()) {
			field.getType().discoverGoTypes(discoveredTypes);
		}
		return true;
	}

}
