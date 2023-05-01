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

import java.util.*;

import java.io.IOException;

import ghidra.app.util.bin.format.dwarf4.DWARFUtil;
import ghidra.app.util.bin.format.golang.rtti.GoName;
import ghidra.app.util.bin.format.golang.rtti.GoSlice;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.data.*;
import ghidra.util.Msg;

@StructureMapping(structureName = "runtime.structtype")
public class GoStructType extends GoType {

	@FieldMapping
	@MarkupReference
	private long pkgPath;	// name

	@FieldMapping
	private GoSlice fields;

	public GoStructType() {
	}

	@Markup
	public GoName getPkgPath() throws IOException {
		return programContext.getGoName(pkgPath);
	}

	public String getPkgPathString() throws IOException {
		GoName n = getPkgPath();
		return n != null ? n.getName() : "";
	}

	public List<GoStructField> getFields() throws IOException {
		return fields.readList(GoStructField.class);
	}

	@Override
	public void additionalMarkup() throws IOException {
		super.additionalMarkup();
		fields.markupArray(getStructureLabel() + "_fields", GoStructField.class, false);
		fields.markupArrayElements(GoStructField.class);
	}

	@Override
	public String getTypeDeclString() throws IOException {
		String methodListStr = getMethodListString();
		if (methodListStr == null || methodListStr.isEmpty()) {
			methodListStr = "// No methods";
		}
		else {
			methodListStr = "// Methods\n" + methodListStr;
		}

		return """
				// size: %d
				type %s struct {
				%s
				%s
				}
				""".formatted(
			typ.getSize(),
			typ.getNameString(),
			getFieldListString().indent(2),
			methodListStr.indent(2));
	}

	private String getFieldListString() throws IOException {
		StringBuilder sb = new StringBuilder();
		for (GoStructField field : getFields()) {
			if (!sb.isEmpty()) {
				sb.append("\n");
			}
			long offset = field.getOffset();
			long fieldSize = field.getType().getBaseType().getSize();
			sb.append("%s %s // %d..%d".formatted(field.getNameString(),
				field.getType().getBaseType().getNameString(), offset, offset + fieldSize));
		}
		return sb.toString();
	}

	@Override
	public DataType recoverDataType() throws IOException {
		StructureDataType struct = new StructureDataType(programContext.getRecoveredTypesCp(),
			typ.getNameString(), (int) typ.getSize(), programContext.getDTM());
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
					field.getNameString(), null);
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
				comment += "Omitted zero-len field: %s=%s".formatted(skippedField.getNameString(),
					skippedFieldType.getBaseType().getNameString());
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
