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
import java.util.Set;

import ghidra.app.util.bin.format.golang.rtti.GoTypeManager;
import ghidra.app.util.bin.format.golang.structmapping.StructureMapping;
import ghidra.app.util.bin.format.golang.structmapping.StructureReader;
import ghidra.program.model.data.*;
import ghidra.util.Msg;

/**
 * WARNING: tricky code / class layout here!
 * <p>
 * To coerce java inheritance and structmapping features to match the layout of Go rtti type structs,
 * this class is constructed strangely.
 * <p>
 * {@link GoType} structure that defines a built-in primitive type.
 */
@StructureMapping(structureName = {"runtime._type", "internal/abi.Type"})
public class GoPlainType extends GoType implements StructureReader<GoType> {
	@Override
	public void readStructure() throws IOException {
		this.typ = context.getDataTypeMapper().readStructure(GoBaseType.class, context.getReader());
	}

	@Override
	public DataType recoverDataType() throws IOException {
		GoTypeManager goTypes = programContext.getGoTypes();
		DataType dt = goTypes.recoverPlainDataType(typ.getKind());
		if (dt == null) {
			dt = super.recoverDataType();
		}

		String name = goTypes.getTypeName(this);
		if (!dt.getName().equalsIgnoreCase(name)) {
			DataTypeManager dtm = goTypes.getDTM();
			dt = new TypedefDataType(goTypes.getCP(this), name, dt, dtm);
		}
		if (dt.getLength() != typ.getSize()) {
			Msg.warn(this,
				"Recovered Go data type size mismatch: %s, %d != %d".formatted(getDebugId(),
					typ.getSize(), dt.getLength()));
		}
		return dt;
	}

	@Override
	public boolean discoverGoTypes(Set<Long> discoveredTypes) throws IOException {
		return super.discoverGoTypes(discoveredTypes);
	}

	@Override
	public boolean isValid() {
		return super.isValid() && switch (typ.getKind()) {
			case Bool -> typ.getSize() == 1;
			case Float32 -> typ.getSize() == 4;
			case Float64 -> typ.getSize() == 8;
			case Uint, Int -> typ.getSize() == programContext.getPtrSize();
			case Uint8, Int8 -> typ.getSize() == 1;
			case Uint16, Int16 -> typ.getSize() == 2;
			case Uint32, Int32 -> typ.getSize() == 4;
			case Uint64, Int64 -> typ.getSize() == 8;
			case Uintptr -> typ.getSize() == programContext.getPtrSize();
			case String -> typ.getSize() == programContext.getPtrSize() * 2;
			case UnsafePointer -> typ.getSize() == programContext.getPtrSize();
			default -> true;
		};
	}

}
