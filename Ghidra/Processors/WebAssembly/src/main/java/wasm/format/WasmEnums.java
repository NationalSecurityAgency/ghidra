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
package wasm.format;

import java.util.HashMap;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.Undefined8DataType;

public class WasmEnums {
	public enum WasmExternalKind {
		EXT_FUNCTION,
		EXT_TABLE,
		EXT_MEMORY,
		EXT_GLOBAL
	}

	public enum ValType {
		i32(0x7f),
		i64(0x7e),
		f32(0x7d),
		f64(0x7c),
		v128(0x7b),

		funcref(0x70),
		externref(0x6f);

		private static final HashMap<Integer, ValType> BY_BYTE = new HashMap<>();
		public static final DataType Undefined16 = Undefined.getUndefinedDataType(16);
		public final int typeByte;

		static {
			for (ValType t : ValType.values()) {
				BY_BYTE.put(t.typeByte, t);
			}
		}

		private ValType(int v) {
			this.typeByte = v;
		}

		public DataType asDataType() {
			switch (this) {
			case i32:
				return Undefined4DataType.dataType;
			case i64:
				return Undefined8DataType.dataType;
			case f32:
				return FloatDataType.dataType;
			case f64:
				return DoubleDataType.dataType;
			case v128:
				return Undefined16;
			case funcref:
				return PointerDataType.dataType;
			case externref:
				return Undefined4DataType.dataType;
			}
			return null;
		}

		public int getSize() {
			switch (this) {
			case i32:
			case f32:
			case funcref:
			case externref:
				return 4;
			case i64:
			case f64:
				return 8;
			case v128:
				return 16;
			}
			return 4;
		}

		public static ValType fromByte(int b) {
			return BY_BYTE.get(b);
		}

		public static ValType[] fromBytes(byte[] types) {
			ValType[] res = new ValType[types.length];
			for (int i = 0; i < types.length; i++) {
				res[i] = fromByte(types[i]);
			}
			return res;
		}
	}
}
