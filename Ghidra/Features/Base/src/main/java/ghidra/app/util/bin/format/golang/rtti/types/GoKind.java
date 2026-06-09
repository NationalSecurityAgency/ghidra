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
import java.util.EnumSet;
import java.util.Set;

/**
 * Enum defining the various Go primitive types
 */
public enum GoKind {
	invalid("invalid"),
	Bool("bool"),                     // 1
	Int("int"),                       // 2
	Int8("int8"),                     // 3
	Int16("int16"),                   // 4
	Int32("int32"),                   // 5
	Int64("int64"),                   // 6
	Uint("uint"),                     // 7
	Uint8("uint8"),                   // 8
	Uint16("uint16"),                 // 9
	Uint32("uint32"),                 // 10
	Uint64("uint64"),                 // 11
	Uintptr("uintptr"),               // 12
	Float32("float32"),               // 13
	Float64("float64"),               // 14
	Complex64("complex64"),           // 15
	Complex128("complex128"),         // 16
	Array("array"),                   // 17
	Chan("chan"),                     // 18
	Func("func()"),                   // 19
	Interface("interface"),           // 20
	Map("map"),                       // 21
	Pointer("pointer"),               // 22
	Slice("slice"),                   // 23
	String("string"),                 // 24
	Struct("struct"),                 // 25
	UnsafePointer("unsafe.Pointer");  // 26

	public static final int KIND_MASK = (1 << 5) - 1;
	public static final int GC_PROG = (1 << 6);
	public static final int DIRECT_IFACE = (1 << 5);

	private static final Set<GoKind> PRIMITIVE_KINDS =
		EnumSet.of(Bool, Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Uint64,
			Uintptr, Float32, Float64, Complex64, Complex128, Pointer, String, UnsafePointer);
	private static final GoKind[] ALLKINDS = values();

	/**
	 * Parses the byte value read from the runtime._type kind field.
	 * 
	 * @param b byte value
	 * @return {@link GoKind} enum, or {@link #invalid} if bad value
	 */
	public static GoKind parseByte(int b) {
		int ordinal = b & KIND_MASK;
		return Bool.ordinal() <= ordinal && ordinal <= UnsafePointer.ordinal()
				? values()[ordinal]
				: invalid;
	}

	public static GoKind parseTypename(String typeName) throws IOException {
		for (GoKind kind : ALLKINDS) {
			if (kind.typeName.equalsIgnoreCase(typeName)) {
				return kind;
			}
		}
		return invalid;
	}

	private final String typeName;

	private GoKind(String typeName) {
		this.typeName = typeName;
	}

	public String getTypeName() {
		return typeName;
	}

	public boolean isPrimitive() {
		return PRIMITIVE_KINDS.contains(this);
	}
}
