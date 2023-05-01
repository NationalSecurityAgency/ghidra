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

public enum GoKind {
	invalid,
	Bool,                   // 1
	Int,                    // 2
	Int8,                   // 3
	Int16,                  // 4
	Int32,                  // 5
	Int64,                  // 6
	Uint,                   // 7
	Uint8,                  // 8
	Uint16,                 // 9
	Uint32,                 // 10
	Uint64,                 // 11
	Uintptr,                // 12
	Float32,                // 13
	Float64,                // 14
	Complex64,              // 15
	Complex128,             // 16
	Array,                  // 17
	Chan,                   // 18
	Func,                   // 19
	Interface,              // 20
	Map,                    // 21
	Pointer,                // 22
	Slice,                  // 23
	String,                 // 24
	Struct,                 // 25
	UnsafePointer;          // 26

	public static final int KIND_MASK = (1 << 5) - 1;
	public static final int GC_PROG = (1 << 6);
	public static final int DIRECT_IFACE = (1 << 5);

	public static GoKind parseByte(int b) {
		int ordinal = b & KIND_MASK;
		return Bool.ordinal() <= ordinal && ordinal <= UnsafePointer.ordinal()
				? values()[ordinal]
				: invalid;
	}
}
