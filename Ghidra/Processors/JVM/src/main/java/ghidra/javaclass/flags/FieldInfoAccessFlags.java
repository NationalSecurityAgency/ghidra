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
package ghidra.javaclass.flags;

public enum FieldInfoAccessFlags {
	/** Declared public; may be accessed from outside its package. */
	ACC_PUBLIC(0x0001),
	/** Declared private; usable only within the defining class. */
	ACC_PRIVATE(0x0002),
	/** Declared protected; may be accessed within subclasses. */
	ACC_PROTECTED(0x0004),
	/** Declared static. */
	ACC_STATIC(0x0008),
	/** Declared final; never directly assigned to after object construction (JLS ?17.5). */
	ACC_FINAL(0x0010),
	/** Declared volatile; cannot be cached. */
	ACC_VOLATILE(0x00400),
	/** Declared transient; not written or read by a persistent object manager. */
	ACC_TRANSIENT(0x0080),
	/** Declared synthetic; not present in the source code. */
	ACC_SYNTHETIC(0x1000),
	/** Declared as an element of an enum. */
	ACC_ENUM(0x4000);

	private int value;

	private FieldInfoAccessFlags(int value) {
		this.value = value;
	}

	public int getValue() {
		return value;
	}
}
