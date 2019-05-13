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

public enum ClassFileFlags {

	/** Declared public; may be accessed from outside its package. */
	ACC_PUBLIC(0x0001),
	/** Declared final; no subclasses allowed. */
	ACC_FINAL(0x0010),
	/** Treat superclass methods specially when invoked by the invokespecial instruction. */
	ACC_SUPER(0x0020),
	/** Is an interface, not a class. */
	ACC_INTERFACE(0x0200),
	/** Declared abstract; must not be instantiated. */
	ACC_ABSTRACT(0x0400),
	/** Declared synthetic; not present in the source code. */
	ACC_SYNTHETIC(0x1000),
	/** Declared as an annotation type. */
	ACC_ANNOTATION(0x2000),
	/** Declared as an enum type. */
	ACC_ENUM(0x4000);

	private int value;

	private ClassFileFlags(int value) {
		this.value = value;
	}

	public int getValue() {
		return value;
	}

}
