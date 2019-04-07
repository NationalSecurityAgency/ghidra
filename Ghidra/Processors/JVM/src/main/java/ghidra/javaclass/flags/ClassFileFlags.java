/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

public final class ClassFileFlags {

	/** Declared public; may be accessed from outside its package. */
	public final static short ACC_PUBLIC      = 0x0001;
	/** Declared final; no subclasses allowed. */
	public final static short ACC_FINAL       = 0x0010;
	/** Treat superclass methods specially when invoked by the invokespecial instruction. */
	public final static short ACC_SUPER       = 0x0020;
	/** Is an interface, not a class. */
	public final static short ACC_INTERFACE   = 0x0200; 
	/** Declared abstract; must not be instantiated. */
	public final static short ACC_ABSTRACT    = 0x0400;
	/** Declared synthetic; not present in the source code. */
	public final static short ACC_SYNTHETIC   = 0x1000;
	/** Declared as an annotation type. */
	public final static short ACC_ANNOTATION  = 0x2000;
	/** Declared as an enum type. */
	public final static short ACC_ENUM        = 0x4000;

}
