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

final class FieldInfoAccessFlags {

	/** Declared public; may be accessed from outside its package. */
	public final short ACC_PUBLIC  = 0x0001;
	/** Declared private; usable only within the defining class. */
	public final short ACC_PRIVATE = 0x0002;
	/** Declared protected; may be accessed within subclasses. */
	public final short ACC_PROTECTED = 0x0004;
	/** Declared static. */
	public final short ACC_STATIC = 0x0008;
	/** Declared final; never directly assigned to after object construction (JLS ?17.5). */
	public final short ACC_FINAL = 0x0010;
	/** Declared volatile; cannot be cached. */
	public final short ACC_VOLATILE = 0x0040;
	/** Declared transient; not written or read by a persistent object manager. */
	public final short ACC_TRANSIENT = 0x0080;
	/** Declared synthetic; not present in the source code. */
	public final short ACC_SYNTHETIC = 0x1000;
	/** Declared as an element of an enum. */
	public final short ACC_ENUM = 0x4000;

}
