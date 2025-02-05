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
package ghidra.pcode.emu.jit.gen;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;

/**
 * An instance field request initialized in the class constructor
 */
public interface InstanceFieldReq extends FieldReq {
	/**
	 * Emit the field declaration and its initialization bytecode
	 * 
	 * <p>
	 * The declaration is emitted into the class definition, and the initialization code is emitted
	 * into the class constructor.
	 * 
	 * @param gen the code generator
	 * @param cv the visitor for the class definition
	 * @param iv the visitor for the class constructor
	 */
	void generateInitCode(JitCodeGenerator gen, ClassVisitor cv, MethodVisitor iv);
}
