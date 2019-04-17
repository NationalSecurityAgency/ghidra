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
package ghidra.program.model.data;

import ghidra.util.classfinder.ClassTranslator;

/**
 * Pointer16 is really a factory for generating 6-byte pointers.
 */
public class Pointer48DataType extends PointerDataType {
	static {
		ClassTranslator.put("ghidra.program.model.data.Pointer48",
			Pointer48DataType.class.getName());
	}

	public static final Pointer48DataType dataType = new Pointer48DataType();

	public Pointer48DataType() {
		this(null);
	}

	public Pointer48DataType(DataType dt) {
		super(dt, 6);
	}

}
