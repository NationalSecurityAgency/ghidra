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
package sarif.export.func;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ISF.AbstractIsfObject;
import ghidra.program.model.listing.Parameter;

public class ExtFunctionRegVar extends AbstractIsfObject {

	String register;
	String comment;
	int size;

	String typeName;
	String typeLocation;
	ExtDataType type;

	public ExtFunctionRegVar(Parameter var) {
		super(var.getDataType());
		name = var.getName();
		register = var.getRegister().getName();
		size = var.getLength();
		comment = var.getComment();
		
		DataType dataType = var.getDataType();
		typeName = dataType.getName();
		typeLocation = dataType.getCategoryPath().getPath();
		type = new ExtDataType(dataType);
	}

}
