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
package ghidra.program.model.data.ISF;

import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.ISF.AbstractIsfWriter.Exclude;

public class IsfComponent extends AbstractIsfObject {

	public Integer offset;
	public IsfObject type;

	@Exclude
	public int ordinal;
	@Exclude
	public int length;
	@Exclude
	public String field_name;
	@Exclude
	public Boolean noFieldName;
	@Exclude
	public String comment;


	public IsfComponent(DataTypeComponent component, IsfObject typeObj) {
		super(component.getDataType());
		offset = component.getOffset();
		type = typeObj;

		field_name = component.getFieldName();
		if (field_name == null || field_name.equals("")) {
			noFieldName = true;
		}
		ordinal = component.getOrdinal();
		length = component.getLength();
		comment = component.getComment();
		
		processSettings(component.getDataType(), component.getDefaultSettings());		
	}

}
