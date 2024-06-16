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
package sarif.export.data;

import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.ISF.IsfComponent;
import ghidra.program.model.data.ISF.IsfComposite;
import ghidra.program.model.data.ISF.IsfDataTypeWriter;
import ghidra.program.model.data.ISF.IsfObject;
import ghidra.util.task.TaskMonitor;

public class ExtIsfComposite extends IsfComposite {
	
	String packed;
	Integer explicitPackingValue;
	String alignment;
	Integer explicitMinimumAlignment;

	public ExtIsfComposite(Composite composite, IsfDataTypeWriter writer, TaskMonitor monitor) {
		super(composite, writer, monitor);
		name = composite.getName();
		location = composite.getCategoryPath().getPath();
		packed = Boolean.toString(composite.isPackingEnabled());
		int epval = composite.getExplicitPackingValue();
		explicitPackingValue = epval > 0 ? epval : null;
		alignment = Integer.toHexString(composite.getAlignment());
		int maval = composite.getExplicitMinimumAlignment();
		explicitMinimumAlignment = maval > 0 ? maval : null;
	}

	@Override
	protected IsfComponent getComponent(DataTypeComponent component, IsfObject type) {
		return new ExtIsfComponent(component, type);
	}

}
