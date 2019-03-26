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
package ghidra.program.model.data;

import java.util.ArrayList;
import java.util.List;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.*;
import ghidra.util.Msg;

/**
 * Structured Dynamic Data type.
 * 
 * Dynamic Structure that is built by adding data types to it.
 * 
 * NOTE: This is a special Dynamic data-type which can only appear as a component
 * created by a Dynamic data-type
 */
public abstract class StructuredDynamicDataType extends DynamicDataType {

	protected String description;
	protected List<DataType> components = new ArrayList<DataType>();
	protected List<String> componentNames = new ArrayList<String>();
	protected List<String> componentDescs = new ArrayList<String>();

	/**
	 * Construct an empty dynamic structure
	 * 
	 * @param name        name of the dynamic structure
	 * @param description description of the dynamic structure
	 */
	public StructuredDynamicDataType(String name, String description, DataTypeManager dtm) {
		super(name, dtm);
		this.description = description;
	}

//	public DataType clone(DataTypeManager dtm) {
//		if (dtm == getDataTypeManager()) {
//			return this;
//		}
//		StructuredDynamicDataType dt = new StructuredDynamicDataType(name, description, dtm);
//		dt.componentNames = new ArrayList<String>(componentNames);
//		dt.componentDescs = new ArrayList<String>(componentDescs);
//		for (DataType childDt : components) {
//			dt.components.add(childDt.clone(dtm));
//		}
//		return dt;
//	}

	/**
	 * Add a component data type onto the end of the dynamic structure
	 * 
	 * @param data        data type to add
	 * @param componentName        name of the field in the dynamic structure
	 * @param componentDescription description of the field
	 */
	public void add(DataType data, String componentName, String componentDescription) {
		components.add(components.size(), data);
		componentNames.add(componentNames.size(), componentName);
		componentDescs.add(componentDescs.size(), componentDescription);
	}

	/**
	 * Set the components of the dynamic structure all at once.
	 * This does not add the components in, it replaces any existing ones.
	 * 
	 * @param components      list of components to add
	 * @param componentNames  list of field names of each component
	 * @param componentDescs  list of descriptions of each component
	 */
	public void setComponents(List<DataType> components, List<String> componentNames,
			List<String> componentDescs) {
		this.components = new ArrayList<DataType>(components);
		this.componentNames = new ArrayList<String>(componentNames);
		this.componentDescs = new ArrayList<String>(componentDescs);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DynamicDataType#getAllComponents(ghidra.program.model.mem.MemBuffer)
	 */
	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer buf) {
		Memory memory = buf.getMemory();

		DataTypeComponent[] comps = new DataTypeComponent[components.size()];
		int offset = 0;
		MemoryBufferImpl newBuf = new MemoryBufferImpl(memory, buf.getAddress());
		try {
			for (int i = 0; i < components.size(); i++) {
				DataTypeInstance dti = DataTypeInstance.getDataTypeInstance(components.get(i), newBuf);
				if (dti == null) {
					Msg.error(this, "Invalid data at " + newBuf.getAddress());
					return null;
				}
				int len = dti.getLength();
				comps[i] =
					new ReadOnlyDataTypeComponent(dti.getDataType(), this, len, i, offset,
						componentNames.get(i) + "_" + newBuf.getAddress(), componentDescs.get(i));
				offset += len;
				newBuf.advance(len);
			}
		}
		catch (AddressOverflowException e) {
			Msg.error(this, "Invalid data at " + newBuf.getAddress());
			return null;
		}
		return comps;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	public String getDescription() {
		return description;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.program.model.lang.ProcessorContext, ghidra.program.model.data.Settings, int)
	 */
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.program.model.lang.ProcessorContext, ghidra.program.model.data.Settings, int)
	 */
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "";
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getMnemonic(ghidra.program.model.data.Settings)
	 */
	public String getMnemonic(Settings settings) {
		return name;
	}

}
