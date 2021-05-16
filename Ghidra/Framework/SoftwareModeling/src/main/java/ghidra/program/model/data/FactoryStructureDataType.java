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

import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.exception.DuplicateNameException;

/**
 * Abstract class used to create specialized data structures that act like
 * a Structure and create a new Dynamic structure each time they are used.
 */
public abstract class FactoryStructureDataType extends BuiltIn implements FactoryDataType {

	/**
	 * Constructs a new DynamicStructureDataType with the given name
	 * @param name the name of this dataType
	 */
	protected FactoryStructureDataType(String name, DataTypeManager dtm) {
		super(null, name, dtm);
	}

	@Override
	public abstract DataType clone(DataTypeManager dtm);

	/**
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
	@Override
	public final int getLength() {
		return -1;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	@Override
	public String getDescription() {
		return "Dynamic Data Type should not be instantiated directly";
	}

	@Override
	public DataType getDataType(MemBuffer buf) {
		Structure struct = new StructureDataType(getName(), 0);
		if (buf != null) {
			populateDynamicStructure(buf, struct);
			struct = setCategoryPath(struct, buf);
		}
		return struct;
	}

	/**
	 * Set the category of this data type.  
	 * 
	 * @param struct
	 * @param buf
	 * @return Returns a new structure with the correct category.
	 */
	protected Structure setCategoryPath(Structure struct, MemBuffer buf) {
		CategoryPath path = CategoryPath.ROOT;
		try {
			path =
				new CategoryPath(new CategoryPath(CategoryPath.ROOT, getName()), "" +
					buf.getAddress());
		}
		catch (Exception e) {
		}
		setCategory(struct, path);
		return struct;
	}

	private void setCategory(DataType dt, CategoryPath path) {
		if (dt == null) {
			return;
		}

		try {
			dt.setCategoryPath(path);
		}
		catch (DuplicateNameException e) {
		}
		if (dt instanceof Structure) {
			Structure struct = (Structure) dt;
			DataTypeComponent[] comps = struct.getDefinedComponents();
			for (DataTypeComponent comp : comps) {
				setCategory(comp.getDataType(), path);
			}
		}
		else if (dt instanceof Union) {
			Union union = (Union) dt;
			DataTypeComponent[] comps = union.getComponents();
			for (DataTypeComponent comp : comps) {
				setCategory(comp.getDataType(), path);
			}
		}
		else if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getDataType();
			setCategory(dt, path);
		}
		else if (dt instanceof Pointer) {
			setCategory(((Pointer) dt).getDataType(), path);
		}
		else if (dt instanceof Array) {
			Array array = (Array) dt;
			setCategory(array.getDataType(), path);
		}
	}

	protected DataTypeComponent addComponent(Structure es, DataType dt, String componentName) {

		return es.add(dt, dt.getLength(), componentName, null);
	}

	protected abstract void populateDynamicStructure(MemBuffer buf, Structure es);
}
