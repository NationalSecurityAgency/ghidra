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
package ghidra.app.util.bin.format.objectiveC;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class ObjectiveC1_SymbolTable implements StructConverter {
	public static final String NAME = "objc_symtab";

	private ObjectiveC1_State _state;
	private long _index;

	private int sel_ref_cnt;
	private int refs;
	private short cls_def_cnt;
	private short cat_def_cnt;
	private List<ObjectiveC1_Class> classes = new ArrayList<ObjectiveC1_Class>();
	private List<ObjectiveC1_Category> categories = new ArrayList<ObjectiveC1_Category>();

	ObjectiveC1_SymbolTable(ObjectiveC1_State state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		sel_ref_cnt  = reader.readNextInt();
		refs         = reader.readNextInt();
		cls_def_cnt  = reader.readNextShort();
		cat_def_cnt  = reader.readNextShort();

		for (int i = 0 ; i < cls_def_cnt ; ++i) {
			long classIndex = reader.readNextInt();
			long oldClassIndex = reader.getPointerIndex();
			reader.setPointerIndex(classIndex);
			classes.add(new ObjectiveC1_Class(state, reader));
			reader.setPointerIndex(oldClassIndex);
		}

		for (int i = 0 ; i < cat_def_cnt ; ++i) {
			long categoryIndex = reader.readNextInt();
			long oldCategoryIndex = reader.getPointerIndex();
			reader.setPointerIndex(categoryIndex);
			categories.add(new ObjectiveC1_Category(state, reader));
			reader.setPointerIndex(oldCategoryIndex);
		}
	}

	public int getSelectorReferenceCount() {
		return sel_ref_cnt;
	}
	public int getRefs() {
		return refs;
	}
	public short getClassDefinitionCount() {
		return cls_def_cnt;
	}
	public short getCategoryDefinitionCount() {
		return cat_def_cnt;
	}

	public List<ObjectiveC1_Class> getClasses() {
		return classes;
	}
	public List<ObjectiveC1_Category> getCategories() {
		return categories;
	}

	public static DataType toGenericDataType() throws DuplicateNameException {
		Structure struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		struct.add(DWORD, "sel_ref_cnt", null);
		struct.add(DWORD, "refs", null);
		struct.add( WORD, "cls_def_cnt", null);
		struct.add( WORD, "cat_def_cnt", null);
		return struct;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME+"_"+cls_def_cnt+"_"+cat_def_cnt+"_", 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		struct.add(DWORD, "sel_ref_cnt", null);
		struct.add(DWORD, "refs", null);
		struct.add( WORD, "cls_def_cnt", null);
		struct.add( WORD, "cat_def_cnt", null);
		for (int i = 0 ; i < cls_def_cnt ; ++i) {
			struct.add(PointerDataType.getPointer(classes.get(i).toDataType(), _state.pointerSize), "class"+i, null);
		}
		for (int i = 0 ; i < cat_def_cnt ; ++i) {
			struct.add(PointerDataType.getPointer(categories.get(i).toDataType(), _state.pointerSize), "category"+i, null);
		}
		return struct;
	}

	public void applyTo() throws Exception {
		if (_state.beenApplied.contains(_index)) {
			return;
		}
		_state.beenApplied.add(_index);

		Address address = _state.program.getAddressFactory().getDefaultAddressSpace().getAddress(_index);
		try {
			_state.program.getListing().createData(address, toDataType());
		}
		catch (Exception e) {}

		_state.program.getListing().getDefinedDataAt(address);

		for (ObjectiveC1_Class clazz : classes) {
			clazz.applyTo();
		}
		for (ObjectiveC1_Category category : categories) {
			category.applyTo();
		}
	}

}
