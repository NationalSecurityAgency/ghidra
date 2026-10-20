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
package ghidra.app.util.bin.format.objc.objc1;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.objc.ObjcState;
import ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Objc1SymbolTable extends ObjcTypeMetadataStructure {
	public static final String NAME = "objc_symtab";

	private int sel_ref_cnt;
	private int refs;
	private short cls_def_cnt;
	private short cat_def_cnt;
	private List<Objc1Class> classes = new ArrayList<Objc1Class>();
	private List<Objc1Category> categories = new ArrayList<Objc1Category>();

	Objc1SymbolTable(Program program, ObjcState state, BinaryReader reader) throws IOException {
		super(program, state, reader.getPointerIndex());

		sel_ref_cnt = reader.readNextInt();
		refs = reader.readNextInt();
		cls_def_cnt = reader.readNextShort();
		cat_def_cnt = reader.readNextShort();

		for (int i = 0; i < cls_def_cnt; ++i) {
			long classIndex = reader.readNextInt();
			long oldClassIndex = reader.getPointerIndex();
			reader.setPointerIndex(classIndex);
			classes.add(new Objc1Class(program, state, reader));
			reader.setPointerIndex(oldClassIndex);
		}

		for (int i = 0; i < cat_def_cnt; ++i) {
			long categoryIndex = reader.readNextInt();
			long oldCategoryIndex = reader.getPointerIndex();
			reader.setPointerIndex(categoryIndex);
			categories.add(new Objc1Category(program, state, reader));
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

	public List<Objc1Class> getClasses() {
		return classes;
	}

	public List<Objc1Category> getCategories() {
		return categories;
	}

	public static DataType toGenericDataType() throws DuplicateNameException {
		Structure struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(Objc1Constants.CATEGORY_PATH);
		struct.add(DWORD, "sel_ref_cnt", null);
		struct.add(DWORD, "refs", null);
		struct.add(WORD, "cls_def_cnt", null);
		struct.add(WORD, "cat_def_cnt", null);
		return struct;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct =
			new StructureDataType(NAME + "_" + cls_def_cnt + "_" + cat_def_cnt + "_", 0);
		struct.setCategoryPath(Objc1Constants.CATEGORY_PATH);
		struct.add(DWORD, "sel_ref_cnt", null);
		struct.add(DWORD, "refs", null);
		struct.add(WORD, "cls_def_cnt", null);
		struct.add(WORD, "cat_def_cnt", null);
		for (int i = 0; i < cls_def_cnt; ++i) {
			struct.add(PointerDataType.getPointer(classes.get(i).toDataType(), pointerSize),
				"class" + i, null);
		}
		for (int i = 0; i < cat_def_cnt; ++i) {
			struct.add(PointerDataType.getPointer(categories.get(i).toDataType(), pointerSize),
				"category" + i, null);
		}
		return struct;
	}

	@Override
	public void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception {
		if (state.beenApplied.contains(base)) {
			return;
		}
		state.beenApplied.add(base);

		Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(base);
		DataType dt = toDataType();
		try {
			DataUtilities.createData(program, address, dt, -1,
				ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
		}
		catch (Exception e) {
			Msg.warn(this, "Could not create " + dt.getName() + " @" + address);
		}

		program.getListing().getDefinedDataAt(address);

		for (Objc1Class clazz : classes) {
			clazz.applyTo(namespace, monitor);
		}
		for (Objc1Category category : categories) {
			category.applyTo(namespace, monitor);
		}
	}

}
