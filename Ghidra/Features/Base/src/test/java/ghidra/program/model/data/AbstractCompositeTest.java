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

import static org.junit.Assert.*;

import java.io.*;
import java.util.HashMap;

import generic.test.AbstractGTest;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.util.Msg;
import resources.ResourceManager;

abstract class AbstractCompositeTest extends AbstractGTest {

	private HashMap<Long, DataType> copyMap = new HashMap<>();

	private final boolean returnDeepCopyOnQuery;

	protected AbstractCompositeTest() {
		// If test class name contains "Impl" enable deep copy on query
		returnDeepCopyOnQuery = getClass().getSimpleName().contains("Impl");
	}

	public void setUp() throws Exception {
		copyMap.clear();
	}

	protected void parseCHeaderFile(String headerResourcePath) throws IOException, ParseException {

		DataTypeManager dataMgr = getDataTypeManager();
		if (dataMgr.getDataTypeCount(false) != 0) {
//			Msg.info(this, "Using previously parsed data types");
			return; // already have types
		}

		Msg.info(this, "Parsing data types from " + headerResourcePath);

		CParser parser = new CParser(dataMgr, true, null);

		try (InputStream is = ResourceManager.getResourceAsStream(headerResourcePath)) {
			if (is == null) {
				throw new FileNotFoundException("Resource not found: " + headerResourcePath);
			}
			// Msg.debug(this, "Parsing C headers from " + headerResourcePath);
			parser.parse(is);
		}

		// uncomment to generate datatype archive
		//writeArchive(headerResourcePath);
	}

//	private void writeArchive(String headerResourcePath) throws IOException {
//		URL resource = ResourceManager.getResource(headerResourcePath);
//		File f = new File(resource.getPath() + ".gdt");
//		if (f.exists()) {
//			f.delete();
//		}
//
//		FileDataTypeManager fileDtMgr = FileDataTypeManager.createFileArchive(f);
//		int txId = fileDtMgr.startTransaction("Save Datatypes");
//		try {
//			Iterator<Composite> composites = getDataTypeManager().getAllComposites();
//			while (composites.hasNext()) {
//				fileDtMgr.addDataType(composites.next(), null);
//			}
//		}
//		finally {
//			fileDtMgr.endTransaction(txId, true);
//		}
//
//		fileDtMgr.save();
//		fileDtMgr.close();
//
//		Msg.debug(this, "Saved datatype archive: " + f.getAbsolutePath());
//	}

	protected final DataTypeManager createDataTypeManager(String name, DataOrganization dataOrg) {
		return new StandAloneDataTypeManager(name, dataOrg);
	}

	abstract DataTypeManager getDataTypeManager();

	protected Structure getStructure(String name) {
		DataTypeManager dtMgr = getDataTypeManager();
		DataType dataType = dtMgr.getDataType("/" + name);
		assertTrue("Data type not found: " + name, dataType instanceof Structure);
		if (returnDeepCopyOnQuery) {
			dataType = deepCopy(dataType); // TODO: need deep copy
		}
		return (Structure) dataType;
	}

	protected Union getUnion(String name) {
		DataTypeManager dtMgr = getDataTypeManager();
		DataType dataType = dtMgr.getDataType("/" + name);
		assertTrue("Data type not found: " + name, dataType instanceof Union);
		if (returnDeepCopyOnQuery) {
			dataType = deepCopy(dataType);
		}
		return (Union) dataType;
	}

	private void copyCompositeSettings(Composite from, Composite to) {
		to.setDescription(from.getDescription());
		if (from.hasExplicitPackingValue()) {
			to.setExplicitPackingValue(from.getExplicitPackingValue());
		}
		else if (from.hasDefaultPacking()) {
			to.setToDefaultPacking();
		}
		if (from.hasExplicitMinimumAlignment()) {
			to.setExplicitMinimumAlignment(from.getExplicitMinimumAlignment());
		}
		else if (from.isMachineAligned()) {
			to.setToMachineAligned();
		}
	}

	private DataType deepCopy(DataType dt) {

		DataTypeManager dtMgr = dt.getDataTypeManager();
		long id = dtMgr.getID(dt);
		if (id > 0 && copyMap.containsKey(id)) {
			return copyMap.get(id);
		}

		if (dt instanceof Structure) {
			Structure s = (Structure) dt;
			StructureDataType struct =
				new StructureDataType(s.getCategoryPath(), s.getName(), s.getLength(), dtMgr);
			copyMap.put(id, struct);
			copyCompositeSettings(s, struct);
			for (DataTypeComponent dtc : s.getDefinedComponents()) {
				if (struct.isPackingEnabled()) {
					struct.add(deepCopy(dtc.getDataType()), dtc.getLength(), dtc.getFieldName(),
						dtc.getComment());
				}
				else if (dtc.isBitFieldComponent()) {
					BitFieldDataType bf = (BitFieldDataType) dtc.getDataType();
					try {
						struct.insertBitFieldAt(dtc.getOffset(), dtc.getLength(), bf.getBitOffset(),
							bf.getBaseDataType().copy(dtMgr), bf.getDeclaredBitSize(),
							dtc.getFieldName(), dtc.getComment());
					}
					catch (InvalidDataTypeException e) {
						failWithException("Unexpected exception", e);
					}
				}
				else {
					struct.insertAtOffset(dtc.getOffset(), deepCopy(dtc.getDataType()),
						dtc.getLength(), dtc.getFieldName(), dtc.getComment());
				}
			}
			return struct;
		}
		else if (dt instanceof Union) {
			Union u = (Union) dt;
			UnionDataType union = new UnionDataType(u.getCategoryPath(), u.getName(), dtMgr);
			copyMap.put(id, union);
			copyCompositeSettings(u, union);
			for (DataTypeComponent dtc : u.getDefinedComponents()) {
				union.add(deepCopy(dtc.getDataType()), dtc.getLength(), dtc.getFieldName(),
					dtc.getComment());
			}
			return union;
		}
		else if (dt instanceof Array) {
			Array a = (Array) dt;
			a = new ArrayDataType(deepCopy(a.getDataType()), a.getNumElements(),
				a.getElementLength(), dtMgr);
			copyMap.put(id, a);
			return a;
		}
		else if (dt instanceof Pointer) {
			Pointer p = (Pointer) dt;
			p = new PointerDataType(deepCopy(p.getDataType()),
				p.hasLanguageDependantLength() ? -1 : p.getLength(), dtMgr);
			copyMap.put(id, p);
			return p;
		}
		else if (dt instanceof TypeDef) {
			TypeDef t = (TypeDef) dt;
			t = new TypedefDataType(t.getCategoryPath(), t.getName(), deepCopy(t.getDataType()),
				dtMgr);
			copyMap.put(id, t);
			return t;
		}
		dt = dt.copy(dtMgr);
		copyMap.put(id, dt);
		return dt;
	}

}
