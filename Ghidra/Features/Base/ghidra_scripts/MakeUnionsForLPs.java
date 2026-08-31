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
// Create unions to replace *32 pointer references
//
//@category Data Types
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.InternalDataTypeComponent;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.PointerTypedef;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class MakeUnionsForLPs extends GhidraScript {

	protected static final String OFFSET_NAME = "__offset__";
	protected static final String SEGMENT_NAME = "__segment__";
	protected static final String NEAR_NAME = "__np__";
	protected static final String FAR_NAME = "__lp__";
	protected static final CategoryPath GHIDRA_LP_UNION_CATEGORY = new CategoryPath("/_GhidraLpUnions");
	protected static final CategoryPath GHIDRA_LP_UNION_STRUCT_CATEGORY = new CategoryPath("/_GhidraLpUnions/_seg");

	protected static final String UNDEFINED = "undefined";
	protected static final String NEAR_P = " * ".concat(NEAR_NAME);
	protected static final String FAR_LP = " far * ".concat(FAR_NAME);
	protected static final String UNION_PREFIX = "LP";
	protected static final String SEGMENT_PREFIX = "__seg";

	@Override
	protected void run() throws Exception, CancelledException {

		DataTypeManager dtMgr = currentProgram.getDataTypeManager();
		if (dtMgr == null) {
			return;
		}

//		// do a test of creating a data type
//		int transTest = dtMgr.startTransaction("Test add new 'LPvoid' union");
//		try {
//			testCreateNewLPUnion(dtMgr);
//		}
//		catch (Exception e) {
//			dtMgr.endTransaction(transTest, false);
//			Msg.error(this, e.getMessage());
//			throw e;
//		}
//		dtMgr.endTransaction(transTest, true);

		// start for real
		String message = "Getting list of pre-created unions from: " + dtMgr.getName();
		monitor.setMessage(message);
		Msg.info(this, message);

		Map<String, Union> lpTypes = setupCurrentLPUnionList(dtMgr);

		message = "Creating new unions in: " + dtMgr.getName();
		monitor.setMessage(message);
		Msg.info(this, message);

		// create new unions
		int trans = dtMgr.startTransaction("Add new ".concat(UNION_PREFIX).concat(" unions"));
		try {
			lpTypes = createNewLPUnions(dtMgr, lpTypes, trans);
		}
		catch (Exception e) {
			dtMgr.endTransaction(trans, false);
			Msg.error(this, e.getMessage());
			throw e;
		}
		dtMgr.endTransaction(trans, true);

		message = "Replacing usage of *32 within Composites with new unions in: " + dtMgr.getName();
		monitor.setMessage(message);
		Msg.info(this, message);

		// update uses of pointer *32 types with new union types
		trans = dtMgr.startTransaction("Change all *32 uses to the new unions");
		try {
			updatePointer32References(dtMgr, lpTypes);
		}
		catch (Exception e) {
			dtMgr.endTransaction(trans, false);
			Msg.error(this, e.getMessage());
			throw e;
		}
		dtMgr.endTransaction(trans, true);

		message = "Replacing usage of *32 with new unions in: " + dtMgr.getName();
		monitor.setMessage(message);
		Msg.info(this, message);

		// update uses of pointer *32 within function declarations with new union types
		trans = dtMgr.startTransaction("Change all *32 uses within function declarations to the new unions");
		try {
			FunctionManager fnMgr = currentProgram.getFunctionManager();
			updatePointer32FunctionParamReferences(fnMgr.getFunctions(false), lpTypes);
		}
		catch (Exception e) {
			dtMgr.endTransaction(trans, false);
			Msg.error(this, e.getMessage());
			throw e;
		}
		dtMgr.endTransaction(trans, true);

//		message = "Results located in: " + dumpFile.getAbsoluteFile();
//		monitor.setMessage(message);
//		Msg.info(this, message);
	}

	/**
	 * Test creation of Union (and Category) using 'void' as an example
	 *
	 * @param dtMgr
	 * @throws CancelledException
	 * @throws DuplicateNameException
	 * @throws ParseException
	 */
	private void testCreateNewLPUnion(DataTypeManager dtMgr) throws ParseException {
//		CParser parser = new CParser(dtMgr);
//
//		String name = "void";
//		String newUnion = "union ".concat(PREFIX).concat(name ).concat(" {")
//				.concat(name).concat(NEAR_P)
//				.concat(name).concat(FAR_LP)
//				.concat("};")
//				;
////			union GhidraLP_Dgn11e0_1c7b_0x1c_t {
////			    Dgn11e0_1c7b_0x1c_t * np;
////			    Dgn11e0_1c7b_0x1c_t*32 lp;
////			};
//
//		try {
//			Union ut = (Union) parser.parse(newUnion);
//			ut.setCategoryPath(GHIDRALPUNIONCATEGORY);
//			dtMgr.addDataType(ut , null);
//		} catch (ParseException e) {
//			e.printStackTrace();
//			Msg.error(this, e.getMessage());
////			throw e;
//		} catch (DuplicateNameException e) {
//			// Don't care
//			e.printStackTrace();
//		}

		StructureDataType structPtrComp = new StructureDataType(GHIDRA_LP_UNION_STRUCT_CATEGORY, "__segLPVOID", 0, dtMgr);
		structPtrComp.add(dtMgr.getDataType("/void *"), -1, OFFSET_NAME, "");
		try {
			structPtrComp.add(dtMgr.getDataType("/SegmentCodeAddress"), 2, SEGMENT_NAME, "");
		}
		catch (Exception e) {
			PluginTool tool = state.getTool();
			DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
			DataTypeManager[] dataTypeManagers = service.getDataTypeManagers();
			for (DataTypeManager dataTypeManager : dataTypeManagers) {
				try {
					structPtrComp.add(dataTypeManager.getDataType("/SegmentCodeAddress"), 2, SEGMENT_NAME, "");
					break;
				}
				catch (Exception e1) {
					// Try next!
				}
			}
		}
		UnionDataType ut = new UnionDataType(GHIDRA_LP_UNION_CATEGORY, "LPVOID_test");
		ut.add(structPtrComp, 4, NEAR_NAME, "");
		ut.add(dtMgr.getDataType("/windows.h/LPVOID"), 4, FAR_NAME, "");
		dtMgr.addDataType(ut, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	/**
	 * Setup list of pre-created LP union types
	 *
	 * @param dtMgr
	 * @return
	 * @throws CancelledException
	 */
	protected Map<String, Union> setupCurrentLPUnionList(DataTypeManager dtMgr) throws CancelledException {
		Map<String,Union> lpTypeNames = new HashMap<>();
		Iterator<Composite> allCompositeTypes = dtMgr.getAllComposites();
		while (allCompositeTypes.hasNext()) {
			monitor.checkCanceled();
			Composite dataType = allCompositeTypes.next();
			if (!dataType.getCategoryPath().equals(GHIDRA_LP_UNION_CATEGORY)) continue;
			if (!(dataType instanceof Union)) continue;
			Union ut = (Union) dataType;
			String unionName = ut.getName();
			if (!unionName.startsWith(UNION_PREFIX)) continue;
			if (2 != ut.getNumComponents()) continue;
			if (4 != ut.getLength()) continue;
			DataTypeComponent[] cdts = ut.getComponents();
			DataTypeComponent dtc0 = cdts[0];
			DataType dt0 = dtc0.getDataType();
			if (!(dt0 instanceof Structure)) continue;
			Structure st = (Structure) dt0;
			if (2 != st.getNumComponents()) continue;
			dtc0 = st.getComponent(0);
			dt0 = dtc0.getDataType();
			if (!(dt0 instanceof Pointer)) continue;
			DataTypeComponent dtc1 = cdts[1];
			DataType dt1 = dtc1.getDataType();
			if (!(dt1 instanceof Pointer)) continue;
			Pointer pDt0 = (Pointer) dt0;
			Pointer pDt1 = (Pointer) dt1;
			if (8 != pDt0.getLength() * pDt1.getLength()) continue;
			if (pDt0.getDataType() != pDt1.getDataType()) continue;

			// otherwise
			lpTypeNames.put(unionName.substring(UNION_PREFIX.length()).toLowerCase(), ut);
		}
		return lpTypeNames;
	}

	/**
	 * Ensure pointer to data type exists, create if not.
	 *
	 * @param dtMgr
	 * @param dt
	 * @param ptrType
	 * @param size
	 * @return
	 * @throws DuplicateNameException
	 */
	private static DataType getPointerType(DataTypeManager dtMgr, DataType dt, String ptrType, int size)
			throws DuplicateNameException {
		if (!ptrType.startsWith("/")) {
			ptrType = "/" + ptrType;
		}
		DataType pDt = dtMgr.getDataType(ptrType);
		if (null == pDt) {
			pDt = new PointerDataType(dt, size, dtMgr);
			pDt.setCategoryPath(dt.getCategoryPath());
		}
		return pDt;
	}

	/**
	 * Add new LP Union types for ones not allocated
	 *
	 * @param dtMgr
	 * @param lpTypeNames
	 * @param trans
	 * @return
	 * @throws CancelledException
	 * @throws DuplicateNameException
	 * @throws ParseException
	 */
	protected Map<String, Union> createNewLPUnions(DataTypeManager dtMgr, Map<String, Union> lpTypeNames, int trans)
			throws CancelledException, DuplicateNameException {
		Iterator<DataType> allDataTypes = dtMgr.getAllDataTypes();

		while (allDataTypes.hasNext()) {
			monitor.checkCanceled();
			DataType dataType = allDataTypes.next();
			if (dataType.getName().startsWith("Dgn1210_0756_0x1a_t")) {
				System.out.println(dataType.getName());
			}
			if (!(dataType instanceof Pointer)) continue;
			Pointer pDt = (Pointer) dataType;
			if (4 != pDt.getLength()) continue;
			DataType dt = pDt.getDataType();
			if (null == dt) continue;
			if (dt instanceof Pointer) continue;
			if (dt instanceof Array) continue;
			String name = dt.getName();
			if (name.startsWith(UNDEFINED)) continue;
			if (lpTypeNames.containsKey(name.toLowerCase())) continue;
			String newUnion = "union ".concat(UNION_PREFIX).concat(name).concat(" {")
					.concat(name).concat(NEAR_P).concat(";")
					.concat(name).concat(FAR_LP).concat(";")
					.concat("};")
					;
//			union GhidraLP_Dgn11e0_1c7b_0x1c_t {
//			    Dgn11e0_1c7b_0x1c_t * np;
//			    Dgn11e0_1c7b_0x1c_t*32 lp;
//			};

			UnionDataType ut = CreateNewLPUnion(dtMgr, dt);
			lpTypeNames.put(name.toLowerCase(), ut);
		}

		return lpTypeNames;
	}

	public UnionDataType CreateNewLPUnion(DataTypeManager dtMgr, DataType dt)
			throws DuplicateNameException {
		String name = dt.getName();
		String unionName = UNION_PREFIX.concat(name);
System.out.println(unionName);
if ("LPpfn01AddToMemoryManager".equals(unionName)) {
System.out.println("");
}
		String structName = SEGMENT_PREFIX.concat(unionName);
		String nearPtrType = dt.getCategoryPath().getName().concat("/").concat(name).concat(" *");
		String farPtrType = dt.getCategoryPath().getName().concat("/").concat(name).concat(" *32");

		StructureDataType structPtrComp = new StructureDataType(GHIDRA_LP_UNION_STRUCT_CATEGORY, structName , 0, dtMgr);
		DataType nearPDt = getPointerType(dtMgr, dt, nearPtrType, 2);
		structPtrComp.add(nearPDt , -1, OFFSET_NAME, "");
		try {
			structPtrComp.add(dtMgr.getDataType("/SegmentCodeAddress"), 2, SEGMENT_NAME, "");
		}
		catch (Exception e) {
			PluginTool tool = state.getTool();
			DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
			DataTypeManager[] dataTypeManagers = service.getDataTypeManagers();
			for (DataTypeManager dataTypeManager : dataTypeManagers) {
				try {
					structPtrComp.add(dataTypeManager.getDataType("/SegmentCodeAddress"), 2, SEGMENT_NAME, "");
					break;
				}
				catch (Exception e1) {
					// Try next!
				}
			}
		}

		UnionDataType ut = new UnionDataType(GHIDRA_LP_UNION_CATEGORY, UNION_PREFIX.concat(name));
		ut.add(structPtrComp, 4, NEAR_NAME, "");
		DataType farPDt = getPointerType(dtMgr, dt, farPtrType, 4);
		ut.add(farPDt, 4, FAR_NAME, "");
		dtMgr.addDataType(ut, DataTypeConflictHandler.REPLACE_HANDLER);

		return ut;
	}

	/**
	 * Search and replace uses of *32 references with LP union version
	 *
	 * @param dtMgr
	 * @param lpTypes
	 * @throws Exception
	 */
	protected void updatePointer32References(DataTypeManager dtMgr, Map<String, Union> lpTypes)
			throws Exception {
		Iterator<DataType> allTypes = dtMgr.getAllDataTypes();
		while (allTypes.hasNext()) {
			monitor.checkCanceled();
			DataType dataType = allTypes.next();
			if (dataType.getCategoryPath().equals(GHIDRA_LP_UNION_CATEGORY)) continue;
			if (dataType instanceof Composite) {
				updatePointer32CompositeReferences((Composite) dataType, lpTypes);
			}
			else if (dataType instanceof FunctionDefinition) {
				updatePointer32FunctionDefinitionReferences((FunctionDefinition) dataType, lpTypes);
			}
			else if (dataType instanceof TypeDef) {
				updatePointer32TypeDefReferences((TypeDef) dataType, lpTypes, dtMgr);
			}
			else if (dataType instanceof Array) {
				;
			}
			else {
//				System.out.println(dataType);
			}
		}
	}

	/**
	 *
	 * @param dataType
	 * @param lpTypes
	 * @param dtMgr
	 */
	private void updatePointer32TypeDefReferences(TypeDef dataType, Map<String, Union> lpTypes,
			DataTypeManager dtMgr) {
		DataType dt = dataType.getDataType();

		if (!(dt instanceof Pointer)) return;
		Pointer pDt = (Pointer) dt;
		if (4 != pDt.getLength()) return;
		DataType dtBase = pDt.getDataType();
		if (null == dtBase) return;
		if (dtBase instanceof Pointer) return;
		String name = dtBase.getName();
		DataType lpType = lpTypes.get(name.toLowerCase());
		if (null == lpType) return;
		String newName = dataType.getName();
		if (newName.equals(lpType.getName())) {
			newName = "TD_" + newName;
		}
		TypedefDataType td = new TypedefDataType(dataType.getCategoryPath(), newName, lpType);
		TypedefDataType.copyTypeDefSettings(dataType, td, false);
		try {
			dtMgr.replaceDataType(dataType, td, false);
		} catch (DataTypeDependencyException e) {
			Msg.error(this, e.getMessage());
		}
	}

	/**
	 *
	 *
	 * @param dataType
	 * @param lpTypes
	 */
	private void updatePointer32FunctionDefinitionReferences(FunctionDefinition dataType,
			Map<String, Union> lpTypes) {
		ParameterDefinition[] params = dataType.getArguments();

		for (int idx=0; idx<params.length; ++idx) {
			ParameterDefinition param = params[idx];
			DataType dt = param.getDataType();
			if (!(dt instanceof Pointer)) continue;
			Pointer pDt = (Pointer) dt;
			if (4 != pDt.getLength()) continue;
			DataType dtBase = pDt.getDataType();
			if (null == dtBase) continue;
			if (dtBase instanceof Pointer) continue;
			String name = dtBase.getName();
			DataType lpType = lpTypes.get(name.toLowerCase());
			if (null == lpType) continue;
			try {
				param.setDataType(lpType);
			} catch (IllegalArgumentException e) {
				Msg.error(this, e.getMessage());
			}
		}

		dataType.setArguments(params);
	}

	/**
	 * In all Composite types, search and replace uses of *32 references with LP union version
	 *
	 * @param dtMgr
	 * @param lpTypes
	 * @param dataType
	 * @throws CancelledException
	 */
	protected void updatePointer32CompositeReferences(Composite dataType, Map<String, Union> lpTypes)
			throws CancelledException {
		if (dataType instanceof FunctionDefinitionDataType) {
			throw new CancelledException("Found FunctionDefinitionDataType");
		}

		DataTypeComponent[] cdts = dataType.getComponents();
		for (int idx=0; idx<cdts.length; ++idx) {
			DataTypeComponent dtc = cdts[idx];
			if (!(dtc instanceof InternalDataTypeComponent)) continue;
			InternalDataTypeComponent idtc = (InternalDataTypeComponent) dtc;
			DataType dt = idtc.getDataType();
			if (!(dt instanceof Pointer)) continue;
			Pointer pDt = (Pointer) dt;
			if (4 != pDt.getLength()) continue;
			DataType dtBase = pDt.getDataType();
			if (null == dtBase) continue;

if("DgnDFileStream_vtable".equals(dtBase.getName())) {
	System.out.println(dtBase);
}
			if (dtBase instanceof Pointer) continue;
			String name = dtBase.getName();
			DataType lpType = lpTypes.get(name.toLowerCase());
			if (null == lpType) continue;
			idtc.setDataType(lpType);
		}
	}

	/**
	 * In all Function definitions, search and replace uses of *32 references with LP union version
	 *
	 * @param functionIterator
	 * @param lpTypes
	 * @throws CancelledException
	 */
	protected void updatePointer32FunctionParamReferences(FunctionIterator functionIterator, Map<String, Union> lpTypes)
			throws CancelledException {
int count=0; int stop[] = {2299}; int restart[] = {3001}; int stopstart=0;
		while ( functionIterator.hasNext()) {
			monitor.checkCanceled();
			Function fnType = functionIterator.next();
System.out.println(fnType.getSignature(false));

			// do return type
			DataType dt = fnType.getReturnType();
			if (dt instanceof Pointer) {
				Pointer pDt = (Pointer) dt;
				if (4 == pDt.getLength()) {
					DataType dtBase = pDt.getDataType();
					if (null != dtBase) {
						if (!(dtBase instanceof Pointer)) {
							String name = dtBase.getName();
							DataType lpType = lpTypes.get(name.toLowerCase());
							if (null != lpType) {
								try {
									fnType.setReturnType(lpType, SourceType.USER_DEFINED);
								} catch (InvalidInputException e) {
									Msg.error(this, e.getMessage());
								}
							}
						}
					}
				}
			}

			// do params
			Parameter[] params = fnType.getParameters();
			for (int idx=0; idx<params.length; ++idx) {
				Parameter param = params[idx];
				dt = param.getDataType();
				if (!(dt instanceof Pointer)) continue;
				Pointer pDt = (Pointer) dt;
				if (4 != pDt.getLength()) continue;
				DataType dtBase = pDt.getDataType();
				if (null == dtBase) continue;
				if (dtBase instanceof Pointer) continue;
				String name = dtBase.getName();
				DataType lpType = lpTypes.get(name.toLowerCase());
				if (null == lpType) continue;
				try {
					param.setDataType(lpType, param.getSource());
				} catch (InvalidInputException e) {
					Msg.error(this, e.getMessage());
				}
			}

			// do locals
			Variable[] localVars = fnType.getLocalVariables();
			for (int idx = 0; idx < localVars.length; idx++) {
				Variable var = localVars[idx];
				dt = var.getDataType();
				if (!(dt instanceof Pointer)) continue;
				Pointer pDt = (Pointer) dt;
				if (4 != pDt.getLength()) continue;
				DataType dtBase = pDt.getDataType();
				if (null == dtBase) continue;
				if (dtBase instanceof Pointer) continue;
				String name = dtBase.getName();
				DataType lpType = lpTypes.get(name.toLowerCase());
				if (null == lpType) continue;
				try {
					var.setDataType(lpType, var.getSource());
				} catch (InvalidInputException e) {
					Msg.error(this, e.getMessage());
				}
			}
		}
	}

}
