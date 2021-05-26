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
//Script to update the given class's virtual functions' function signature data types and 
// the given class's vfunction structure field name for any differing functions in 
// the class virtual function table(s). To run, put the cursor on any of the desired class's
// virtual functions or at the top a class vftable. The script will not work if the <class>_vftable
// structure is not applied to the vftable using the ExtractClassInfoFromRTTIScript.
//@category C++

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;

public class UpdateClassFunctionDataScript extends GhidraScript {
	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("There is no open program");
			return;
		}


		Function function = getFunctionContaining(currentAddress);
		if (function != null) {

			Namespace parentNamespace = function.getParentNamespace();
			
			Parameter thisParam = function.getParameter(0);
			if (thisParam.getName().equals("this")) {
				DataType dataType = thisParam.getDataType();
				if (dataType instanceof Pointer) {
					Pointer pointer = (Pointer) dataType;
					DataType baseDataType = pointer.getDataType();
					if (baseDataType.getName().equals(parentNamespace.getName())) {
						// call update
						println("updating class " + parentNamespace.getName());
						updateClassFunctionDataTypes(parentNamespace);
						return;
					}
				}

			}
			
		}

		Symbol primarySymbol = currentProgram.getSymbolTable().getPrimarySymbol(currentAddress);
		if (primarySymbol.getName().equals("vftable") ||
			primarySymbol.getName().substring(1).startsWith("vftable")) {
			updateClassFunctionDataTypes(primarySymbol.getParentNamespace());
			return;
		}

	}

	private void updateClassFunctionDataTypes(Namespace classNamespace)
			throws CancelledException, DuplicateNameException, DataTypeDependencyException {

		List<Symbol> classVftableSymbols = getClassVftableSymbols(classNamespace);

		Iterator<Symbol> vftableIterator = classVftableSymbols.iterator();
		while (vftableIterator.hasNext()) {
			monitor.checkCanceled();
			Symbol vftableSymbol = vftableIterator.next();
			Address vftableAddress = vftableSymbol.getAddress();
			Data data = getDataAt(vftableAddress);
			if (data == null) {
				continue;
			}
			DataType baseDataType = data.getBaseDataType();
			if (!(baseDataType instanceof Structure)) {
				continue;
			}

			Structure vfunctionStructure = (Structure) baseDataType;

			Category category = getDataTypeCategory(vfunctionStructure);

			if (category == null) {
				continue;
			}

			// check that the structure name starts with <classname>_vtable and that it is in 
			// the dt folder with name <classname>
			if (category.getName().equals(classNamespace.getName()) &&
				vfunctionStructure.getName().startsWith(classNamespace.getName() + "_vftable")) {
				println(
					"Updating vfunction signature data types and (if necessary) vtable structure for vftable at address " +
					vftableAddress.toString());
				updateVfunctionDataTypes(data, vfunctionStructure, vftableAddress);
			}
		}

	}

	/**
	 * Method to find any function signatures in the given vfunction structure that have changed
	 * and update the function signature data types
	 * @throws DuplicateNameException 
	 * @throws DataTypeDependencyException 
	 */
	private void updateVfunctionDataTypes(Data structureAtAddress, Structure vfunctionStructure,
			Address vftableAddress) throws DuplicateNameException, DataTypeDependencyException {

		DataTypeManager dtMan = currentProgram.getDataTypeManager();

		int numVfunctions = structureAtAddress.getNumComponents();

		for (int i = 0; i < numVfunctions; i++) {
			Data dataComponent = structureAtAddress.getComponent(i);

			Reference[] referencesFrom = dataComponent.getReferencesFrom();
			if (referencesFrom.length != 1) {
				continue;
			}
			Address functionAddress = referencesFrom[0].getToAddress();
			Function vfunction = getFunctionAt(functionAddress);
			if (vfunction == null) {
				continue;
			}
			FunctionDefinitionDataType functionSignatureDataType =
				(FunctionDefinitionDataType) vfunction.getSignature();

			DataTypeComponent structureComponent = vfunctionStructure.getComponent(i);
			DataType componentDataType = structureComponent.getDataType();
			if (!(componentDataType instanceof Pointer)) {
				continue;
			}

			Pointer pointer = (Pointer) componentDataType;
			DataType pointedToDataType = pointer.getDataType();
			if (functionSignatureDataType.equals(pointedToDataType)) {
				continue;
			}
			// update data type with new new signature
			dtMan.replaceDataType(pointedToDataType, functionSignatureDataType, true);
			if (!structureComponent.getFieldName().equals(vfunction.getName())) {
				structureComponent.setFieldName(vfunction.getName());
			}
		}

	}

	private Category getDataTypeCategory(DataType dataType) {

		DataTypeManager dataTypeManager = currentProgram.getDataTypeManager();
		CategoryPath originalPath = dataType.getCategoryPath();
		Category category = dataTypeManager.getCategory(originalPath);

		return category;
	}

	private List<Symbol> getClassVftableSymbols(Namespace classNamespace)
			throws CancelledException {

		SymbolTable symbolTable = currentProgram.getSymbolTable();
		List<Symbol> vftableSymbols = new ArrayList<Symbol>();

		SymbolIterator symbols = symbolTable.getSymbols(classNamespace);
		while (symbols.hasNext()) {

			monitor.checkCanceled();
			Symbol symbol = symbols.next();
			if (symbol.getName().equals("vftable") ||
				symbol.getName().substring(1).startsWith("vftable")) {
				vftableSymbols.add(symbol);
			}

		}
		return vftableSymbols;
	}
}
