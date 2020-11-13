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

import ghidra.app.plugin.core.data.ProgramProviderContext;
import ghidra.app.plugin.core.data.ProgramStructureProviderContext;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.DataTypeProviderContext;
import ghidra.program.model.listing.*;

/**
 * Creates and initializes {@link Structure} objects.
 * 
 * 
 */
public class StructureFactory {
	public static final String DEFAULT_STRUCTURE_NAME = "struct";

	/**
	 * Creates a {@link StructureDataType} instance based upon the information
	 * provided.  The instance will not be placed in memory.
	 * <p>
	 * This method is just a pass-through method for 
	 * {@link #createStructureDataType(Program,Address,int,String,boolean)}
	 * equivalent to calling:
	 * <pre>
	 *      Structure newStructure = StructureFactory.createStructureDataType(
	 *          program, address, dataLength, DEFAULT_STRUCTURE_NAME, true );
	 * </pre>
	 * 
	 * @param  program The program to which the structure will belong.
	 * @param  address The address of the structure.
	 * @param  dataLength The number of components to add to the structure.
	 * @return A new structure not yet added to memory.
	 * @throws IllegalArgumentException for the following conditions:
	 *         <ul>
	 *              <li>if <code>dataLength</code> is not greater than zero
	 *              <li>if the number of components to add exceeds the available
	 *                  address space
	 *              <li>if there are any instructions in the provided 
	 *                  address space
	 *              <li>if there are no data components to add to the structure
	 *         </ul>
	 */
	public static Structure createStructureDataType(Program program, Address address,
			int dataLength) {
		return createStructureDataType(program, address, dataLength, DEFAULT_STRUCTURE_NAME, true);
	}

	/**
	 * Creates a {@link StructureDataType} instance based upon the information
	 * provided.  The instance will not be placed in memory.
	 * 
	 * @param  program The program to which the structure will belong.
	 * @param  address The address of the structure.
	 * @param  dataLength The number of components to add to the structure.
	 * @param  structureName The name of the structure to create.
	 * @param  makeUniqueName True indicates that the provided name should be
	 *         altered as necessary in order to make it unique in the program.
	 * @return A new structure not yet added to memory.
	 * @throws IllegalArgumentException for the following conditions:
	 *         <ul>
	 *              <li>if <code>structureName</code> is <code>null</code>
	 *              <li>if <code>dataLength</code> is not greater than zero
	 *              <li>if the number of components to add exceeds the available
	 *                  address space
	 *              <li>if there are any instructions in the provided 
	 *                  address space
	 *              <li>if there are no data components to add to the structure
	 *         </ul>
	 */
	public static Structure createStructureDataType(Program program, Address address,
			int dataLength, String structureName, boolean makeUniqueName) {

		if (structureName == null) {
			throw new IllegalArgumentException("Structure name cannot " + "be null.");
		}

		if (dataLength <= 0) {
			throw new IllegalArgumentException(
				"Structure length must be positive, not " + dataLength);
		}

		Address endAddress;
		try {
			endAddress = address.addNoWrap(dataLength - 1);
		}
		catch (AddressOverflowException e1) {
			throw new IllegalArgumentException(
				"Can't create structure because length exceeds address " + "space" + dataLength);
		}

		AddressSet set = new AddressSet(address, endAddress);
		InstructionIterator iter = program.getListing().getInstructions(set, true);
		if (iter.hasNext()) {
			throw new IllegalArgumentException(
				"Can't create structure because the current selection " + "contains instructions");
		}

		DataTypeProviderContext providerContext = new ProgramProviderContext(program, address);

		String name = structureName;
		if (makeUniqueName) {
			name = providerContext.getUniqueName(name);
		}

		Structure newStructure = new StructureDataType(name, 0, program.getDataTypeManager());

		initializeStructureFromContext(newStructure, providerContext, dataLength);

		return newStructure;
	}

	/**
	 * Creates a {@link StructureDataType} instance, which is inside of 
	 * another structure, based upon the information provided.  The instance 
	 * will not be placed in memory.
	 * <p>
	 * This method is just a pass-through method for 
	 * {@link #createStructureDataTypeInStrucuture(Program,Address,int[],int[],String,boolean)}
	 * equivalent to calling:
	 * <pre>
	 *      Structure newStructure = StructureFactory.createStructureDataTypeInStrucuture(
	 *          program, address, fromPath, toPath, DEFAULT_STRUCTURE_NAME, true );
	 * </pre>
	 * 
	 * @param  program The program to which the structure will belong.
	 * @param  address The address of the structure.
	 * @param  fromPath The path to the first element in the parent structure
	 *         that will be in the new structure.
	 * @param  toPath The path to the last element in the parent structure
	 *         that will be in the new structure.
	 * @return A new structure not yet added to memory.
	 * @throws IllegalArgumentException for the following conditions:
	 *         <ul>
	 *              <li>if the component at <code>fromPath</code> or the component
	 *                  at <code>toPath</code> are null
	 *              <li>if there is not data to add to the structure
	 *              <li>if the parent data type is not a structure
	 *         </ul>
	 */
	public static Structure createStructureDataTypeInStrucuture(Program program, Address address,
			int[] fromPath, int[] toPath) {

		return createStructureDataTypeInStrucuture(program, address, fromPath, toPath,
			DEFAULT_STRUCTURE_NAME, true);
	}

	/**
	 * Creates a {@link StructureDataType} instance, which is inside of 
	 * another structure, based upon the information provided.  The instance 
	 * will not be placed in memory.
	 * 
	 * @param  program The program to which the structure will belong.
	 * @param  address The address of the structure.
	 * @param  fromPath The path to the first element in the parent structure
	 *         that will be in the new structure.
	 * @param  toPath The path to the last element in the parent structure
	 *         that will be in the new structure.
	 * @param  structureName the name of the structure to create
	 * @param  makeUniqueName True indicates that the provided name should be
	 *         altered as necessary in order to make it unique in the program.
	 * @return A new structure not yet added to memory.
	 * @throws IllegalArgumentException for the following conditions:
	 *         <ul>
	 *              <li>if <code>structureName</code> is <code>null</code>
	 *              <li>if the component at <code>fromPath</code> or the component
	 *                  at <code>toPath</code> are null
	 *              <li>if there is not data to add to the structure
	 *              <li>if the parent data type is not a structure
	 *         </ul>
	 */
	public static Structure createStructureDataTypeInStrucuture(Program program, Address address,
			int[] fromPath, int[] toPath, String structureName, boolean makeUniqueName) {

		if (structureName == null) {
			throw new IllegalArgumentException("Structure name cannot " + "be null.");
		}

		Listing listing = program.getListing();

		Data data = listing.getDataContaining(address);
		Data comp1 = data.getComponent(fromPath);
		Data comp2 = data.getComponent(toPath);
		if ((comp1 == null) || (comp2 == null)) {
			throw new IllegalArgumentException("Invalid selection");
		}

		int dataLength = (comp2.getParentOffset() + comp2.getLength()) - comp1.getParentOffset();
		if (dataLength <= 0) {
			throw new IllegalArgumentException("Data length must be positive, not " + dataLength);
		}

		// make sure there is a valid parent structure
		Data firstComponent = data.getComponent(fromPath);
		DataType parentDataType = firstComponent.getParent().getBaseDataType();
		if (!(parentDataType instanceof Structure)) {
			throw new IllegalArgumentException("New structure is not in a structure");
		}

		// create the context
		DataTypeProviderContext providerContext = new ProgramStructureProviderContext(program,
			data.getMinAddress(), (Structure) parentDataType, comp1.getParentOffset());

		String name = structureName;
		if (makeUniqueName) {
			name = providerContext.getUniqueName(name);
		}

		Structure newStructure = new StructureDataType(name, 0, program.getDataTypeManager());

		initializeStructureFromContext(newStructure, providerContext, dataLength);

		return newStructure;
	}

	// uses the provided context to initiailze the provided structure with 
	// dataLength number of components
	private static void initializeStructureFromContext(Structure structure,
			DataTypeProviderContext context, int dataLength) {

		DataTypeComponent[] dataComps = context.getDataTypeComponents(0, dataLength - 1);

		if (dataComps.length == 0) {
			throw new IllegalArgumentException("No data type components found");
		}

		for (int i = 0; i < dataComps.length; i++) {
			structure.add(dataComps[i].getDataType(), dataComps[i].getLength(),
				dataComps[i].getFieldName(), dataComps[i].getComment());
		}
	}
}
