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
package ghidra.app.cmd.data.exceptionhandling;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAlignedPack4Structure;

import ghidra.app.cmd.data.AbstractCreateDataTypeModel;
import ghidra.app.cmd.data.EHDataTypeUtilities;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.scalar.Scalar;

/**
 * Model for exception handling information about the IpToStateMapEntry data type and its 
 * associated exception handling data types.
 * <br>
 * This is based on data type information from ehdata.h
 */
public class EHIPToStateModel extends AbstractCreateDataTypeModel {

	public static final String DATA_TYPE_NAME = "IPToStateMapEntry";
	private static String STRUCTURE_NAME = STRUCT_PREFIX + DATA_TYPE_NAME;

	private static final int IP_ORDINAL = 0;
	private static final int STATE_ORDINAL = 1;

	private DataType dataType;

	/**
	 * Creates the model for the exception handling IpToStateMapEntry data type.
	 * @param program the program
	 * @param ipToStateCount the number of IpToStateMapEntry data types expected at the map address.
	 * @param ipToStateMapAddress the address in the program for the map of IpToStateMapEntry data
	 * types.
	 */
	public EHIPToStateModel(Program program, int ipToStateCount, Address ipToStateMapAddress,
			DataValidationOptions validationOptions) {
		super(program, ipToStateCount, ipToStateMapAddress, validationOptions);
	}

	@Override
	public String getName() {
		return DATA_TYPE_NAME;
	}

	/**
	 * Whether or not the memory at the indicated address appears to be a valid location for the
	 * indicated number of ipToState map entry data types.
	 * @throws InvalidDataTypeException if this model's location does not appear to be a valid 
	 * group of ipToState map entries. The exception has a message indicating
	 * why it does not appear to be a valid location for the data type.
	 */
	@Override
	protected void validateModelSpecificInfo() throws InvalidDataTypeException {
		// Does each IP to State map entry refer to a valid address for the IP?
		Program program = getProgram();
		int numEntries = getCount();
		for (int ipToStateOrdinal = 0; ipToStateOrdinal < numEntries; ipToStateOrdinal++) {
			Object ip = getIP(ipToStateOrdinal);
			if (ip instanceof Address) {
				Address ipAddress = (Address) ip;
				if (!EHDataTypeUtilities.isValidAddress(program, ipAddress)) {
					throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
						" doesn't refer to a valid location for the IP.");
				}
			}
		}
	}

	/**
	 * This gets the IPToStateMap structure for the indicated program.
	 * @param program the program which will contain this data type. 
	 * @return the IPToStateMap structure.
	 */
	public static DataType getDataType(Program program) {

		DataTypeManager dataTypeManager = program.getDataTypeManager();
		boolean isRelative = isRelative(program);
		CategoryPath categoryPath = new CategoryPath(CATEGORY_PATH);
		StructureDataType struct =
			getAlignedPack4Structure(dataTypeManager, categoryPath, STRUCTURE_NAME);

		// Add the components.
		DataType compDt;

		/* comps[0] */
		if (isRelative) {
			compDt = new ImageBaseOffset32DataType(dataTypeManager);
		}
		else {
			DataType dwordDt = new TypedefDataType(new CategoryPath("/WinDef.h"), "DWORD",
				new UnsignedLongDataType(dataTypeManager), dataTypeManager);
			compDt = new TypedefDataType(new CategoryPath("/wtypes.h"), "ULONG", dwordDt,
				dataTypeManager);
		}
		struct.add(compDt, "Ip", null);

		/* comps[1] */
		DataType ehStateDt = MSDataTypeUtils.getEHStateDataType(program);
		struct.add(ehStateDt, "state", null);

		TypedefDataType typedefDt =
			new TypedefDataType(categoryPath, DATA_TYPE_NAME, struct, dataTypeManager);

		return MSDataTypeUtils.getMatchingDataType(program, typedefDt);
	}

	/**
	 * This gets the IPToStateMap structure for this model.
	 * @return the IPToStateMap structure.
	 */
	@Override
	public DataType getDataType() {
		if (dataType == null) {
			dataType = getDataType(getProgram());
		}
		return dataType;
	}

	@Override
	protected int getDataTypeLength() {
		return getDataType().getLength();
	}

	/**
	 * Gets the IP value for the IP To State map as either an address of IP or as an IP value, 
	 * if there is one, in the IpToStateMapEntry indicated by the ordinal.
	 * @param ipToStateOrdinal 0-based ordinal indicating which IpToStateMapEntry in the map.
	 * @return the IP value (as either an Address or a Scalar) for IP To State map.
	 * @throws InvalidDataTypeException if valid IPToStateEntry data can't be created for 
	 * the indicated ordinal.
	 */
	public Object getIP(int ipToStateEntryOrdinal) throws InvalidDataTypeException {
		checkValidity(ipToStateEntryOrdinal);
		DataType ipToStateDt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(ipToStateEntryOrdinal, ipToStateDt);
		// component 0 is ULONG or displacement.

		if (isRelative()) { // displacement
			Address refAddress =
				EHDataTypeUtilities.getAddress(ipToStateDt, IP_ORDINAL, specificMemBuffer);
			return getAdjustedAddress(refAddress, 0);
		}

		// ULONG  - Does this actually represent an address?
		Scalar scalarValue =
			EHDataTypeUtilities.getScalarValue(ipToStateDt, IP_ORDINAL, specificMemBuffer);
		return scalarValue;
	}

	/**
	 * Gets the address of the component containing the IP To State address, if there is one 
	 * in the IpToStateMapEntry indicated by the ordinal. 
	 * Otherwise, this returns null.
	 * @param ipToStateOrdinal 0-based ordinal indicating which IpToStateMapEntry in the map.
	 * @return the address of the component with the IP To State address or null.
	 * @throws InvalidDataTypeException if valid IPToStateEntry data can't be created for 
	 * the indicated ordinal.
	 */
	public Address getComponentAddressOfIPAddress(int ipToStateEntryOrdinal)
			throws InvalidDataTypeException {
		checkValidity(ipToStateEntryOrdinal);
		DataType dt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(ipToStateEntryOrdinal, dt);
		// component 0 is ULONG or displacement.
		return EHDataTypeUtilities.getComponentAddress(dt, IP_ORDINAL, specificMemBuffer);
	}

	/**
	 * Gets the state value, if there is one, in the IpToStateMapEntry indicated by the ordinal.
	 * @param ipToStateOrdinal 0-based ordinal indicating which IpToStateMapEntry in the map.
	 * @return the state value.
	 * @throws InvalidDataTypeException if valid IPToStateEntry data can't be created for 
	 * the indicated ordinal.
	 */
	public int getState(int ipToStateEntryOrdinal) throws InvalidDataTypeException {
		checkValidity(ipToStateEntryOrdinal);
		DataType ipToStateDt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(ipToStateEntryOrdinal, ipToStateDt);
		// component 1 is state value.
		return EHDataTypeUtilities.getEHStateValue(ipToStateDt, STATE_ORDINAL, specificMemBuffer);
	}
}
