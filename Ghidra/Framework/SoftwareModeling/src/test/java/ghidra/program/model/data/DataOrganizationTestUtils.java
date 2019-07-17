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

/**
 * <code>DataOrganizationTestUtils</code> provides various methods for modifying
 * a DataOrganization to reflect a specific processor/compiler spec.  This can be used 
 * when only the DataOrganization is needed and not the Language/CompilerSpec.
 */
public class DataOrganizationTestUtils {

	private DataOrganizationTestUtils() {
		// no construct
	}

	/**
	 * Initialize data organization to reflect x86-64-win.cspec specification
	 * @param dataOrg data organization
	 */
	public static void initDataOrganizationWindows64BitX86(DataOrganizationImpl dataOrg) {

		dataOrg.setBigEndian(false);

		dataOrg.setAbsoluteMaxAlignment(0);
		dataOrg.setMachineAlignment(2);
		dataOrg.setDefaultAlignment(1);
		dataOrg.setDefaultPointerAlignment(8);
		dataOrg.setPointerSize(8);
		dataOrg.setWideCharSize(2);
		dataOrg.setShortSize(2);
		dataOrg.setIntegerSize(4);
		dataOrg.setLongSize(4);
		dataOrg.setLongLongSize(8);
		dataOrg.setFloatSize(4);
		dataOrg.setDoubleSize(8);
		dataOrg.setLongDoubleSize(8);
		dataOrg.setSizeAlignment(1, 1);
		dataOrg.setSizeAlignment(2, 2);
		dataOrg.setSizeAlignment(4, 4);
		dataOrg.setSizeAlignment(8, 8);

		BitFieldPackingImpl bitFieldPacking = new BitFieldPackingImpl();
		bitFieldPacking.setUseMSConvention(true);
		dataOrg.setBitFieldPacking(bitFieldPacking);
	}

	/**
	 * Initialize data organization to reflect x86-64-gcc.cspec specification
	 * @param dataOrg data organization
	 */
	public static void initDataOrganizationGcc64BitX86(DataOrganizationImpl dataOrg) {

		dataOrg.setBigEndian(false);

		dataOrg.setAbsoluteMaxAlignment(0);
		dataOrg.setMachineAlignment(2);
		dataOrg.setDefaultAlignment(1);
		dataOrg.setDefaultPointerAlignment(8);
		dataOrg.setPointerSize(8);
		dataOrg.setWideCharSize(4);
		dataOrg.setShortSize(2);
		dataOrg.setIntegerSize(4);
		dataOrg.setLongSize(8);
		dataOrg.setLongLongSize(8);
		dataOrg.setFloatSize(4);
		dataOrg.setDoubleSize(8);
		dataOrg.setLongDoubleSize(16);
		dataOrg.setSizeAlignment(1, 1);
		dataOrg.setSizeAlignment(2, 2);
		dataOrg.setSizeAlignment(4, 4);
		dataOrg.setSizeAlignment(8, 8);

		BitFieldPackingImpl bitFieldPacking = new BitFieldPackingImpl(); // use defaults
		dataOrg.setBitFieldPacking(bitFieldPacking);
	}

	/**
	 * Initialize data organization to reflect big-endian mips32.cspec specification (MIPS 32-bit)
	 * @param dataOrg data organization
	 */
	public static void initDataOrganization32BitMips(DataOrganizationImpl dataOrg) {

		dataOrg.setBigEndian(true);

		dataOrg.setPointerSize(4);

		dataOrg.setFloatSize(4);
		dataOrg.setDoubleSize(8);
		dataOrg.setLongDoubleSize(8);

		dataOrg.setSizeAlignment(1, 1);
		dataOrg.setSizeAlignment(2, 2);
		dataOrg.setSizeAlignment(4, 4);
		dataOrg.setSizeAlignment(8, 8);

		BitFieldPackingImpl bitFieldPacking = new BitFieldPackingImpl(); // use defaults
		dataOrg.setBitFieldPacking(bitFieldPacking);
	}
}
