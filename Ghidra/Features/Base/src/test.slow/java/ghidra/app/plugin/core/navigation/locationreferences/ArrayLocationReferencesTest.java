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
package ghidra.app.plugin.core.navigation.locationreferences;

import static ghidra.GhidraOptions.CATEGORY_BROWSER_FIELDS;
import static ghidra.app.util.viewer.format.FormatManager.ARRAY_DISPLAY_OPTIONS;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.util.viewer.field.ArrayElementWrappedOption;
import ghidra.framework.options.CustomOption;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DWordDataType;

public class ArrayLocationReferencesTest extends AbstractLocationReferencesTest {

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();

		setOptionsToRenderArraysVertically();
	}

	@Test
	public void testArrayReferences_MnemonicField_NoOffcuts() {
		//
		// Find all references to the array.  With all references pointing to the min address
		// of array elements, none of the results should report being offcut.
		// 

		/*
		 	Disassembly:
		 	
		 				DWORD_ARRAY_010054e8[1]   XREF[1,2]:   01005300(R), 01005301(R), 
		                DWORD_ARRAY_010054e8[2]                01005302(R)  
		                DWORD_ARRAY_010054e8
		    010054e8 00 00 00        ddw[3]
		             00 00 00 
		             00 00 00 
		       010054e8 00 00 00 00     ddw       0h  [0] XREF[1]:     01005300(R)  
		       010054ec 00 00 00 00     ddw       0h  [1] XREF[1]:     01005301(R)  
		       010054f0 00 00 00 00     ddw       0h  [2] XREF[1]:     01005302(R)  
		
		 */

		// go to an unused address
		Address arrayAddr = addr(0x010054e8);

		createArray_WithoutOffcuts(arrayAddr);

		goToDataMnemonicField(arrayAddr);

		search();

		List<LocationReference> results = getResultLocations();

		// we searched on the mnemonic--the results should be the 3 direct refs and the 
		// data type refs of each array element
		assertContainsAddrs(results, addr("01005300"), addr("01005301"), addr("01005302"));
		assertContainsAddrs(results, addr("010054e8"));

		// Note: these addresses are *not* found, as we do not search the elements of the array.
		//       This is by design, as it saves a lot of work.
		// addr("010054ec"), addr("010054f0"));

		assertNoOffcuts(results);
	}

	@Test
	public void testArrayReferences_MnemonicField_Offcuts() {
		//
		// Find all references to the array.  With all references pointing to the min address
		// of array elements, some of the results should report being offcut.
		// 

		/*
		 	Disassembly:
		 	
		 				// 2 offcuts
		 				DWORD_ARRAY_010054e8[1]+1    XREF[1,2]:   01005300(R), 01005301(R), 
		             	DWORD_ARRAY_010054e8[2]+1                 01005302(R)  
		             	DWORD_ARRAY_010054e8
		   010054e8 00 00 00        ddw[3]
		         	 00 00 00 
		         	 00 00 00 
			   010054e8 00 00 00 00     ddw       0h [0] XREF[1]:     01005300(R)  
			   010054ec 00 00 00 00     ddw       0h [1] XREF[0,1]:   01005301(R)   // offuct
			   010054f0 00 00 00 00     ddw       0h [2] XREF[0,1]:   01005302(R)   // offuct		
		 */

		// go to an unused address
		Address arrayAddr = addr(0x010054e8);

		createArray_WithOffcuts(arrayAddr);

		goToDataMnemonicField(arrayAddr);

		search();

		List<LocationReference> results = getResultLocations();

		// we searched on the mnemonic--the results should be the 3 direct refs and the 
		// data type refs of each array element
		assertContainsAddrs(results, addr("01005300"), addr("01005301"), addr("01005302"));
		assertContainsAddrs(results, addr("010054e8"));

		// Note: these addresses are *not* found, as we do not search the elements of the array.
		//       This is by design, as it saves a lot of work.
		// addr("010054ec"), addr("010054f0"));

		assertOffcut(results, addr("01005301"), addr("01005302"));
		assertNotOffcut(results, addr("01005300"), addr("010054e8"), addr("010054ec"),
			addr("010054f0"));
	}

	@Test
	public void testArrayReferences_AddressField_NoOffcuts() {
		//
		// Find all references to the array.  With all references pointing to the min address
		// of array elements, none of the results should report being offcut.
		// 

		/*
		 	Disassembly:
		 	
		 				DWORD_ARRAY_010054e8[1]   XREF[1,2]:   01005300(R), 01005301(R), 
		                DWORD_ARRAY_010054e8[2]                01005302(R)  
		                DWORD_ARRAY_010054e8
		    010054e8 00 00 00        ddw[3]
		             00 00 00 
		             00 00 00 
		       010054e8 00 00 00 00     ddw       0h  [0] XREF[1]:     01005300(R)  
		       010054ec 00 00 00 00     ddw       0h  [1] XREF[1]:     01005301(R)  
		       010054f0 00 00 00 00     ddw       0h  [2] XREF[1]:     01005302(R)  
		
		 */

		// go to an unused address
		Address arrayAddr = addr(0x010054e8);

		createArray_WithoutOffcuts(arrayAddr);

		goToDataAddressField(arrayAddr);

		search();

		List<LocationReference> results = getResultLocations();
		assertContains(results, addr("01005300"), addr("01005301"), addr("01005302"));
		assertNoOffcuts(results);
	}

	@Test
	public void testArrayReferences_AddressField_Offcuts() {
		//
		// Find all references to the array.  With all references pointing to the min address
		// of array elements, some of the results should report being offcut.
		// 

		/*
		 	Disassembly:
		 	
		 				// 2 offcuts
		 				DWORD_ARRAY_010054e8[1]+1    XREF[1,2]:   01005300(R), 01005301(R), 
		             	DWORD_ARRAY_010054e8[2]+1                 01005302(R)  
		             	DWORD_ARRAY_010054e8
		   010054e8 00 00 00        ddw[3]
		         	 00 00 00 
		         	 00 00 00 
			   010054e8 00 00 00 00     ddw       0h [0] XREF[1]:     01005300(R)  
			   010054ec 00 00 00 00     ddw       0h [1] XREF[0,1]:   01005301(R)   // offuct
			   010054f0 00 00 00 00     ddw       0h [2] XREF[0,1]:   01005302(R)   // offuct		
		 */

		Address arrayAddr = addr(0x010054e8);

		createArray_WithOffcuts(arrayAddr);

		goToDataAddressField(arrayAddr);

		search();

		List<LocationReference> results = getResultLocations();
		assertContains(results, addr("01005300"), addr("01005301"), addr("01005302"));
		assertOffcut(results, addr("01005301"), addr("01005302"));
		assertNotOffcut(results, addr("01005300"));
	}

	@Test
	public void testArrayElementReferences_AddressField_FirstElement() {
		//
		// Only find references to the actual array element, not the entire array. 
		//

		/*
		Disassembly:
		
					DWORD_ARRAY_010054e8[1]   XREF[1,2]:   01005300(R), 01005301(R), 
		            DWORD_ARRAY_010054e8[2]                01005302(R)  
		            DWORD_ARRAY_010054e8
		   010054e8 00 00 00        ddw[3]
		         00 00 00 
		         00 00 00                        (row)
			   010054e8 00 00 00 00     ddw       0h  [0] XREF[1]:     01005300(R)  
			   010054ec 00 00 00 00     ddw       0h  [1] XREF[1]:     01005301(R)  
			   010054f0 00 00 00 00     ddw       0h  [2] XREF[1]:     01005302(R)  
		
		*/

		// go to an unused address
		Address arrayAddr = addr(0x010054e8);

		createArray_WithoutOffcuts(arrayAddr);

		// same address; first child row; element [0]
		int row = 0;
		goToDataAddressField(arrayAddr, row);

		search();

		List<LocationReference> results = getResultLocations();

		// we searched on the address field--the results should be the 1 direct ref to the
		// first array element.
		assertContains(results, addr("01005300"));
	}

	@Test
	public void testArrayElementReferences_AddressField_SecondElement() {
		//
		// Only find references to the actual array element, not the entire array. 
		//

		/*
		Disassembly:
		
					DWORD_ARRAY_010054e8[1]   XREF[1,2]:   01005300(R), 01005301(R), 
		            DWORD_ARRAY_010054e8[2]                01005302(R)  
		            DWORD_ARRAY_010054e8
		   010054e8 00 00 00        ddw[3]
		         00 00 00 
		         00 00 00                        (row)
			   010054e8 00 00 00 00     ddw       0h  [0] XREF[1]:     01005300(R)  
			   010054ec 00 00 00 00     ddw       0h  [1] XREF[1]:     01005301(R)  
			   010054f0 00 00 00 00     ddw       0h  [2] XREF[1]:     01005302(R)  
		
		*/

		// go to an unused address
		Address arrayAddr = addr(0x010054e8);

		createArray_WithoutOffcuts(arrayAddr);

		goToDataAddressField(addr(0x010054ec)); // element [1]

		search();

		List<LocationReference> results = getResultLocations();

		// we searched on the address field--the results should be the 1 direct ref to the
		// second array element.
		assertContains(results, addr("01005301"));
	}

	@Test
	public void testOperandReferenceToArray() {

		/*
		 	Disassembly:
		 	
		 	The Instruction:
		 												\/
		 	 01002252 b9 81 00        MOV        ECX=>DWORD_ARRAY_010054e8,0x81                   = 
		         00 00
		
		
		 	The Array:
		 	
		 				DWORD_ARRAY_010054e8[1]   XREF[1,2]:   01005300(R), 01005301(R), 
		                DWORD_ARRAY_010054e8[2]                01005302(R)  
		                DWORD_ARRAY_010054e8
		    010054e8 00 00 00        ddw[3]
		             00 00 00 
		             00 00 00 
		       010054e8 00 00 00 00     ddw       0h  [0] XREF[1]:     01005300(R)  
		       010054ec 00 00 00 00     ddw       0h  [1] XREF[1]:     01005301(R)  
		       010054f0 00 00 00 00     ddw       0h  [2] XREF[1]:     01005302(R)  
		
		 */

		// go to an unused address
		Address arrayAddr = addr(0x010054e8);

		DWordDataType dt = new DWordDataType();
		int length = dt.getLength();
		ArrayDataType array = new ArrayDataType(dt, 3, length);
		createData(arrayAddr, array);

		Address instructionAddr = addr(0x01002252);
		int arrayLabelColumn = 8; // somewhere in DWORD_ARRAY
		goToOperandField(instructionAddr, arrayLabelColumn);
		createReference(instructionAddr, arrayAddr);

		search();

		List<LocationReference> results = getResultLocations();
		assertContainsAddrs(results, instructionAddr);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void assertNoOffcuts(List<LocationReference> results) {
		for (LocationReference ref : results) {
			String context = getContextColumnValue(ref);
			assertThat(context, not(containsString("OFFCUT")));
		}
	}

	private void assertOffcut(List<LocationReference> list, Address... expected) {
		assertOffcutMatches(list, true, expected);
	}

	private void assertNotOffcut(List<LocationReference> list, Address... expected) {
		assertOffcutMatches(list, false, expected);
	}

	private void assertOffcutMatches(List<LocationReference> list, boolean expectOffcut,
			Address... expected) {

		String errorPrefix = expectOffcut ? "Offcut expected but not found"
				: "Found offcut when it was not expected";

		//@formatter:off
		list.stream()
		    .filter(ref -> {			
		    		Address addr = ref.getLocationOfUse();
		    		boolean contains = Arrays.asList(expected).contains(addr);
		    		return contains;
		    	})
		    .collect(Collectors.toList())
		    .forEach(ref -> {
		    		String context = getContextColumnValue(ref);
		    		assertEquals(errorPrefix + ": " + ref, expectOffcut, context.contains("OFFCUT"));
		    })
		    ;
		//@formatter:on
	}

	private void assertContainsAddrs(List<LocationReference> list, Address... expected) {
		for (Address addr : expected) {
			assertContainsAddr(list, addr);
		}
	}

	private void createArray_WithoutOffcuts(Address addr) {

		DWordDataType dt = new DWordDataType();
		int length = dt.getLength();
		ArrayDataType array = new ArrayDataType(dt, 3, length);

		createData(addr, array);

		Address element1Addr = addr;
		Address from1 = addr(0x01005300);
		createReference(from1, element1Addr);

		Address element2Addr = element1Addr.add(length);
		Address from2 = addr(0x01005301);
		createReference(from2, element2Addr);

		Address element3Addr = element2Addr.add(length);
		Address from3 = addr(0x01005302);
		createReference(from3, element3Addr);
	}

	private void createArray_WithOffcuts(Address addr) {

		DWordDataType dt = new DWordDataType();
		int length = dt.getLength();
		ArrayDataType array = new ArrayDataType(dt, 3, length);

		createData(addr, array);

		Address element1Addr = addr;
		Address from1 = addr(0x01005300);
		createReference(from1, element1Addr);

		Address element2Addr = element1Addr.add(length);
		Address from2 = addr(0x01005301);
		createReference(from2, element2Addr.add(1)); // offcut

		Address element3Addr = element2Addr.add(length);
		Address from3 = addr(0x01005302);
		createReference(from3, element3Addr.add(1)); // offcut
	}

	private void setOptionsToRenderArraysVertically() {

		ToolOptions options = tool.getOptions(CATEGORY_BROWSER_FIELDS);

		CustomOption option = options.getCustomOption(ARRAY_DISPLAY_OPTIONS, null);
		assertNotNull(option);
		ArrayElementWrappedOption arrayOption = (ArrayElementWrappedOption) option;
		arrayOption.setShowMultipleArrayElementPerLine(false);

		runSwing(() -> {
			options.setCustomOption(ARRAY_DISPLAY_OPTIONS, arrayOption);
		});
	}

}
