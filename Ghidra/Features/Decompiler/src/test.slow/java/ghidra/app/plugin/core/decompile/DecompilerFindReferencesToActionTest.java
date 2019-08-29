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
package ghidra.app.plugin.core.decompile;

import org.junit.Test;

public class DecompilerFindReferencesToActionTest
		extends AbstractDecompilerFindReferencesActionTest {

	private static final long INIT_STRING_ADDR = 0X080483c7;

	@Override
	protected String getProgramName() {
		return "elf/CentOS/32bit/decomp.gzf";
	}

	@Test
	public void testActionEnablement() throws Exception {

		/*
		 
		 Decomp of 'init_string':
		 
		 	1|
			2| void init_string(mystring *ptr)
			3|
			4| {
			5|   ptr->alloc = 0;
			6|   return;
			7| }
			8|
		 
		 Note: there are two places in this function we can search for data type references:
		 		1) the parameter (line 2, cols 17-25, 26-30)
		 		2) the usage of the parameter: (line 5 at cols 2-5 for the type and cols 7-12 for the field)
		 
		 */
		decompile(INIT_STRING_ADDR);

		//
		// Action should not enabled unless on the data type
		// 
		// Empty line
		int line = 1;
		int charPosition = 0;
		setDecompilerLocation(line, charPosition);
		assertActionNotInPopup();

		// Signature - return statement
		line = 2;
		charPosition = 0;
		setDecompilerLocation(line, charPosition);
		assertActionInPopup();

		// Signature - first param; a data type
		line = 2;
		charPosition = 17;
		setDecompilerLocation(line, charPosition);
		assertActionInPopup();

		// Signature - first param name
		line = 2;
		charPosition = 26;
		setDecompilerLocation(line, charPosition);
		assertActionInPopup();

		// Syntax - {
		line = 4;
		charPosition = 0;
		setDecompilerLocation(line, charPosition);
		assertActionNotInPopup();

		// Data access - the data type itself
		line = 5;
		charPosition = 2;
		setDecompilerLocation(line, charPosition);
		assertActionInPopup();

		// Data access - the data type field dereference
		line = 5;
		charPosition = 7;
		setDecompilerLocation(line, charPosition);
		assertActionInPopup();
	}

	@Test
	public void testFindDataTypeReferences_ToEntireDataType_FromParameter() throws Exception {
		/*
		 
		 Decomp of 'init_string':
		 
		 	1|
			2| void init_string(mystring *ptr)
			3|
			4| {
			5|   ptr->alloc = 0;
			6|   return;
			7| }
			8|
		 
		 Note: there are two places in this function we can search for data type references:
		 		1) the parameter (line 2, cols 17-25, 26-30)
		 		2) the usage of the parameter: (line 5 at cols 2-5 for the type and cols 7-12 for the field)
		 
		 */

		decompile(INIT_STRING_ADDR);

		int line = 2;
		int charPosition = 17;
		setDecompilerLocation(line, charPosition);
		performFindDataTypes();

		assertFindAllReferencesToDataTypeWasCalled();
	}

	@Test
	public void testFindDataTypeReferences_ToEntireDataType_FromVariable() throws Exception {
		/*
		 
		 Decomp of 'init_string':
		 
		 	1|
			2| void init_string(mystring *ptr)
			3|
			4| {
			5|   ptr->alloc = 0;
			6|   return;
			7| }
			8|
		 
		 Note: there are two places in this function we can search for data type references:
		 		1) the parameter (line 2, cols 17-25, 26-30)
		 		2) the usage of the parameter: (line 5 at cols 2-5 for the type and cols 7-12 for the field)
		 
		 */

		decompile(INIT_STRING_ADDR);

		int line = 5;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);
		performFindDataTypes();

		assertFindAllReferencesToDataTypeWasCalled();
	}

	@Test
	public void testFindDataTypeReferences_ToFieldOfDataType() throws Exception {
		/*
		 
		 Decomp of 'init_string':
		 
		 	1|
			2| void init_string(mystring *ptr)
			3|
			4| {
			5|   ptr->alloc = 0;
			6|   return;
			7| }
			8|
		 
		 Note: there are two places in this function we can search for data type references:
		 		1) the parameter (line 2, cols 17-25, 26-30)
		 		2) the usage of the parameter: (line 5 at cols 2-5 for the type and cols 7-12 for the field)
		 
		 */

		decompile(INIT_STRING_ADDR);

		int line = 5;
		int charPosition = 7;
		setDecompilerLocation(line, charPosition);
		performFindDataTypes();

		assertFindAllReferencesToCompositeFieldWasCalled();
	}

	@Test
	public void testFindDataTypeReferences_ToCastSymbol() throws Exception {

		// void lzw_decompress(mytable *table,char *intstream,int len,char *output)
		// output = (char *)output_string(output,&local_2c);

		decompile(0x0804873f); // lzw_decompress()

		int line = 18;
		int charPosition = 11;
		setDecompilerLocation(line, charPosition);
		performFindDataTypes();

		assertFindAllReferencesToDataTypeWasCalled();
	}

	@Test
	public void testFindDataTypeReferences_ToCurrentAddress() throws Exception {

		/*
		 
		 Decomp of 'init_string':
		 
		 	1|
			2| void init_string(mystring *ptr)
			3|
			4| {
			5|   ptr->alloc = 0;
			6|   return;
			7| }
			8|
		 */

		decompile(INIT_STRING_ADDR);

		int line = 5;
		int charPosition = 7;
		setDecompilerLocation(line, charPosition);
		performFindReferencesToAddress();

		assertFindAllReferencesToAddressWasCalled();
	}

	@Test
	public void testFindDataTypeReferences_ToCurrentFunction() throws Exception {

		decompile(INIT_STRING_ADDR);

		int line = 2;
		int charPosition = 10; // function name
		setDecompilerLocation(line, charPosition);
		performFindReferencesToSymbol();

		assertFindAllReferencesToSymbolWasCalled();
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

}
