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

import org.junit.Before;
import org.junit.Test;

import ghidra.app.decompiler.DecompileOptions.NamespaceStrategy;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;

/**
 * This test is very similar in concept to {@link DecompilerFindReferencesToActionTest}, 
 * except that it uses input test data that has more than one level of dereferencing, such as:
 * <pre>
 * 	_printf("call_structure_A: %s\n",(a->b).name);
 * </pre>
 * 
 */
public class DecompilerFindReferencesToNestedStructureActionTest
		extends AbstractDecompilerFindReferencesActionTest {

	private static final String CALL_STRUCTURE_A_ADDRESS = "0x100000d60";

	@Override
	protected String getProgramName() {
		return "ghidra/app/extension/datatype/finder/functions_with_structure_usage.gzf";
	}

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();
		OptionsService service = provider.getTool().getService(OptionsService.class);
		ToolOptions opt = service.getOptions("Decompiler");
		opt.setEnum("Display.Display Namespaces", NamespaceStrategy.Never);
	}

	@Test
	public void testActionEnablementOnNestedStructureField() throws Exception {

		/*		 
			1|
			2| void _call_structure_A(A *a)
			3| 
			4| {
			5|   _printf("call_structure_A: %s\n",a->name);
			6|   _printf("call_structure_A: %s\n",(a->b).name);
			7|   _printf("call_structure_A: %s\n",(a->b).c.name);
			8|   _printf("call_structure_A: %s\n",(a->b).c.d.name);
			9|   _printf("call_structure_A: %s\n",(a->b).c.d.e.name);
		   10|  _call_structure_B(&a->b);
		   11|  return;
		   12| }
		   13| 
		
		 */
		decompile(CALL_STRUCTURE_A_ADDRESS);

		//
		// Action should not enabled unless on the data type
		// 
		// _printf("call_structure_A: %s\n",(a->b).name);
		//    b is char 37
		//    name is char 40
		//
		int line = 6;
		int charPosition = 37;
		setDecompilerLocation(line, charPosition);
		assertActionInPopup();

		charPosition = 40;
		setDecompilerLocation(line, charPosition);
		assertActionInPopup();

		//
		// _printf("call_structure_A: %s\n",(a->b).c.d.e.name);
		//    d is char 42
		//    . is char 43
		//    e is char 44
		//
		line = 9;
		charPosition = 42;
		setDecompilerLocation(line, charPosition);
		assertActionInPopup();

		charPosition = 43;
		setDecompilerLocation(line, charPosition);
		assertActionNotInPopup();

		charPosition = 44;
		setDecompilerLocation(line, charPosition);
		assertActionInPopup();
	}

	@Test
	public void testFindDataTypeReferences_ToNestedFieldOfDataType() throws Exception {

		/*		 
			1|
			2| void _call_structure_A(A *a)
			3| 
			4| {
			5|   _printf("call_structure_A: %s\n",a->name);
			6|   _printf("call_structure_A: %s\n",(a->b).name);
			7|   _printf("call_structure_A: %s\n",(a->b).c.name);
			8|   _printf("call_structure_A: %s\n",(a->b).c.d.name);
			9|   _printf("call_structure_A: %s\n",(a->b).c.d.e.name);
			10|  _call_structure_B(&a->b);
			11|  return;
			12| }
			13| 
		
		 */
		decompile(CALL_STRUCTURE_A_ADDRESS);

		//
		// _printf("call_structure_A: %s\n",(a->b).c.d.e.name);
		//    e is char 44
		//
		int line = 9;
		int charPosition = 44;
		setDecompilerLocation(line, charPosition);
		performFindDataTypes();

		assertFindAllReferencesToCompositeFieldWasCalled();
	}
}
