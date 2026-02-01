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
package ghidra.program.model.lang;

import java.util.ArrayList;

import org.junit.*;

public class X64WinPrototypeModelTest extends AbstractProtoModelTest {

	@Before
	public void setUp() throws Exception {
		buildArchitecture("x86:LE:64:default:windows");
	}

	@Test
	public void testThisCall() throws Exception {
		PrototypeModel model = cspec.getCallingConvention("__thiscall");
		parseStructure("bigstruct", "int,int,int,int,int");
		PrototypePieces pieces = parseSignature(model, "bigstruct func(int *,int)");
		ArrayList<ParameterPieces> res = new ArrayList<>();
		model.assignParameterStorage(pieces, dtManager, res, true);
		Assert.assertEquals(res.size(), 4);
		Assert.assertTrue(res.get(2).hiddenReturnPtr);
		Assert.assertTrue(res.get(1).isThisPointer);
	}

}
