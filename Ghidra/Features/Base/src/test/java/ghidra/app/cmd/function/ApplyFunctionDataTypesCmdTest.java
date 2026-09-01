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
package ghidra.app.cmd.function;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGuiTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.*;
import ghidra.test.ToyProgramBuilder;

public class ApplyFunctionDataTypesCmdTest extends AbstractGuiTest {

	@Test
	public void testImportedArchiveMatchingRespectsNamespaces() throws Exception {
		ProgramBuilder builder = new ToyProgramBuilder("Test", false, this);
		builder.createMemory(".text", "0x1000", 0x100);

		Function globalFunction = builder.createEmptyFunction("SetBkMode", "0x1000", 1,
			VoidDataType.dataType);
		Function namespacedFunction = builder.createEmptyFunction("SetBkMode",
			"CGdiGraphicContext", "0x1010", 1, VoidDataType.dataType);
		ExternalLocation externalFunction =
			builder.createExternalFunction(null, "USER32.DLL", "SetBkMode");

		assertTrue(ApplyFunctionDataTypesCmd.isArchiveSignatureCandidate(
			globalFunction.getSymbol(), SourceType.IMPORTED));
		assertFalse(ApplyFunctionDataTypesCmd.isArchiveSignatureCandidate(
			namespacedFunction.getSymbol(), SourceType.IMPORTED));
		assertTrue(ApplyFunctionDataTypesCmd.isArchiveSignatureCandidate(
			externalFunction.getSymbol(), SourceType.IMPORTED));

		// Explicit/manual application uses USER_DEFINED and keeps the existing ability to target
		// namespaced methods deliberately.
		assertTrue(ApplyFunctionDataTypesCmd.isArchiveSignatureCandidate(
			namespacedFunction.getSymbol(), SourceType.USER_DEFINED));
	}
}
