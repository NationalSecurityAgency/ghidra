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
package ghidra.feature.vt.api;

import org.junit.Test;

import ghidra.feature.vt.api.correlator.program.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.*;

public class BasicSelfSimilarCorrelatorTest extends AbstractSelfSimilarCorrelatorTest {
	public BasicSelfSimilarCorrelatorTest() {
		super();
	}

@Test
    public void testExactBytes() throws Exception {
		exerciseFunctionsForFactory(new ExactMatchBytesProgramCorrelatorFactory(),
			sourceProgram.getMemory().getLoadedAndInitializedAddressSet());
	}

@Test
    public void testExactInstructions() throws Exception {
		exerciseFunctionsForFactory(new ExactMatchInstructionsProgramCorrelatorFactory(),
			sourceProgram.getMemory().getLoadedAndInitializedAddressSet());
	}

@Test
    public void testExactMnemonics() throws Exception {
		exerciseFunctionsForFactory(new ExactMatchMnemonicsProgramCorrelatorFactory(),
			sourceProgram.getMemory().getLoadedAndInitializedAddressSet());
	}

@Test
    public void testSymbolName() throws Exception {
		AddressSet realSymbols = new AddressSet();
		SymbolIterator symbolIterator = sourceProgram.getSymbolTable().getSymbolIterator();
		for (Symbol symbol : symbolIterator) {
			if (symbol.getSource() != SourceType.DEFAULT) {
				realSymbols.addRange(symbol.getAddress(), symbol.getAddress());
			}
		}

		exerciseFunctionsForFactory(new SymbolNameProgramCorrelatorFactory(), realSymbols);
	}

}
