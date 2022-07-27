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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.PeCoffSectionMsSymbol;
import ghidra.program.model.listing.Program;

/**
 * Stub PDB Applicator for testing.
 */
public class StubPdbApplicator implements PdbApplicator {

	private AbstractPdb pdb = null;
	private long originalImageBase = 0L;

	private Program program = null;

	private List<PeCoffSectionMsSymbol> linkerPeCoffSectionSymbols = null;
	private AbstractMsSymbol compileSymbolForLinkerModule = null;

//==================================================================================================
	@Override
	public AbstractPdb getPdb() {
		return pdb;
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public long getOriginalImageBase() {
		return originalImageBase;
	}

	@Override
	public List<PeCoffSectionMsSymbol> getLinkerPeCoffSectionSymbols() {
		return linkerPeCoffSectionSymbols;
	}

	@Override
	public AbstractMsSymbol getLinkerModuleCompileSymbol() {
		return compileSymbolForLinkerModule;
	}

//==================================================================================================
	StubPdbApplicator setPdb(AbstractPdb pdb) {
		this.pdb = pdb;
		return this;
	}

	StubPdbApplicator setProgram(Program program) {
		this.program = program;
		return this;
	}

	StubPdbApplicator setOriginalImageBase(long originalImageBase) {
		this.originalImageBase = originalImageBase;
		return this;
	}

	StubPdbApplicator setLinkerPeCoffSectionSymbols(
			List<PeCoffSectionMsSymbol> linkerPeCoffSectionSymbols) {
		this.linkerPeCoffSectionSymbols = linkerPeCoffSectionSymbols;
		return this;
	}

	StubPdbApplicator setLinkerModuleCompileSymbol(AbstractMsSymbol compileSymbolForLinkerModule) {
		this.compileSymbolForLinkerModule = compileSymbolForLinkerModule;
		return this;
	}

}
