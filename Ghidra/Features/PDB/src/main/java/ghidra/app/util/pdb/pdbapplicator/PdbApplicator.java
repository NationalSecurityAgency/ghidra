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
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;

/**
 * Interface for PDB Applicator.
 * <p>
 * The main engine for applying an AbstractPdb to Ghidra, whether a Program or DataTypeManager.
 * The class is to be constructed first.
 * <p>
 * <b>NOTE: The plan is that this interface will be grown to a be a full/true interface, but it
 * is currently only being created to allow for creating a stub for testing.</b>
 */
public interface PdbApplicator {

	/**
	 * Returns the {@link AbstractPdb} being analyzed
	 * @return {@link AbstractPdb} being analyzed
	 */
	public AbstractPdb getPdb();

	/**
	 * Returns the {@link Program} for which this analyzer is working
	 * @return {@link Program} for which this analyzer is working
	 */
	Program getProgram();

	/**
	 * Returns the original image base value from the PE Header
	 * @return the original image base for the binary
	 */
	public long getOriginalImageBase();

	/**
	 * Returns the {@link PeCoffSectionMsSymbol}s from the "Linker" module
	 * @return list of symbols
	 * @throws CancelledException upon user cancellation
	 */
	public List<PeCoffSectionMsSymbol> getLinkerPeCoffSectionSymbols() throws CancelledException;

	/**
	 * Returns the compile symbol seen in the "Linker" module.  Should be one of
	 * {@link Compile3MsSymbol} or {@link AbstractCompile2MsSymbol}
	 * @return the compile symbol
	 * @throws CancelledException upon user cancellation
	 */
	public AbstractMsSymbol getLinkerModuleCompileSymbol() throws CancelledException;

}
