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
package ghidra.app.util.opinion;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.commands.ExportTrie.ExportEntry;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/**
 * Builds up a {@link Program} of components extracted from a Mach-O container by parsing the Mach-O 
 * headers
 */
public class MachoExtractProgramBuilder extends MachoProgramBuilder {

	/**
	 * Creates a new {@link MachoExtractProgramBuilder} based on the given information.
	 * 
	 * @param program The {@link Program} to build up.
	 * @param provider The {@link ByteProvider} that contains the Mach-O's bytes.
	 * @param fileBytes Where the Mach-O's bytes came from.
	 * @param log The log.
	 * @param monitor A cancelable task monitor.
	 * @throws Exception if a problem occurs.
	 */
	protected MachoExtractProgramBuilder(Program program, ByteProvider provider,
			FileBytes fileBytes, MessageLog log, TaskMonitor monitor) throws Exception {
		super(program, provider, fileBytes, log, monitor);
	}

	/**
	 * Builds up a {@link Program} of Mach-O components extracted from a Mach-O container
	 * 
	 * @param program The {@link Program} to build up.
	 * @param provider The {@link ByteProvider} that contains the Mach-O's bytes.
	 * @param fileBytes Where the Mach-O's bytes came from.
	 * @param log The log.
	 * @param monitor A cancelable task monitor.
	 * @throws Exception if a problem occurs.
	 */
	public static void buildProgram(Program program, ByteProvider provider, FileBytes fileBytes,
			MessageLog log, TaskMonitor monitor) throws Exception {
		MachoExtractProgramBuilder programBuilder = new MachoExtractProgramBuilder(program,
			provider, fileBytes, log, monitor);
		programBuilder.build();
	}

	@Override
	protected void setProgramImageBase() throws Exception {
		program.setImageBase(space.getAddress(0), true);
	}

	@Override
	protected void fixupProgramTree(String suffix) throws Exception {
		super.fixupProgramTree(" - " + provider.getAbsolutePath());

		// Our program tree must account for Add To Program's happening, so we want to put each
		// added program into its own subfolder.  We tag these subfolders with ".extract" so we
		// can keep all of these program subfolders at the top-level of the tree.
		ProgramModule rootModule = listing.getDefaultRootModule();
		String tag = ".extract";
		String newName = provider.getAbsolutePath() + tag;
		ProgramModule newRootModule = rootModule.createModule(newName);
		for (Group group : rootModule.getChildren()) {
			if (!group.getName().endsWith(tag)) {
				newRootModule.reparent(group.getName(), rootModule);
			}
		}
	}

	@Override
	protected void processNewExport(Address baseAddr, ExportEntry export, String name)
			throws AddressOutOfBoundsException, Exception {
		SymbolTable symbolTable = program.getSymbolTable();
		FunctionManager funcManager = program.getFunctionManager();
		ExternalManager extManager = program.getExternalManager();

		// Add the new exported symbol like normal
		super.processNewExport(baseAddr, export, name);

		Address exportAddr = baseAddr.add(export.address());

		for (Symbol sym : symbolTable.getGlobalSymbols(name)) {

			// If it's a thunk function (stub), redirect its thunked function from the external
			// location to the newly exported function
			Function func = funcManager.getFunctionAt(sym.getAddress());
			if (func != null && func.getThunkedFunction(false) != null) {
				func.setThunkedFunction(createOneByteFunction(name, exportAddr));

				// Remove the external location associated with the thunk function.
				// After the first delete, the external location becomes an external label, which
				// must also get deleted.
				ExternalLocation loc = extManager.getUniqueExternalLocation(Library.UNKNOWN, name);
				if (loc != null) {
					if (loc.getSymbol().delete()) {
						loc = extManager.getUniqueExternalLocation(Library.UNKNOWN, name);
						if (loc != null) {
							loc.getSymbol().delete();
						}
					}
				}
			}

		}
	}
}
