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

import java.io.IOException;
import java.util.List;

import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;

/**
 * An abstract {@link Loader} that provides a convenience wrapper around 
 * {@link AbstractProgramLoader}, minimizing the amount of work a subclass needs to do to load a
 * {@link Program}
 */
public abstract class AbstractProgramWrapperLoader extends AbstractProgramLoader {

	/**
	 * Loads bytes in a particular format into the given {@link Program}.
	 *
	 * @param program The {@link Program} to load into.
	 * @param settings The {@link Loader.ImporterSettings}.
	 * @throws IOException if there was an IO-related problem loading.
	 * @throws CancelledException if the user cancelled the load.
	 */
	protected abstract void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException;

	@Override
	protected List<Loaded<Program>> loadProgram(ImporterSettings settings)
			throws IOException, CancelledException {

		Program program = createProgram(settings);
		Loaded<Program> loaded = new Loaded<Program>(program, settings);

		int transactionID = program.startTransaction("Loading");
		boolean success = false;
		try {
			load(program, settings);
			createDefaultMemoryBlocks(program, settings);
			success = true;
			return List.of(loaded);
		}
		finally {
			program.endTransaction(transactionID, true); // More efficient to commit when program will be discarded
			if (!success) {
				loaded.close();
			}
		}
	}

	@Override
	protected void loadProgramInto(Program program, ImporterSettings settings)
			throws CancelledException, LoadException, IOException {

		LanguageCompilerSpecPair pair = settings.loadSpec().getLanguageCompilerSpec();
		LanguageID languageID = program.getLanguageID();
		CompilerSpecID compilerSpecID = program.getCompilerSpec().getCompilerSpecID();
		if (!(pair.languageID.equals(languageID) && pair.compilerSpecID.equals(compilerSpecID))) {
			String message = settings.provider().getAbsolutePath() +
				" does not have the same language/compiler spec as program " + program.getName();
			settings.log().appendMsg(message);
			throw new LoadException(message);
		}
		load(program, settings);
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.GENERIC_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}
}
