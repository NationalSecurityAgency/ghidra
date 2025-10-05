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

import java.io.*;
import java.util.*;
import java.util.function.Consumer;

import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;

/**
 * A {@link Loader} for processing Microsoft DEF files.
 */
public class DefLoader extends AbstractProgramWrapperLoader {
	public final static String DEF_NAME = "Module Definition (DEF)";

	public static final String NO_MAGIC = "0";

	private List<DefExportLine> parseExports(ByteProvider provider) throws IOException {
		List<DefExportLine> list = new ArrayList<>();
		try (InputStream inputStream = provider.getInputStream(0)) {
			boolean hasExports = false;
			BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
			String line = null;
			while ((line = reader.readLine()) != null) {
				if (line.startsWith(";") || line.isEmpty()) {// comment
					continue;
				}
				else if (line.startsWith("LIBRARY")) {
					// why skip libraries?  Who knows?  If you do, please update this comment
				}
				else if (line.startsWith("EXPORTS")) {
					hasExports = true;
				}
				else if (hasExports) {
					DefExportLine exp = new DefExportLine(line);
					list.add(exp);
				}
			}
		}
		return list;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		String name = provider.getName();
		if (name != null && name.toLowerCase().endsWith(".def") &&
			!parseExports(provider).isEmpty()) {
			List<QueryResult> results = QueryOpinionService.query(getName(), NO_MAGIC, null);
			for (QueryResult result : results) {
				loadSpecs.add(new LoadSpec(this, 0, result));
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, 0, true));
			}
		}

		return loadSpecs;
	}

	@Override
	public void load(Program prog, ImporterSettings settings) throws IOException {

		if (!prog.getExecutableFormat().equals(PeLoader.PE_NAME)) {
			throw new IOException("Program must be a " + PeLoader.PE_NAME);
		}

		SymbolTable symtab = prog.getSymbolTable();
		Consumer<String> errorConsumer = err -> settings.log().appendMsg("DefLoader", err);
		for (DefExportLine def : parseExports(settings.provider())) {
			Integer ordinal = def.getOrdinal();
			if (ordinal == null) {
				continue;
			}
			Symbol symbol = SymbolUtilities.getLabelOrFunctionSymbol(prog,
				SymbolUtilities.ORDINAL_PREFIX + ordinal, errorConsumer);
			if (symbol == null) {
				continue;
			}
			try {
				Symbol label =
					symtab.createLabel(symbol.getAddress(), def.getName(), SourceType.IMPORTED);
				label.setPrimary();
			}
			catch (InvalidInputException e) {
				settings.log().appendMsg(e.getMessage());
			}
		}
	}

	@Override
	public String getName() {
		return DEF_NAME;
	}

	@Override
	public boolean supportsLoadIntoProgram(Program program) {
		return true;
	}
}
