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
package ghidra.features.bsim.gui.filters;

import java.sql.SQLException;
import java.util.*;

import ghidra.features.bsim.query.client.IDSQLResolution;
import ghidra.features.bsim.query.client.SQLEffects;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.elastic.*;
import ghidra.features.bsim.query.protocol.FilterAtom;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import utility.function.Callback;

/**
 * A BsimFilterType for filtering functions based on not matching a Ghidra compiler specification.
 */
public class NotCompilerBSimFilterType extends BSimFilterType {
	public static final String XML_VALUE = "compnotequal";

	public NotCompilerBSimFilterType() {
		super("Compiler does not equal", XML_VALUE, "gcc");
	}

	@Override
	public void gatherSQLEffect(SQLEffects effect, FilterAtom atom, IDSQLResolution resolution)
		throws SQLException {
		effect.setExeTable();
		StringBuilder buf = new StringBuilder();
		buf.append("exetable.name_compiler!=").append(resolution.id1);
		effect.addWhere(this, buf.toString());
	}

	@Override
	public void gatherElasticEffect(ElasticEffects effect, FilterAtom atom,
		IDElasticResolution resolution) throws ElasticException {
		effect.addDocValue("String comp = doc['name_compiler'].value; ");
		String argName = effect.assignArgument();
		effect.addScriptElement(this, "comp != params." + argName);
		effect.addParam(argName, atom.value);
	}

	@Override
	public boolean evaluate(ExecutableRecord rec, String value) {
		return (!value.equals(rec.getNameCompiler()));
	}

	@Override
	public IDSQLResolution generateIDSQLResolution(FilterAtom atom) {
		return new IDSQLResolution.Compiler(atom.value);
	}

	@Override
	public boolean orMultipleEntries() {
		return false;
	}

	@Override
	public BSimValueEditor getEditor(List<String> initialValues, Callback listener) {
		List<String> choices = getCompilers();
		return new MultiChoiceBSimValueEditor(this, choices, initialValues, "Compiler",
			listener);
	}

	/**
	 * Returns a list of all known compilers.
	 * 
	 * @return the list of compiler specs
	 */
	private static List<String> getCompilers() {
		List<String> compilers = new ArrayList<>();

		List<LanguageDescription> languages =
			DefaultLanguageService.getLanguageService().getLanguageDescriptions(true);

		Set<String> compilerIds = new HashSet<>();
		for (LanguageDescription language : languages) {
			LanguageCompilerSpecQuery query =
				new LanguageCompilerSpecQuery(language.getProcessor(), language.getEndian(),
					language.getSize(), language.getVariant(), null);

			for (LanguageCompilerSpecPair specPair : DefaultLanguageService.getLanguageService()
				.getLanguageCompilerSpecPairs(
					query)) {
				try {
					String compilerId =
						specPair.getCompilerSpecDescription().getCompilerSpecID().getIdAsString();
					if (!compilerIds.contains(compilerId)) {
						compilerIds.add(compilerId);
						compilers.add(compilerId);
					}
				}
				catch (LanguageNotFoundException | CompilerSpecNotFoundException e) {
					// Just eat the exception - no need to rethrow or print an error
				}
			}
		}

		return compilers;
	}

}
