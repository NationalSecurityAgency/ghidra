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
import java.util.List;
import java.util.stream.Collectors;

import ghidra.features.bsim.query.client.IDSQLResolution;
import ghidra.features.bsim.query.client.SQLEffects;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.elastic.*;
import ghidra.features.bsim.query.protocol.FilterAtom;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.util.DefaultLanguageService;
import utility.function.Callback;

/**
 * A BsimFilterType for filtering functions based on a Ghidra computer architecture
 * specification.
 */
public class ArchitectureBSimFilterType extends BSimFilterType {
	public static final String XML_VALUE = "archequals";

	public ArchitectureBSimFilterType() {
		super("Architecture equals", XML_VALUE, "x86:LE:64:default");
	}

	@Override
	public void gatherSQLEffect(SQLEffects effect, FilterAtom atom, IDSQLResolution resolution)
		throws SQLException {
		effect.setExeTable();
		StringBuilder buf = new StringBuilder();
		buf.append("exetable.architecture=").append(resolution.id1);
		effect.addWhere(this, buf.toString());
	}

	@Override
	public void gatherElasticEffect(ElasticEffects effect, FilterAtom atom,
		IDElasticResolution resolution) throws ElasticException {
		effect.addDocValue("String arch = doc['architecture'].value; ");
		String argName = effect.assignArgument();
		effect.addScriptElement(this, "arch == params." + argName);
		effect.addParam(argName, atom.value);
	}

	@Override
	public boolean evaluate(ExecutableRecord rec, String value) {
		return (value.equals(rec.getArchitecture()));
	}

	@Override
	public IDSQLResolution generateIDSQLResolution(FilterAtom atom) {
		return new IDSQLResolution.Architecture(atom.value);
	}

	@Override
	public BSimValueEditor getEditor(List<String> initialValues, Callback listener) {
		List<String> choices = getArchitectures();
		return new MultiChoiceBSimValueEditor(this, choices, initialValues, "Architecture",
			listener);
	}

	public static List<String> getArchitectures() {
		LanguageService service = DefaultLanguageService.getLanguageService();
		List<LanguageDescription> languages = service.getLanguageDescriptions(true);
		return languages.stream()
			.map(l -> l.getLanguageID().toString())
			.collect(Collectors.toList());
	}

}
