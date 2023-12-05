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

import java.io.IOException;
import java.io.Writer;
import java.sql.SQLException;
import java.util.List;
import java.util.Objects;

import ghidra.features.bsim.query.client.IDSQLResolution;
import ghidra.features.bsim.query.client.SQLEffects;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.elastic.*;
import ghidra.features.bsim.query.facade.SimilarFunctionQueryService;
import ghidra.features.bsim.query.protocol.FilterAtom;

/**
 * A BsimFilterType for filtering functions based on not matching specific category values.
 */
public class NotExecutableCategoryBSimFilterType extends BSimFilterType {
	public static final String XML_VALUE = "execatnomatch";

	private String subType;

	public NotExecutableCategoryBSimFilterType(String sub) {
		super(sub + " does not match", XML_VALUE, "category value");
		subType = sub;
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		super.saveXml(fwrite);
		fwrite.append(" subtype=\"").append(subType).append('\"');
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Objects.hash(subType);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (obj instanceof NotExecutableCategoryBSimFilterType t) {
			return Objects.equals(subType, t.subType);
		}
		return false;
	}

	/**
	 * Custom category filters are processed after results are received, as a necessary consequence
	 * of the database structure.  So we allow the query to return all possible results, and cull
	 * them after the fact.
	 * 
	 * @see SimilarFunctionQueryService
	 */
	@Override
	public void gatherSQLEffect(SQLEffects effect, FilterAtom atom, IDSQLResolution resolution)
		throws SQLException {
		StringBuilder buf = new StringBuilder();
		buf.append("(execattable.id_type =").append(resolution.id1);
		buf.append(" AND execattable.id_category =").append(resolution.id2).append(')');
		effect.addWhere(this, buf.toString());
	}

	@Override
	public void gatherElasticEffect(ElasticEffects effect, FilterAtom atom,
		IDElasticResolution resolution) throws ElasticException {
		effect.addDocValue("def execat = doc['execategory']; ");
		String argName = effect.assignArgument();
		effect.addScriptElement(this,
			"Collections.binarySearch(execat,params." + argName + ")<0");
		effect.addParam(argName, subType + "\\t" + atom.value);
	}

	@Override
	public String buildSQLCombinedClause(List<String> subClauses) {
		StringBuilder buf = new StringBuilder();
		buf.append(
			"NOT EXISTS ( SELECT 1 FROM execattable WHERE desctable.id_exe=execattable.id_exe AND (");
		boolean printOr = false;
		for (String clause : subClauses) {
			if (printOr) {
				buf.append(" OR ");
			}
			buf.append(clause);
			printOr = true;
		}
		buf.append(") )");
		return buf.toString();
	}

	@Override
	public boolean evaluate(ExecutableRecord rec, String value) {
		return !rec.hasCategory(subType, value);
	}

	@Override
	public IDSQLResolution generateIDSQLResolution(FilterAtom atom) {
		return new IDSQLResolution.ExeCategory(subType, atom.value);
	}

	@Override
	public boolean orMultipleEntries() {
		return false;
	}
}
