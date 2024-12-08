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

import ghidra.features.bsim.query.client.IDSQLResolution;
import ghidra.features.bsim.query.client.SQLEffects;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.elastic.*;
import ghidra.features.bsim.query.protocol.FilterAtom;

/**
 * A BsimFilterType for filtering on functions by the starting path of their containing program.
 */
public class PathStartsBSimFilterType extends BSimFilterType {
	public static final String XML_VALUE = "pathstarts";

	public PathStartsBSimFilterType() {
		super("Path starts with", XML_VALUE, "path");
	}

	@Override
	public void gatherSQLEffect(SQLEffects effect, FilterAtom atom, IDSQLResolution resolution)
		throws SQLException {
		if (atom.value.length() > 0) {
			effect.setExeTable();
			effect.setPathTable();
			StringBuilder buf = new StringBuilder();
			buf.append("position( \'").append(atom.value).append("\' in pathtable.val) = 1");
			effect.addWhere(this, buf.toString());
		}
	}

	@Override
	public void gatherElasticEffect(ElasticEffects effect, FilterAtom atom,
		IDElasticResolution resolution) throws ElasticException {
		effect.addDocValue("String path = doc['path'].value; ");
		String argName = effect.assignArgument();
		effect.addScriptElement(this,
			"(path != null) && path.startsWith(params." + argName + ')');
		effect.addParam(argName, atom.value);
	}

	@Override
	public boolean evaluate(ExecutableRecord rec, String value) {
		if (rec.getPath() == null) {
			return false;
		}
		return rec.getPath().startsWith(value);
	}

	@Override
	public String normalizeValue(String value) {
		value = value.trim();
		// If the string is empty, it's invalid, just return false.
		if (value.isBlank()) {
			return null;
		}
		int pos = 0;
		int posend = value.length();
		if (value.charAt(0) == '/') {
			pos = 1;
		}
		if (value.charAt(posend - 1) == '/') {
			posend -= 1;
		}
		if (posend <= pos) {
			return null;
		}
		value = value.substring(pos, posend);
		return value;
	}

	@Override
	public boolean isValidValue(String value) {
		return normalizeValue(value) != null;
	}

	@Override
	public IDSQLResolution generateIDSQLResolution(FilterAtom atom) {
		return null; // Id resolution not needed
	}
}
