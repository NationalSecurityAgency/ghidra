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

import org.json.simple.JSONObject;

import ghidra.features.bsim.query.client.IDSQLResolution;
import ghidra.features.bsim.query.client.SQLEffects;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.elastic.*;
import ghidra.features.bsim.query.protocol.FilterAtom;

/**
 * A BsimFilterType for filtering on functions by the name of their containing program.
 */
public class ExecutableNameBSimFilterType extends BSimFilterType {

	public static final String XML_VALUE = "nameequals";

	public ExecutableNameBSimFilterType() {
		super("Executable name equals", XML_VALUE, "executable name");
	}

	@Override
	public void gatherSQLEffect(SQLEffects effect, FilterAtom atom, IDSQLResolution resolution)
		throws SQLException {
		effect.setExeTable();
		StringBuilder buf = new StringBuilder();
		buf.append("exetable.name_exec = '").append(atom.value).append('\'');
		effect.addWhere(this, buf.toString());
	}

	@Override
	public void gatherElasticEffect(ElasticEffects effect, FilterAtom atom,
		IDElasticResolution resolution) throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("\"filter\": { \"term\": { \"name_exec\": \"");
		buffer.append(JSONObject.escape(atom.value));
		buffer.append("\" } } ");
		effect.addStandalone(this, buffer.toString());
	}

	@Override
	public boolean evaluate(ExecutableRecord rec, String value) {
		return (value.equals(rec.getNameExec()));
	}

	@Override
	public IDSQLResolution generateIDSQLResolution(FilterAtom atom) {
		return null; // No resolution needed
	}
}
