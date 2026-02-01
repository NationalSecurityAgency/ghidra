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
 * A BsimFilterType for filtering on functions whose containing program don't match a specific md5.
 */
public class NotMd5BSimFilterType extends BSimFilterType {
	public static final String XML_VALUE = "md5notequal";

	public NotMd5BSimFilterType() {
		super("MD5 does not equal", XML_VALUE, "32-digit hex value");
	}

	@Override
	public void gatherSQLEffect(SQLEffects effect, FilterAtom atom, IDSQLResolution resolution)
		throws SQLException {
		StringBuilder buf = new StringBuilder();
		effect.setExeTable();
		buf.append("exetable.md5 != '").append(atom.value).append('\'');
		effect.addWhere(this, buf.toString());
	}

	@Override
	public void gatherElasticEffect(ElasticEffects effect, FilterAtom atom,
		IDElasticResolution resolution) throws ElasticException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("\"must_not\": { \"term\": { \"md5\": \"");
		buffer.append(atom.value);
		buffer.append("\" } } ");
		effect.addStandalone(this, buffer.toString());
	}

	@Override
	public boolean evaluate(ExecutableRecord rec, String value) {
		return (!value.equals(rec.getMd5()));
	}

	@Override
	public String normalizeValue(String value) {
		if (value.length() == 34 && value.charAt(0) == '0' && value.charAt(1) == 'x') {
			value = value.substring(2, 34);
		}
		if (value.length() != 32 || !value.matches(Md5BSimFilterType.md5Regex)) {
			return null;
		}
		value = value.toLowerCase();
		return value;
	}

	@Override
	public boolean isValidValue(String value) {
		value = value.trim();
		if (value.length() == 34 && value.charAt(0) == '0' && value.charAt(1) == 'x') {
			value = value.substring(2, 34);
		}
		return value.length() == 32 && value.matches(Md5BSimFilterType.md5Regex);
	}

	@Override
	public IDSQLResolution generateIDSQLResolution(FilterAtom atom) {
		return null; // Id resolution not needed
	}

	@Override
	public boolean orMultipleEntries() {
		return false;
	}
}
