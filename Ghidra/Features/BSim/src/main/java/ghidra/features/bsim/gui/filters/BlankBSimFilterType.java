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
 * A BSimFilterType that represents a non-specified filter. Used for the gui so that when adding
 * a filter it doesn't have to default to some specific filter.
 */
public class BlankBSimFilterType extends BSimFilterType {
	public static final String XML_VALUE = "blank";

	@Override
	public boolean isBlank() {
		return true;
	}

	public BlankBSimFilterType() {
		super("<No Filter Selected>  ", XML_VALUE, "");
	}

	@Override
	public void gatherSQLEffect(SQLEffects effect, FilterAtom atom, IDSQLResolution resolution)
		throws SQLException {
		// Blank does nothing
	}

	@Override
	public void gatherElasticEffect(ElasticEffects effect, FilterAtom atom,
		IDElasticResolution resolution) throws ElasticException {
		// Blank does nothing

	}

	@Override
	public boolean evaluate(ExecutableRecord rec, String value) {
		return true;
	}

	@Override
	public boolean isValidValue(String value) {
		return value == null || value.isBlank();
	}

	@Override
	public String normalizeValue(String value) {
		return null;
	}

	@Override
	public IDSQLResolution generateIDSQLResolution(FilterAtom atom) {
		return null;
	}

}
