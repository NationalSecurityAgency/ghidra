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
import ghidra.features.bsim.query.protocol.ChildAtom;
import ghidra.features.bsim.query.protocol.FilterAtom;

/**
 * A BsimFilterType for filtering functions based on calls to specific external functions.
 * The called function must be external, i.e. in terms of the database, the function must be
 * associated with a library executable (having no code body)
 */
public class HasNamedChildBSimFilterType extends BSimFilterType {
	public static final String XML_VALUE = "namedchild";

	public HasNamedChildBSimFilterType() {
		super("Calls external function", XML_VALUE, "external subfunction");
	}

	@Override
	public boolean isChildFilter() {
		return true;
	}

	@Override
	public boolean isLocal() {
		return false;
	}

	@Override
	public void gatherSQLEffect(SQLEffects effect, FilterAtom atom, IDSQLResolution resolution)
		throws SQLException {
		StringBuilder buf = new StringBuilder();
		buf.append("EXISTS (SELECT 1 FROM callgraphtable WHERE src = desctable.id AND dest = ");
		buf.append(resolution.id1);
		buf.append(')');
		effect.addWhere(this, buf.toString());
	}

	@Override
	public void gatherElasticEffect(ElasticEffects effect, FilterAtom atom,
		IDElasticResolution resolution) throws ElasticException {
		String argName = effect.assignArgument();
		effect.addChildId("Collections.binarySearch(childid,params." + argName + ")>=0");
		effect.addFuncParam(argName, resolution.idString);
	}

	@Override
	public boolean evaluate(ExecutableRecord rec, String value) {
		return true;
	}

	@Override
	public IDSQLResolution generateIDSQLResolution(FilterAtom atom) {
		ChildAtom childatom = (ChildAtom) atom;
		return new IDSQLResolution.ExternalFunction(childatom.exename, childatom.name);
	}

	@Override
	public IDElasticResolution generateIDElasticResolution(FilterAtom atom) {
		ChildAtom childatom = (ChildAtom) atom;
		return new IDElasticResolution.ExternalFunction(childatom.exename, childatom.name);
	}
}
