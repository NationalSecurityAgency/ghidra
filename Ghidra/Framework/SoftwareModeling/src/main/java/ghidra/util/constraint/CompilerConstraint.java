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
package ghidra.util.constraint;

import java.util.Objects;

import generic.constraint.ConstraintData;
import ghidra.program.model.listing.Program;
import ghidra.util.xml.XmlAttributeException;

public class CompilerConstraint extends ProgramConstraint {

	public CompilerConstraint() {
		super("compiler");
	}

	private String compilerid;
	private String compilerName;

	@Override
	public boolean isSatisfied(Program program) {
		if (compilerid == null && compilerName == null) {
			return false;
		}

		boolean satisfied = true;

		if (compilerid != null) {
			satisfied &=
				compilerid.equals(program.getCompilerSpec().getCompilerSpecID().getIdAsString());
		}

		if (compilerName != null) {
			satisfied &= compilerName.contains(program.getCompiler());
		}

		return satisfied;
	}

	@Override
	public void loadConstraintData(ConstraintData data) {
		if (data.hasValue("id")) {
			compilerid = data.getString("id");
		}

		if (data.hasValue("name")) {
			compilerName = data.getString("name");
		}

		if (compilerid == null && compilerName == null) {
			throw new XmlAttributeException("Missing both id and name attributes");
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof CompilerConstraint)) {
			return false;
		}

		CompilerConstraint constraint = (CompilerConstraint) obj;

		if (compilerid != constraint.compilerid) {
			if (compilerid == null || !compilerid.equals(constraint.compilerid)) {
				return false;
			}
		}

		if (compilerName != constraint.compilerName) {
			if (compilerName == null || !compilerName.equals(constraint.compilerName)) {
				return false;
			}
		}

		return true;
	}

	@Override
	public int hashCode() {
		return Objects.hash(compilerid, compilerName);
	}

	@Override
	public String getDescription() {
		return "compiler = " + compilerid + " compilerName = " + compilerName;
	}

}
