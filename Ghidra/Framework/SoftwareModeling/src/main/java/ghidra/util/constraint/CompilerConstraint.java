/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import generic.constraint.ConstraintData;
import ghidra.program.model.listing.Program;

public class CompilerConstraint extends ProgramConstraint {

	public CompilerConstraint() {
		super("compiler");
	}

	private String compilerid;

	@Override
	public boolean isSatisfied(Program program) {
		return compilerid.equals(program.getCompilerSpec().getCompilerSpecID().getIdAsString());
	}

	@Override
	public void loadConstraintData(ConstraintData data) {
		compilerid = data.getString("id");
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof CompilerConstraint)) {
			return false;
		}
		return ((CompilerConstraint) obj).compilerid.equals(compilerid);
	}

	@Override
	public String getDescription() {
		return "compiler = " + compilerid;
	}

}
