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

import java.util.StringTokenizer;

public class LanguageConstraint extends ProgramConstraint {

	public LanguageConstraint() {
		super("language");
	}

	private String languageID;

	@Override
	public boolean isSatisfied(Program program) {
		StringTokenizer tokA = new StringTokenizer(languageID, ":");
		StringTokenizer tokB = new StringTokenizer(program.getLanguageID().getIdAsString(), ":");

		while (tokA.hasMoreTokens() || tokB.hasMoreTokens()) {
			if (!tokA.hasMoreTokens() || !tokB.hasMoreTokens()) {
				return false;
			}
			String nextTokenA = tokA.nextToken();
			String nextTokenB = tokB.nextToken();
			if (nextTokenA.equals("*")) {
				continue;
			}
			if (!nextTokenA.equals(nextTokenB)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public void loadConstraintData(ConstraintData data) {
		languageID = data.getString("id");
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof LanguageConstraint)) {
			return false;
		}
		return ((LanguageConstraint) obj).languageID.equals(languageID);
	}

	@Override
	public String getDescription() {
		return "languageID = " + languageID;
	}

}
