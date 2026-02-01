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
package ghidra.program.model.lang.protorules;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.program.model.lang.PrototypePieces;
import ghidra.program.model.pcode.Encoder;
import ghidra.xml.XmlParseException;
import ghidra.xml.XmlPullParser;

/**
 * Logically AND multiple QualifierFilters together into a single filter.
 * An instances contains some number of other arbitrary filters.  In order for this filter to
 * pass, all these contained filters must pass.
 */
public class AndFilter implements QualifierFilter {

	private QualifierFilter[] subQualifiers;	// Filters being logically ANDed together

	/**
	 * The AndFilter assumes ownership of all the filters in the ArrayList
	 * @param qualifierList is the list of filters pulled into this filter
	 */
	public AndFilter(ArrayList<QualifierFilter> qualifierList) {
		subQualifiers = new QualifierFilter[qualifierList.size()];
		qualifierList.toArray(subQualifiers);
	}

	public AndFilter(AndFilter op) {
		subQualifiers = new QualifierFilter[op.subQualifiers.length];
		for (int i = 0; i < subQualifiers.length; ++i) {
			subQualifiers[i] = op.subQualifiers[i].clone();
		}
	}

	@Override
	public QualifierFilter clone() {
		return new AndFilter(this);
	}

	@Override
	public boolean isEquivalent(QualifierFilter op) {
		if (op.getClass() != this.getClass()) {
			return false;
		}
		AndFilter otherFilter = (AndFilter) op;
		if (subQualifiers.length != otherFilter.subQualifiers.length) {
			return false;
		}
		// Preserve strict order
		for (int i = 0; i < subQualifiers.length; ++i) {
			if (!subQualifiers[i].isEquivalent(otherFilter.subQualifiers[i])) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean filter(PrototypePieces proto, int pos) {
		for (int i = 0; i < subQualifiers.length; ++i) {
			if (!subQualifiers[i].filter(proto, pos)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		for (int i = 0; i < subQualifiers.length; ++i) {
			subQualifiers[i].encode(encoder);
		}
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		// This method is not called
	}
}
