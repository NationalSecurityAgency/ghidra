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
package ghidra.program.database.data.merge;

import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;

/**
 * Datatype merger for Enums.
 */
public class EnumMerger extends DataTypeMerger<Enum> {

	public EnumMerger(Enum enum1, Enum enum2) {
		super(enum1, enum2);
	}

	@Override
	public void doMerge() throws DataTypeMergeException {
		mergeSize();
		mergeDescription();

		String[] names = other.getNames();
		for (String name : names) {
			long value = other.getValue(name);

			if (!working.contains(name)) {
				addValue(name, value, other.getComment(name));

			}
			else {
				// current value must match
				long currentResultValue = working.getValue(name);
				if (value != currentResultValue) {
					String msg = "Enums have different values for name \"%s\". %d and %d"
							.formatted(name, currentResultValue, value);
					error(msg);
				}

				// otherwise join comments
				String comment1 = working.getComment(name);
				String comment2 = other.getComment(name);
				working.remove(name);
				working.add(name, value, join(comment1, comment2));
			}

		}
	}

	private void addValue(String name, long value, String comment) throws DataTypeMergeException {
		try {
			working.add(name, value, other.getComment(name));
		}
		catch (IllegalArgumentException e) {
			error("Enum conflict: one enum has negative values: one has large unsigned values");
		}
	}

	private void mergeSize() {
		if (working.getLength() < other.getLength()) {
			((EnumDataType) working).setLength(other.getLength());
		}
	}
}
