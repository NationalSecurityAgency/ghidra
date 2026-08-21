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
package ghidra.app.plugin.core.clear;

import java.util.HashSet;
import java.util.Set;

import ghidra.program.model.symbol.SourceType;

public class ClearOptions {
	public enum ClearType {
		INSTRUCTIONS,
		DATA,
		SYMBOLS,
		COMMENTS,
		PROPERTIES,
		FUNCTIONS,
		REGISTERS,
		EQUATES,
		USER_REFERENCES,
		ANALYSIS_REFERENCES,
		IMPORT_REFERENCES,
		DEFAULT_REFERENCES,
		BOOKMARKS
	}

	private Set<ClearType> typesToClearSet = new HashSet<>();

	/**
	 * Default constructor that will clear everything!
	 */
	public ClearOptions() {
		this(true);
	}

	public ClearOptions(boolean defaultClearState) {
		if (defaultClearState) {
			for (ClearType type : ClearType.values()) {
				typesToClearSet.add(type);
			}
		}
	}

	public void setShouldClear(ClearType type, boolean shouldClear) {
		if (shouldClear) {
			typesToClearSet.add(type);
		}
		else {
			typesToClearSet.remove(type);
		}
	}

	public boolean shouldClear(ClearType type) {
		return typesToClearSet.contains(type);
	}

	Set<SourceType> getReferenceSourceTypesToClear() {
		HashSet<SourceType> sourceTypesToClear = new HashSet<SourceType>();
		if (shouldClear(ClearType.USER_REFERENCES)) {
			sourceTypesToClear.add(SourceType.USER_DEFINED);
		}
		if (shouldClear(ClearType.DEFAULT_REFERENCES)) {
			sourceTypesToClear.add(SourceType.DEFAULT);
		}
		if (shouldClear(ClearType.IMPORT_REFERENCES)) {
			sourceTypesToClear.add(SourceType.IMPORTED);
		}
		if (shouldClear(ClearType.ANALYSIS_REFERENCES)) {
			sourceTypesToClear.add(SourceType.ANALYSIS);
		}
		return sourceTypesToClear;
	}

	boolean clearAny() {
		return !typesToClearSet.isEmpty();
	}
}
