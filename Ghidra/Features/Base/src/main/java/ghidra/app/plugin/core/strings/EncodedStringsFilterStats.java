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
package ghidra.app.plugin.core.strings;

import java.lang.Character.UnicodeScript;
import java.util.HashMap;
import java.util.Map;

/**
 * Holds counts of reasons for filter rejection
 */
class EncodedStringsFilterStats {
	int total;
	int codecErrors;
	int nonStdCtrlChars;
	int failedStringModel;
	int stringLength;
	int requiredScripts;
	int otherScripts;
	int latinScript;
	int commonScript;
	Map<UnicodeScript, Integer> foundScriptCounts = new HashMap<>();

	public EncodedStringsFilterStats() {
		// empty
	}

	public EncodedStringsFilterStats(EncodedStringsFilterStats other) {
		this.total = other.total;
		this.codecErrors = other.codecErrors;
		this.nonStdCtrlChars = other.nonStdCtrlChars;
		this.failedStringModel = other.failedStringModel;
		this.stringLength = other.stringLength;
		this.requiredScripts = other.requiredScripts;
		this.otherScripts = other.otherScripts;
		this.latinScript = other.latinScript;
		this.commonScript = other.commonScript;
		this.foundScriptCounts.putAll(other.foundScriptCounts);
	}

	int getTotalForAdvancedOptions() {
		return codecErrors + nonStdCtrlChars + failedStringModel + stringLength;
	}

	int getTotalOmitted() {
		return codecErrors + nonStdCtrlChars + failedStringModel + stringLength + requiredScripts;
	}

	@Override
	public EncodedStringsFilterStats clone() {
		return new EncodedStringsFilterStats(this);
	}

}
