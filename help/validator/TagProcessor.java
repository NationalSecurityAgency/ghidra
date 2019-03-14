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
package help.validator;

import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;

public abstract class TagProcessor {

	enum TagProcessingState {
		LOOKING_FOR_NEXT_ATTR, READING_ATTR, LOOKING_FOR_VALUE, READING_VALUE;
	}

	TagProcessor() {
	}

	abstract void processTag(String tagType, LinkedHashMap<String, String> tagAttributes,
			Path file, int lineNum) throws IOException;

	public void startOfFile(Path htmlFile) {
		// stub
	}

	public void endOfFile() {
		// stub
	}

	public String processText(String text) {
		return text;
	}

	public boolean isTagSupported(String tagType) {
		return true;
	}

	public int getErrorCount() {
		return 0;
	}
}
