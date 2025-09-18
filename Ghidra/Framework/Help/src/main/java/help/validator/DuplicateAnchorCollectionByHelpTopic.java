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
package help.validator;

import java.nio.file.Path;
import java.util.List;

import help.validator.model.AnchorDefinition;
import help.validator.model.HelpTopic;

public class DuplicateAnchorCollectionByHelpTopic implements DuplicateAnchorCollection,
		Comparable<DuplicateAnchorCollectionByHelpTopic> {

	private final HelpTopic topic;
	private final List<AnchorDefinition> definitions;

	DuplicateAnchorCollectionByHelpTopic(HelpTopic topic, List<AnchorDefinition> definitions) {
		this.topic = topic;
		this.definitions = definitions;
	}

	@Override
	public String toString() {
		return "Duplicate anchors for topic\n\ttopic dir:  " + topic.getTopicDir() + "\n" +
			getAnchorsAsString();
	}

	private String getAnchorsAsString() {
		StringBuilder buildy = new StringBuilder();
		for (AnchorDefinition definition : definitions) {
			buildy.append('\t').append('\t').append(definition).append('\n');
		}
		return buildy.toString();
	}

	@Override
	public int compareTo(DuplicateAnchorCollectionByHelpTopic o) {
		Path topicDir1 = topic.getTopicDir();
		Path topicDir2 = o.topic.getTopicDir();
		return topicDir1.compareTo(topicDir2);
	}
}
