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
package ghidra.xml;

import java.util.Map;

public interface XmlElement {
	public int getLevel();

	public boolean isStart();

	public boolean isEnd();

	public boolean isContent();

	public String getName();

	public Map<String, String> getAttributes();

	public boolean hasAttribute(String key);

	public String getAttribute(String key);

	public String getText();

	public int getColumnNumber();

	public int getLineNumber();

	public void setAttribute(String key, String value);
}
