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
package ghidra.trace.model;

import java.util.Date;
import java.util.Map;

import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;

public interface TraceOptionsManager {
	Map<String, String> asMap();

	void setName(String name);

	String getName();

	Date getCreationDate();

	Language getBaseLanguage();

	LanguageID getBaseLanguageID();

	String getBaseLanguageIDName();

	// TODO: Use a "Platform" type?
	void setPlatform(String platform);

	String getPlatform();

	void setExecutablePath(String path);

	String getExecutablePath();

}
