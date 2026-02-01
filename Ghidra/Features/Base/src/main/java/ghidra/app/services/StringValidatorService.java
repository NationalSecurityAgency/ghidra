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
package ghidra.app.services;

import java.util.*;

import ghidra.framework.plugintool.PluginTool;

/**
 * A service that judges the validity of a string
 */
public interface StringValidatorService {
	/**
	 * Returns a list of string validator services
	 * 
	 * @param tool {@link PluginTool}
	 * @return list of services
	 */
	static List<StringValidatorService> getCurrentStringValidatorServices(
			PluginTool tool) {

		List<StringValidatorService> results =
			new ArrayList<>(List.of(tool.getServices(StringValidatorService.class)));
		Collections.sort(results,
			(s1, s2) -> s1.getValidatorServiceName().compareTo(s2.getValidatorServiceName()));

		return results;
	}

	StringValidatorService DUMMY = new DummyStringValidator();

	/**
	 * Returns the name of the service
	 * 
	 * @return
	 */
	String getValidatorServiceName();

	/**
	 * Judges a string (specified in the query instance).
	 * 
	 * @param query {@link StringValidatorQuery}
	 * @return {@link StringValidityScore}
	 */
	StringValidityScore getStringValidityScore(StringValidatorQuery query);

	static class DummyStringValidator implements StringValidatorService {

		@Override
		public String getValidatorServiceName() {
			return "Dummy";
		}

		@Override
		public StringValidityScore getStringValidityScore(StringValidatorQuery query) {
			return StringValidityScore.makeDummyFor(query.stringValue());
		}

	}
}
