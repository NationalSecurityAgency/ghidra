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
package ghidra.test.processors.cspec;

import ghidra.test.compilers.support.CSpecPrototypeTest;

public class ARM_CSpecTest extends CSpecPrototypeTest {
	//ARM_LE_32_v8_default___stdcall
	private static final String LANGUAGE_ID = "ARM:LE:32:v8";
	private static final String COMPILER_SPEC_ID = "default";

	private static final String CALLING_CONVENTION = "__stdcall";

	private static final String[] EXPECTED_PROTOTYPE_ERRORS = {
		"paramsUnion_65",
		"paramsUnion_68",
		"paramsUnion_70",
		"returnUnion_112",
		"returnUnion_113",
		"returnUnion_121"
	};

	public ARM_CSpecTest() throws Exception {
		super(EXPECTED_PROTOTYPE_ERRORS);
	}

	@Override
	public String getLanguageID() {
		return LANGUAGE_ID;
	}

	@Override
	public String getCompilerSpecID() {
		return COMPILER_SPEC_ID;
	}

	@Override
	public String getCallingConvention() {
		return CALLING_CONVENTION;
	}

}
