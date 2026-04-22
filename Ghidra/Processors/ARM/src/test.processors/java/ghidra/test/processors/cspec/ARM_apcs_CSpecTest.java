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

public class ARM_apcs_CSpecTest extends CSpecPrototypeTest {
	//ARM_BE_32_v8-m_apcs___stdcall
	private static final String LANGUAGE_ID = "ARM:BE:32:v8-m";
	private static final String COMPILER_SPEC_ID = "apcs";

	private static final String CALLING_CONVENTION = "__stdcall";

	private static final String[] EXPECTED_PROTOTYPE_ERRORS = {
		"paramsSingletonStruct_7",
		"paramsSingletonStruct_8",
		"paramsPairStruct_11",
		"paramsTripStruct_15",
		"paramsTripStruct_16",
		"paramsUnion_26",
		"paramsUnion_27",
		"paramsUnion_33",
		"paramsUnion_34",
		"returnSingleton_36",
		"returnPair_37",
		"returnTriple_38",
		"returnUnion_40",
		"returnUnion_41",
		"returnSingleton_43",
		"returnUnion_47"
	};

	public ARM_apcs_CSpecTest() throws Exception {
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
