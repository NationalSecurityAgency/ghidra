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

public class MSP430_CSpecTest extends CSpecPrototypeTest {
	private static final String LANGUAGE_ID = "TI_MSP430:LE:16:default";
	private static final String COMPILER_SPEC_ID = "default";

	private static final String CALLING_CONVENTION = "__stdcall";

	private static final String[] EXPECTED_PROTOTYPE_ERRORS = {
		"paramsVariadic_I_I_C_C_S_S_I_I_L_L_50",
		"paramsUnion_56",
		"paramsUnion_57",
		"paramsUnion_58",
		"paramsUnion_59",
		"paramsUnion_60",
		"paramsUnion_61",
		"paramsUnion_62",
		"paramsUnion_63",
		"paramsUnion_64",
		"paramsUnion_65",
		"paramsUnion_66",
		"paramsUnion_67",
		"paramsUnion_68",
		"paramsUnion_69",
		"paramsUnion_70",
		"paramsUnion_71",
		"paramsUnion_72",
		"paramsUnion_73",
		"paramsUnion_74",
		"paramsUnion_75",
		"paramsUnion_76",
		"returnUnion_82",
		"returnUnion_83",
		"returnUnion_89",
		"returnUnion_90",
		"returnUnion_96",
		"returnUnion_102",
		"returnUnion_104",
		"returnUnion_112",
		"returnUnion_121",
		"returnUnion_130",
	};

	public MSP430_CSpecTest() throws Exception {
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
