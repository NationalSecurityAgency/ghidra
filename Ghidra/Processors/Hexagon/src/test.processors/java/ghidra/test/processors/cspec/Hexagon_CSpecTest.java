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

public class Hexagon_CSpecTest extends CSpecPrototypeTest {

	private static final String LANGUAGE_ID = "Hexagon:LE:32:default";
	private static final String COMPILER_SPEC_ID = "default";

	private static final String CALLING_CONVENTION = "__stdcall";

	private static final String[] EXPECTED_PROTOTYPE_ERRORS = {
		"paramsPrimitiveIdentical_0",
		"paramsPrimitiveIdentical_1",
		"paramsPrimitiveAlternate_8",
		"paramsPrimitiveAlternate_14",
		"paramsPrimitiveAlternate_16",
		"paramsSingletonStruct_18",
		"paramsSingletonStruct_19",
		"paramsPairStruct_25",
		"paramsPairStruct_26",
		"paramsTripStruct_32",
		"paramsTripStruct_33",
		"paramsQuadStruct_39",
		"paramsVariadic_I_I_C_C_S_S_I_I_L_L_50",
		"paramsMisc_54",
		"paramsUnion_56",
		"paramsUnion_57",
		"paramsUnion_63",
		"paramsUnion_64"
	};

	public Hexagon_CSpecTest() throws Exception {
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
