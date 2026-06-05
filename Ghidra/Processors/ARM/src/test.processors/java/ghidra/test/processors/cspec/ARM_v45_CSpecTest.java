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

public class ARM_v45_CSpecTest extends CSpecPrototypeTest {
	//ARM_LE_32_v8_default___stdcall
	private static final String LANGUAGE_ID = "ARM:LE:32:v6";
	private static final String COMPILER_SPEC_ID = "default";

	private static final String CALLING_CONVENTION = "__stdcall";

	private static final String[] EXPECTED_PROTOTYPE_ERRORS = {
		"paramsPrimitiveIdentical_7",
		"paramsPrimitiveAlternate_8",
		"paramsPrimitiveAlternate_9",
		"paramsPrimitiveIdentical_13",
		"paramsPrimitiveAlternate_14",
		"paramsPrimitiveAlternate_15",
		"paramsPrimitiveAlternate_16",
		"paramsPrimitiveAlternate_17",
		"paramsSingletonStruct_23",
		"paramsSingletonStruct_24",
		"paramsPairStruct_27",
		"paramsPairStruct_28",
		"paramsPairStruct_29",
		"paramsPairStruct_30",
		"paramsPairStruct_31",
		"paramsTripStruct_33",
		"paramsTripStruct_34",
		"paramsTripStruct_35",
		"paramsTripStruct_36",
		"paramsTripStruct_37",
		"paramsTripStruct_38",
		"paramsQuadStruct_40",
		"paramsQuadStruct_41",
		"paramsQuadStruct_42",
		"paramsQuadStruct_43",
		"paramsQuadStruct_44",
		"paramsQuadStruct_45",
		"paramsMixedStruct_46",
		"paramsMixedStruct_47",
		"paramsMixedStruct_48",
		"paramsMixedStruct_49",
		"paramsVariadic_L_d_L_d_L_d_L_d_L_d_52",
		"paramsMisc_54",
		"paramsMisc_55",
		"paramsUnion_61",
		"paramsUnion_62",
		"paramsUnion_64",
		"paramsUnion_68",
		"paramsUnion_69",
		"paramsUnion_70",
		"paramsUnion_71",
		"paramsUnion_72",
		"paramsUnion_73",
		"paramsUnion_74",
		"paramsUnion_75",
		"paramsUnion_76",
		"returnTriple_87",
		"returnQuad_88",
		"returnUnion_90",
		"returnPair_93",
		"returnPair_99",
		"returnPair_108",
		"returnSingleton_116",
		"returnUnion_121",
		"returnSingleton_126",
		"returnUnion_130",
	};

	public ARM_v45_CSpecTest() throws Exception {
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
