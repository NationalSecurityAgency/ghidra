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
//Developer script
//@category Symbol
import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.microsoft.MicrosoftDemangler;

public class MicrosoftDemanglerScript extends GhidraScript {

	private MicrosoftDemangler demangler;

	@Override
	protected void run() throws Exception {

		demangler = new MicrosoftDemangler();

//		demangle("??$_LStrcoll@_W@std@@YAHPB_W000PBU_Collvec@@@Z");

		demangle("??$?0G@?$allocator@U_Container_proxy@std@@@std@@QAE@ABV?$allocator@G@1@@Z");

		/*
		
		demangle("??0__non_rtti_object@@QAE@PBD@Z");
		demangle("??0bad_cast@@AAE@PBQBD@Z");
		demangle("??0bad_cast@@QAE@ABQBD@Z");
		demangle("??0bad_cast@@QAE@ABV0@@Z");
		demangle("??0bad_cast@@QAE@PBD@Z");
		demangle("??0bad_typeid@@QAE@ABV0@@Z");
		demangle("??0bad_typeid@@QAE@PBD@Z");
		demangle("??0exception@@QAE@ABQBD@Z");
		demangle("??0exception@@QAE@ABQBDH@Z");
		demangle("??0exception@@QAE@ABV0@@Z");
		demangle("??0exception@@QAE@XZ");
		demangle("??1__non_rtti_object@@UAE@XZ");
		demangle("??1bad_cast@@UAE@XZ");
		demangle("??1bad_typeid@@UAE@XZ");
		demangle("??1exception@@UAE@XZ");
		demangle("??1type_info@@UAE@XZ");
		demangle("??2@YAPAXI@Z");
		demangle("??2@YAPAXIHPBDH@Z");
		demangle("??3@YAXPAX@Z");
		demangle("??4__non_rtti_object@@QAEAAV0@ABV0@@Z");
		demangle("??4bad_cast@@QAEAAV0@ABV0@@Z");
		demangle("??4bad_typeid@@QAEAAV0@ABV0@@Z");
		demangle("??4exception@@QAEAAV0@ABV0@@Z");
		demangle("??8type_info@@QBEHABV0@@Z");
		demangle("??9type_info@@QBEHABV0@@Z");
		demangle("??_7__non_rtti_object@@6B@");
		demangle("??_7bad_cast@@6B@");
		demangle("??_7bad_typeid@@6B@");
		demangle("??_7exception@@6B@");
		demangle("??_E__non_rtti_object@@UAEPAXI@Z");
		demangle("??_Ebad_cast@@UAEPAXI@Z");
		demangle("??_Ebad_typeid@@UAEPAXI@Z");
		demangle("??_Eexception@@UAEPAXI@Z");
		demangle("??_Fbad_cast@@QAEXXZ");
		demangle("??_Fbad_typeid@@QAEXXZ");
		demangle("??_G__non_rtti_object@@UAEPAXI@Z");
		demangle("??_Gbad_cast@@UAEPAXI@Z");
		demangle("??_Gbad_typeid@@UAEPAXI@Z");
		demangle("??_Gexception@@UAEPAXI@Z");
		demangle("??_U@YAPAXI@Z");
		demangle("??_U@YAPAXIHPBDH@Z");
		demangle("??_V@YAXPAX@Z");
		demangle("?_query_new_handler@@YAP6AHI@ZXZ");
		demangle("?_query_new_mode@@YAHXZ");
		demangle("?_set_new_handler@@YAP6AHI@ZP6AHI@Z@Z");
		demangle("?_set_new_mode@@YAHH@Z");
		demangle("?_set_se_translator@@YAP6AXIPAU_EXCEPTION_POINTERS@@@ZP6AXI0@Z@Z");
		demangle("?before@type_info@@QBEHABV1@@Z");
		demangle("?name@type_info@@QBEPBDXZ");
		demangle("?raw_name@type_info@@QBEPBDXZ");
		demangle("?set_new_handler@@YAP6AXXZP6AXXZ@Z");
		demangle("?set_terminate@@YAP6AXXZP6AXXZ@Z");
		demangle("?set_unexpected@@YAP6AXXZP6AXXZ@Z");
		demangle("?terminate@@YAXXZ");
		demangle("?unexpected@@YAXXZ");
		demangle("?what@exception@@UBEPBDXZ");
		*/
	}

	private void demangle(String mangled) throws Exception {
		DemangledObject demangled = demangler.demangle(mangled);
		printf("magled %s\ndemangled %s", mangled, demangled);
	}
}
