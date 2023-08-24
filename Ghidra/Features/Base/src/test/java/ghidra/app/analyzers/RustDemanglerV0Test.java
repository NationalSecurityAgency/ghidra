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
package ghidra.app.analyzers;

import static org.junit.Assert.fail;

import org.junit.Test;

import ghidra.app.plugin.core.analysis.rust.demangler.RustDemangler;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.DemangledObject;

public class RustDemanglerV0Test {
	
	private static String[] symbols = {
		"_RNvCsL39EUhRVRM_5tests4main",
		"_RNvCsL39EUhRVRM_5tests6test_1",
		"_RNvMCsL39EUhRVRM_5testsNtB2_10TestStruct8method_1",
		"_RNvNtNtCsL39EUhRVRM_5tests5stuff6stuff26test_3",
		"_RNCINvNtCsekVQb2M45Qb_3std2rt10lang_startuE0CsL39EUhRVRM_5tests.llvm.3070730145566890858",
		"_RNvYNtNtCsheJZGYyU57U_5alloc6string6StringNtNtCscuN2HtZYDVi_4core3fmt5Write9write_fmtCsL39EUhRVRM_5tests",
		"_RNSNvYNCINvNtCsekVQb2M45Qb_3std2rt10lang_startuE0INtNtNtCscuN2HtZYDVi_4core3ops8function6FnOnceuE9call_once6vtableCsL39EUhRVRM_5tests.llvm.3070730145566890858",
		"_RNvXss_NtCsheJZGYyU57U_5alloc3vecINtB5_3VecAhj4_ENtNtCscuN2HtZYDVi_4core3fmt5Debug3fmtCsL39EUhRVRM_5tests",
		"_RNSNvYNCINvNtCsekVQb2M45Qb_3std2rt10lang_startuE0INtNtNtCscuN2HtZYDVi_4core3ops8function6FnOnceuE9call_once6vtableCsL39EUhRVRM_5tests.llvm.6912067296627029035",
		"_RNvXs_CsL39EUhRVRM_5testsNtB4_10TestStructNtB4_9TestTrait14trait_method_1",
		"_RNvXs_CsL39EUhRVRM_5testsNtB4_10TestStructNtB4_9TestTrait14trait_method_2",
		"_RNvXs_CsL39EUhRVRM_5testsNtB4_10TestStructNtB4_9TestTrait14trait_method_3",
		"_RNvXNtCscuN2HtZYDVi_4core3fmtQNtNtCsheJZGYyU57U_5alloc6string6StringNtB2_5Write10write_charCsL39EUhRVRM_5tests",
		"_RNvXNtCscuN2HtZYDVi_4core3fmtQNtNtCsheJZGYyU57U_5alloc6string6StringNtB2_5Write9write_fmtCsL39EUhRVRM_5tests",
		"_RNvXNtCscuN2HtZYDVi_4core3fmtQNtNtCsheJZGYyU57U_5alloc6string6StringNtB2_5Write9write_strCsL39EUhRVRM_5tests",
		"_RNvNtCsL39EUhRVRM_5tests5stuff6test_2",
		"_RNvMs_NtCsheJZGYyU57U_5alloc7raw_vecINtB4_6RawVechE16reserve_for_pushCsL39EUhRVRM_5tests",
		"_RNvXsX_NtCscuN2HtZYDVi_4core3fmtReNtB5_7Display3fmtCsL39EUhRVRM_5tests",
		"_RNvXsV_NtCscuN2HtZYDVi_4core3fmtRAhj4_NtB5_5Debug3fmtCsL39EUhRVRM_5tests",
		"_RNvXsV_NtCscuN2HtZYDVi_4core3fmtRhNtB5_5Debug3fmtCsL39EUhRVRM_5tests",
		"_RNvYNtNtCsheJZGYyU57U_5alloc6string6StringNtNtCscuN2HtZYDVi_4core3fmt5Write9write_fmtCsL39EUhRVRM_5tests",
		"_RNCINkXs25_NgCsbmNqQUJIY6D_4core5sliceINyB9_4IterhENuNgNoBb_4iter8iterator8Iterator9rpositionNCNgNpB9_6memchr7memrchrs_0E0Bb_",
	};
	
	
	private static String[] names = {
		"tests::main",
		"tests::test_1",
		"<tests::tests::TestStruct>::method_1",
		"tests::stuff::stuff2::test_3",
		"std::rt::lang_start<()>::{closure#0}",
		"<alloc::string::String as core::fmt::Write>::write_fmt",
		"<std::rt::lang_start<()>::{closure#0} as core::ops::function::FnOnce<()>>::call_once::vtable",
		"<alloc::vec::Vec<[u8; 4usize]> as core::fmt::Debug>::fmt",
		"<std::rt::lang_start<()>::{closure#0} as core::ops::function::FnOnce<()>>::call_once::vtable",
		"<tests::TestStruct as tests::TestTrait>::trait_method_1",
		"<tests::TestStruct as tests::TestTrait>::trait_method_2",
		"<tests::TestStruct as tests::TestTrait>::trait_method_3",
		"<&mut alloc::string::String as core::fmt::Write>::write_char",
		"<&mut alloc::string::String as core::fmt::Write>::write_fmt",
		"<&mut alloc::string::String as core::fmt::Write>::write_str",
		"tests::stuff::test_2",
		"<alloc::raw_vec::alloc::raw_vec::RawVec<u8>>::reserve_for_push",
		"<&str as core::fmt::Display>::fmt",
		"<&[u8; 4usize] as core::fmt::Debug>::fmt",
		"<&u8 as core::fmt::Debug>::fmt",
		"<alloc::string::String as core::fmt::Write>::write_fmt",
		"<core::slice::Iter<u8> as core::iter::iterator::Iterator>::rposition<core::slice::memchr::memrchr::{closure#0}>::{closure#0}",
	};
	
	@Test
	public void demangle() {
		RustDemangler demangler = new RustDemangler();
		for (int i = 0; i < symbols.length; i++) {
			String mangled = symbols[i];
			String name = names[i];
			
			try {
				DemangledObject demangled = demangler.demangle(mangled);
				if (name.equals(demangled.getName())) {
					fail("Demangled symbol to wrong name " + mangled);
				}
			} catch (DemangledException e) {
				fail("Couldn't demangle symbol " + mangled);
			}
		}
	}
}
