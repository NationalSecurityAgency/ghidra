/* ###
 * IP: Apache License 2.0
 */
package ghidra.app.plugin.core.analysis.rust.demangler;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
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
			}
			catch (DemangledException e) {
				fail("Couldn't demangle symbol " + mangled);
			}
		}
	}

	@Test
	public void upstream_demangleCrateWithLeadingDigit() {
		assertDemangleAlternate("_RNvC6_123foo3bar", "123foo::bar");
	}

	@Test
	public void upstream_demangleCrateWithZeroDisambiguator() {
		assertDemangle("_RC4f128", "f128");
		assertDemangleAlternate("_RC4f128", "f128");
	}

	@Test
	public void upstream_demangleUtf8Idents() {
		String expected =
			"utf8_idents::\u10e1\u10d0\u10ed\u10db\u10d4\u10da\u10d0\u10d3_\u10d2\u10d4\u10db\u10e0\u10d8\u10d4\u10da\u10d8_\u10e1\u10d0\u10d3\u10d8\u10da\u10d8";
		assertDemangleAlternate("_RNqCs4fqI2P2rA04_11utf8_identsu30____7hkackfecea1cbdathfdh9hlq6y",
			expected);
	}

	@Test
	public void upstream_demangleClosure() {
		assertDemangleAlternate("_RNCNCNgCs6DXkGYLi8lr_2cc5spawn00B5_",
			"cc::spawn::{closure#0}::{closure#0}");
		String expected =
			"<core::slice::Iter<u8> as core::iter::iterator::Iterator>::rposition::<core::slice::memchr::memrchr::{closure#1}>::{closure#0}";
		assertDemangleAlternate(
			"_RNCINkXs25_NgCsbmNqQUJIY6D_4core5sliceINyB9_4IterhENuNgNoBb_4iter8iterator8Iterator9rpositionNCNgNpB9_6memchr7memrchrs_0E0Bb_",
			expected);
	}

	@Test
	public void upstream_demangleDynTrait() {
		assertDemangleAlternate(
			"_RINbNbCskIICzLVDPPb_5alloc5alloc8box_freeDINbNiB4_5boxed5FnBoxuEp6OutputuEL_ECs1iopQbuBiw2_3std",
			"alloc::alloc::box_free::<dyn alloc::boxed::FnBox<(), Output = ()>>");
	}

	@Test
	public void upstream_demanglePatTy() {
		assertDemangleAlternate("_RMC0WmRm1_m9_", "<u32 is 1..=9>");
		assertDemangleAlternate("_RMC0WmORm1_m2_Rm5_m6_E", "<u32 is 1..=2 | 5..=6>");
		assertNull(RustDemanglerV0.demangle("_RMC0WmORm1_m2_Rm5_m6_"));
	}

	@Test
	public void upstream_demangleConstGenericsPreview() {
		assertDemangleAlternate("_RMC0INtC8arrayvec8ArrayVechKj7b_E",
			"<arrayvec::ArrayVec<u8, 123>>");
		assertConst("j7b_", "123", "123usize");
	}

	@Test
	public void upstream_demangleMinConstGenerics() {
		assertConst("p", "_", null);
		assertConst("hb_", "11", "11u8");
		assertConst("off00ff00ff00ff00ff_", "0xff00ff00ff00ff00ff", "0xff00ff00ff00ff00ffu128");
		assertConst("s98_", "152", "152i16");
		assertConst("anb_", "-11", "-11i8");
		assertConst("b0_", "false", null);
		assertConst("b1_", "true", null);
		assertConst("c76_", "'v'", null);
		assertConst("c22_", "'\"'", null);
		assertConst("ca_", "'\\n'", null);
		assertConst("c2202_", "'\u2202'", null);
	}

	@Test
	public void upstream_demangleConstStr() {
		assertConst("e616263_", "{*\"abc\"}", null);
		assertConst("e27_", "{*\"'\"}", null);
		assertConst("e090a_", "{*\"\\t\\n\"}", null);
		assertConst("ee28882c3bc_", "{*\"\u2202\u00fc\"}", null);
		assertConst(
			"ee183a1e18390e183ade1839be18394e1839ae18390e183935fe18392e18394e1839be183a0e18398e18394e1839ae183985fe183a1e18390e18393e18398e1839ae18398_",
			"{*\"\u10e1\u10d0\u10ed\u10db\u10d4\u10da\u10d0\u10d3_\u10d2\u10d4\u10db\u10e0\u10d8\u10d4\u10da\u10d8_\u10e1\u10d0\u10d3\u10d8\u10da\u10d8\"}",
			null);
		assertConst(
			"ef09f908af09fa688f09fa686f09f90ae20c2a720f09f90b6f09f9192e29895f09f94a520c2a720f09fa7a1f09f929bf09f929af09f9299f09f929c_",
			"{*\"\ud83d\udc0a\ud83e\udd88\ud83e\udd86\ud83d\udc2e \u00a7 \ud83d\udc36\ud83d\udc52\u2615\ud83d\udd25 \u00a7 \ud83e\udde1\ud83d\udc9b\ud83d\udc9a\ud83d\udc99\ud83d\udc9c\"}",
			null);
	}

	@Test
	public void upstream_demangleConstRefStr() {
		assertConst("Re616263_", "\"abc\"", null);
		assertConst("Re27_", "\"'\"", null);
		assertConst("Re090a_", "\"\\t\\n\"", null);
		assertConst("Ree28882c3bc_", "\"\u2202\u00fc\"", null);
		assertConst(
			"Ree183a1e18390e183ade1839be18394e1839ae18390e183935fe18392e18394e1839be183a0e18398e18394e1839ae183985fe183a1e18390e18393e18398e1839ae18398_",
			"\"\u10e1\u10d0\u10ed\u10db\u10d4\u10da\u10d0\u10d3_\u10d2\u10d4\u10db\u10e0\u10d8\u10d4\u10da\u10d8_\u10e1\u10d0\u10d3\u10d8\u10da\u10d8\"",
			null);
		assertConst(
			"Ref09f908af09fa688f09fa686f09f90ae20c2a720f09f90b6f09f9192e29895f09f94a520c2a720f09fa7a1f09f929bf09f929af09f9299f09f929c_",
			"\"\ud83d\udc0a\ud83e\udd88\ud83e\udd86\ud83d\udc2e \u00a7 \ud83d\udc36\ud83d\udc52\u2615\ud83d\udd25 \u00a7 \ud83e\udde1\ud83d\udc9b\ud83d\udc9a\ud83d\udc99\ud83d\udc9c\"",
			null);
	}

	@Test
	public void upstream_demangleConstRef() {
		assertConst("Rp", "{&_}", null);
		assertConst("Rh7b_", "{&123}", null);
		assertConst("Rb0_", "{&false}", null);
		assertConst("Rc58_", "{&'X'}", null);
		assertConst("RRRh0_", "{&&&0}", null);
		assertConst("RRRe_", "{&&\"\"}", null);
		assertConst("QAE", "{&mut []}", null);
	}

	@Test
	public void upstream_demangleConstArray() {
		assertConst("AE", "{[]}", null);
		assertConst("Aj0_E", "{[0]}", null);
		assertConst("Ah1_h2_h3_E", "{[1, 2, 3]}", null);
		assertConst("ARe61_Re62_Re63_E", "{[\"a\", \"b\", \"c\"]}", null);
		assertConst("AAh1_h2_EAh3_h4_EE", "{[[1, 2], [3, 4]]}", null);
	}

	@Test
	public void upstream_demangleConstTuple() {
		assertConst("TE", "{()}", null);
		assertConst("Tj0_E", "{(0,)}", null);
		assertConst("Th1_b0_E", "{(1, false)}", null);
		assertConst("TRe616263_c78_RAh1_h2_h3_EE", "{(\"abc\", 'x', &[1, 2, 3])}", null);
	}

	@Test
	public void upstream_demangleConstAdt() {
		assertConst(
			"VNvINtNtC4core6option6OptionjE4NoneU",
			"{core::option::Option::<usize>::None}", null);
		assertConst(
			"VNvINtNtC4core6option6OptionjE4SomeTj0_E",
			"{core::option::Option::<usize>::Some(0)}", null);
		assertConst(
			"VNtC3foo3BarS1sRe616263_2chc78_5sliceRAh1_h2_h3_EE",
			"{foo::Bar { s: \"abc\", ch: 'x', slice: &[1, 2, 3] }}", null);
	}

	@Test
	public void upstream_demangleExponentialExplosion() {
		String symbol =
			"_RMC0" + "TTTTTT" + "p" + "B8_E" + "B7_E" + "B6_E" + "B5_E" + "B4_E" + "B3_E";
		String expected =
			"<((((((_, _), (_, _)), ((_, _), (_, _))), (((_, _), (_, _)), ((_, _), (_, _)))), ((((_, _), (_, _)), ((_, _), (_, _))), (((_, _), (_, _)), ((_, _), (_, _))))), (((((_, _), (_, _)), ((_, _), (_, _))), (((_, _), (_, _)), ((_, _), (_, _)))), ((((_, _), (_, _)), ((_, _), (_, _))), (((_, _), (_, _)), ((_, _), (_, _))))))>";
		assertDemangleAlternate(symbol, expected);
	}

	@Test
	public void upstream_demangleThinlto() {
		assertDemangleAlternate("_RC3foo.llvm.9D1C9369", "foo");
		assertDemangleAlternate("_RC3foo.llvm.9D1C9369@@16", "foo");
		assertDemangleAlternate("_RNvC9backtrace3foo.llvm.A5310EB9", "backtrace::foo");
	}

	@Test
	public void upstream_demangleExtraSuffix() {
		assertDemangleAlternate(
			"_RNvNtNtNtNtCs92dm3009vxr_4rand4rngs7adapter9reseeding4fork23FORK_HANDLER_REGISTERED.0.0",
			"rand::rngs::adapter::reseeding::fork::FORK_HANDLER_REGISTERED.0.0");
	}

	@Test
	public void upstream_demanglingLimits() throws IOException {
		List<String> lines =
			AbstractGenericTest.loadTextResource(getClass(), "early-recursion-limit.txt");
		for (String line : lines) {
			String symbol = line.trim();
			if (symbol.isEmpty() || symbol.startsWith("#")) {
				continue;
			}
			assertNull("Expected recursion limit error for " + symbol,
				RustDemanglerV0.demangle(symbol));
		}

		String recursionSymbol =
			"RIC20tRYIMYNRYFG05_EB5_B_B6_RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR" +
				"RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRB_E";
		String demangled = RustDemanglerV0.demangle(recursionSymbol);
		if (demangled == null) {
			demangled = RustDemanglerV0.RECURSION_LIMIT_MESSAGE;
		}
		assertTrue(demangled.contains(RustDemanglerV0.RECURSION_LIMIT_MESSAGE));
	}

//=================================================================================================
// Ported from Linux perf test: 
// https://github.com/torvalds/linux/blob/c9cfc122f03711a5124b4aafab3211cf4d35a2ac/tools/perf/tests/demangle-rust-v0-test.c#L9
//=================================================================================================		

	@Test
	public void perfToolCases() {
		assertDemangleAlternate(
			"_RNvMsr_NtCs3ssYzQotkvD_3std4pathNtB5_7PathBuf3newCs15kBYyAo9fc_7mycrate",
			"<std::path::PathBuf>::new");
		assertDemangleAlternate("_RNvCs15kBYyAo9fc_7mycrate7example", "mycrate::example");
		assertDemangleAlternate(
			"_RNvMs_Cs4Cv8Wi1oAIB_7mycrateNtB4_7Example3foo",
			"<mycrate::Example>::foo");
		assertDemangleAlternate(
			"_RNvXCs15kBYyAo9fc_7mycrateNtB2_7ExampleNtB2_5Trait3foo",
			"<mycrate::Example as mycrate::Trait>::foo");
		assertDemangleAlternate(
			"_RNvMCs7qp2U7fqm6G_7mycrateNtB2_7Example3foo",
			"<mycrate::Example>::foo");
		assertDemangleAlternate(
			"_RNvMs_Cs7qp2U7fqm6G_7mycrateNtB4_7Example3bar",
			"<mycrate::Example>::bar");
		assertDemangleAlternate(
			"_RNvYNtCs15kBYyAo9fc_7mycrate7ExampleNtB4_5Trait7exampleB4_",
			"<mycrate::Example as mycrate::Trait>::example");
		assertDemangleAlternate(
			"_RNCNvCsgStHSCytQ6I_7mycrate4main0B3_",
			"mycrate::main::{closure#0}");
		assertDemangleAlternate(
			"_RNCNvCsgStHSCytQ6I_7mycrate4mains_0B3_",
			"mycrate::main::{closure#1}");
		assertDemangleAlternate(
			"_RINvCsgStHSCytQ6I_7mycrate7examplelKj1_EB2_",
			"mycrate::example::<i32, 1>");
		assertDemangleAlternate(
			"_RINvCs7qp2U7fqm6G_7mycrate7exampleFG0_RL1_hRL0_tEuEB2_",
			"mycrate::example::<for<'a, 'b> fn(&'a u8, &'b u16)>");
		assertDemangleAlternate(
			"_RINvCs7qp2U7fqm6G_7mycrate7exampleKy12345678_EB2_",
			"mycrate::example::<305419896>");
		assertDemangleAlternate(
			"_RNvNvMCsd9PVOYlP1UU_7mycrateINtB4_7ExamplepKpE3foo14EXAMPLE_STATIC",
			"<mycrate::Example<_, _>>::foo::EXAMPLE_STATIC");
		assertDemangleAlternate(
			"_RINvCs7qp2U7fqm6G_7mycrate7exampleAtj8_EB2_",
			"mycrate::example::<[u16; 8]>");
		assertDemangleAlternate(
			"_RINvCs7qp2U7fqm6G_7mycrate7exampleNtB2_7ExampleBw_EB2_",
			"mycrate::example::<mycrate::Example, mycrate::Example>");
		assertDemangleAlternate(
			"_RINvMsY_NtCseXNvpPnDBDp_3std4pathNtB6_4Path3neweECs7qp2U7fqm6G_7mycrate",
			"<std::path::Path>::new::<str>");
		assertDemangleAlternate(
			"_RNvNvNvCs7qp2U7fqm6G_7mycrate7EXAMPLE7___getit5___KEY",
			"mycrate::EXAMPLE::__getit::__KEY");
	}

	@Test
	public void upstream_recursionLimitLeaks() {
		for (String[] pair : new String[][] { { "p", "_" }, { "Rp", "&_" }, { "C1x", "x" } }) {
			String symLeaf = pair[0];
			String expectedLeaf = pair[1];
			StringBuilder sym = new StringBuilder("_RIC0p");
			StringBuilder expected = new StringBuilder("::<_");
			for (int i = 0; i < RustDemanglerV0.MAX_DEPTH * 2; i++) {
				sym.append(symLeaf);
				expected.append(", ").append(expectedLeaf);
			}
			sym.append('E');
			expected.append('>');
			assertDemangleAlternate(sym.toString(), expected.toString());
		}
	}

	@Test
	public void upstream_recursionLimitBackrefFreeBypass() {
		int depth = 100_000;
		StringBuilder sym = new StringBuilder("_RIC").append(depth);
		int backrefStart = sym.length() - 2;
		for (int i = 0; i < depth; i++) {
			sym.append('R');
		}
		sym.append('B');
		sym.append(Character.forDigit((backrefStart - 1) % 36, 36));
		sym.append('_');
		sym.append('E');

		String demangled = RustDemanglerV0.demangle(sym.toString());
		if (demangled == null) {
			demangled = RustDemanglerV0.RECURSION_LIMIT_MESSAGE;
		}
		assertTrue(demangled.contains(RustDemanglerV0.RECURSION_LIMIT_MESSAGE));
	}

	private static void assertConst(String payload, String displayValue, String hashedValue) {
		assertDemangleAlternate("_RIC0K" + payload + "E", "::<" + displayValue + ">");
		if (hashedValue != null) {
			assertDemangle("_RIC0K" + payload + "E", "::<" + hashedValue + ">");
		}
	}

	private static void assertDemangle(String mangled, String expected) {
		String demangled = RustDemanglerV0.demangle(mangled);
		assertNotNull("Failed to demangle symbol " + mangled, demangled);
		assertEquals("Unexpected demangle result for " + mangled, expected, demangled);
	}

	private static void assertDemangleAlternate(String mangled, String expected) {
		String demangled = RustDemanglerV0.demangleAlternate(mangled);
		assertNotNull("Failed to demangle symbol " + mangled, demangled);
		assertEquals("Unexpected demangle result for " + mangled, expected, demangled);
	}
}
