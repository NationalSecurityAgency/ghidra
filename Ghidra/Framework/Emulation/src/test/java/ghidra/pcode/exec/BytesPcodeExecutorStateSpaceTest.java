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
package ghidra.pcode.exec;

import static org.junit.Assert.assertEquals;

import java.io.File;

import org.junit.Before;
import org.junit.Test;

import generic.ULongSpan;
import generic.ULongSpan.ULongSpanSet;
import generic.test.AbstractGTest;
import ghidra.GhidraTestApplicationLayout;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighLanguageHelper;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.address.AddressSpace;

public class BytesPcodeExecutorStateSpaceTest extends AbstractGTest {

	@Before
	public void setUp() throws Exception {
		if (!Application.isInitialized()) {
			Application.initializeApplication(
				new GhidraTestApplicationLayout(new File(getTestDirectoryPath())),
				new ApplicationConfiguration());
		}
	}

	@Test
	public void testComputeUninitialized64() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();
		AddressSpace space = language.getDefaultSpace();
		BytesPcodeExecutorStateSpace<Void> stateSpace =
			new BytesPcodeExecutorStateSpace<Void>(language, space, null);

		ULongSpanSet.of(ULongSpan.span(0, 9));

		assertEquals(ULongSpanSet.of(
			ULongSpan.span(0, 7)),
			stateSpace.computeUninitialized(0, 8));
		assertEquals(ULongSpanSet.of(
			ULongSpan.span(0x7fff_ffff_ffff_fff8L, 0x7fff_ffff_ffff_ffffL)),
			stateSpace.computeUninitialized(0x7fff_ffff_ffff_fff8L, 8));
		assertEquals(ULongSpanSet.of(
			ULongSpan.span(0x7fff_ffff_ffff_fffcL, 0x8000_0000_0000_0003L)),
			stateSpace.computeUninitialized(0x7fff_ffff_ffff_fffcL, 8));
		assertEquals(ULongSpanSet.of(
			ULongSpan.span(0x8000_0000_0000_0008L, 0x8000_0000_0000_000fL)),
			stateSpace.computeUninitialized(0x8000_0000_0000_0008L, 8));
		assertEquals(ULongSpanSet.of(
			ULongSpan.span(0xffff_ffff_ffff_fffcL, 0xffff_ffff_ffff_ffffL),
			ULongSpan.span(0, 3)),
			stateSpace.computeUninitialized(0xffff_ffff_ffff_fffcL, 8));
	}

	@Test
	public void testComputeUninitialized32() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();
		AddressSpace space = language.getAddressFactory().getRegisterSpace();
		BytesPcodeExecutorStateSpace<Void> stateSpace =
			new BytesPcodeExecutorStateSpace<Void>(language, space, null);

		ULongSpanSet.of(ULongSpan.span(0, 9));

		assertEquals(ULongSpanSet.of(
			ULongSpan.span(0, 7)),
			stateSpace.computeUninitialized(0, 8));
		assertEquals(ULongSpanSet.of(
			ULongSpan.span(0x7fff_fff8L, 0x7fff_ffffL)),
			stateSpace.computeUninitialized(0x7fff_fff8L, 8));
		assertEquals(ULongSpanSet.of(
			ULongSpan.span(0x7fff_fffcL, 0x8000_0003L)),
			stateSpace.computeUninitialized(0x7fff_fffcL, 8));
		assertEquals(ULongSpanSet.of(
			ULongSpan.span(0x8000_0008L, 0x8000_000fL)),
			stateSpace.computeUninitialized(0x8000_0008L, 8));
		assertEquals(ULongSpanSet.of(
			ULongSpan.span(0xffff_fffcL, 0xffff_ffffL),
			ULongSpan.span(0, 3)),
			stateSpace.computeUninitialized(0xffff_fffcL, 8));
	}
}
