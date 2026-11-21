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
package ghidra.ghidrassist.apple;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

public class AppleBinaryContextTest {

	private static final String MACH_O = "Mac OS X Mach-O";
	private static final String ELF = "Executable and Linking Format (ELF)";

	@Test
	public void linuxElfIsNotApple() {
		AppleBinaryContext ctx = AppleBinaryContext.classify(ELF, "x86:LE:64:default",
			List.of(".text", ".rodata", ".data"), "/bin/ls");
		assertFalse(ctx.isMachO());
		assertFalse(ctx.isAppleSilicon());
		assertFalse(ctx.hasObjectiveC());
		assertFalse(ctx.hasSwift());
		assertFalse(ctx.mayBeArm64e());
		assertTrue(ctx.isX86_64());
	}

	@Test
	public void appleSiliconMachOIsDetected() {
		AppleBinaryContext ctx = AppleBinaryContext.classify(MACH_O,
			"AARCH64:LE:64:AppleSilicon", List.of("__TEXT", "__text", "__DATA"),
			"/Applications/Example.app/Contents/MacOS/Example");
		assertTrue(ctx.isMachO());
		assertTrue(ctx.isAppleSilicon());
		assertTrue(ctx.isAARCH64());
		assertFalse(ctx.isX86_64());
		assertFalse(ctx.hasObjectiveC());
		assertFalse(ctx.hasSwift());
	}

	@Test
	public void objectiveCRuntimeIsDetectedFromSectionNames() {
		AppleBinaryContext ctx = AppleBinaryContext.classify(MACH_O,
			"AARCH64:LE:64:AppleSilicon",
			List.of("__TEXT", "__objc_classlist", "__objc_methname", "__objc_selrefs"), "");
		assertTrue(ctx.hasObjectiveC());
		assertFalse(ctx.hasSwift());
	}

	@Test
	public void swiftRuntimeIsDetectedFromSectionNames() {
		AppleBinaryContext ctx = AppleBinaryContext.classify(MACH_O,
			"AARCH64:LE:64:AppleSilicon",
			List.of("__TEXT", "__swift5_types", "__swift5_proto"), "");
		assertFalse(ctx.hasObjectiveC());
		assertTrue(ctx.hasSwift());
	}

	@Test
	public void arm64eIsHintedFromPath() {
		AppleBinaryContext ctx = AppleBinaryContext.classify(MACH_O,
			"AARCH64:LE:64:AppleSilicon", List.of("__TEXT"),
			"/System/Library/dyld/arm64e/dyld_shared_cache_arm64e");
		assertTrue(ctx.mayBeArm64e());
	}

	@Test
	public void x86_64MachOIsStillMachO() {
		AppleBinaryContext ctx = AppleBinaryContext.classify(MACH_O, "x86:LE:64:default",
			List.of("__TEXT", "__text"), "/usr/bin/x86tool");
		assertTrue(ctx.isMachO());
		assertFalse(ctx.isAppleSilicon());
		assertFalse(ctx.isAARCH64());
		assertTrue(ctx.isX86_64());
	}

	@Test
	public void nullInputsDoNotCrash() {
		AppleBinaryContext ctx =
			AppleBinaryContext.classify(null, null, null, null);
		assertFalse(ctx.isMachO());
		assertFalse(ctx.isAppleSilicon());
		assertFalse(ctx.hasObjectiveC());
		assertFalse(ctx.hasSwift());
		assertFalse(ctx.mayBeArm64e());
		assertEquals("", ctx.languageId());
	}

	@Test
	public void summaryIsHumanReadable() {
		AppleBinaryContext ctx = AppleBinaryContext.classify(MACH_O,
			"AARCH64:LE:64:AppleSilicon",
			List.of("__TEXT", "__objc_classlist", "__swift5_types"),
			"/path/to/arm64e/binary");
		String s = ctx.summary();
		assertTrue(s, s.contains("Mach-O"));
		assertTrue(s, s.contains("Apple Silicon"));
		assertTrue(s, s.contains("Objective-C"));
		assertTrue(s, s.contains("Swift"));
		assertTrue(s, s.contains("arm64e"));
	}

	@Test
	public void promptPreambleEmptyForNonAppleBinary() {
		AppleBinaryContext ctx = AppleBinaryContext.classify(ELF, "x86:LE:64:default",
			List.of(".text"), "/bin/ls");
		assertEquals("", ctx.promptPreamble());
	}

	@Test
	public void promptPreambleMentionsObjcMsgSendWhenObjcIsPresent() {
		AppleBinaryContext ctx = AppleBinaryContext.classify(MACH_O,
			"AARCH64:LE:64:AppleSilicon", List.of("__objc_classlist"), "");
		String p = ctx.promptPreamble();
		assertTrue(p, p.contains("objc_msgSend"));
	}
}
