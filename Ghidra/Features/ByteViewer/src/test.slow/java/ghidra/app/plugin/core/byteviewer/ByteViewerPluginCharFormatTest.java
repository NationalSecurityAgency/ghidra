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
package ghidra.app.plugin.core.byteviewer;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.Test;

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.NavigationHistoryPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.util.charset.CharsetInfoManager;

/**
 * Test for "chars" format 
 */
public class ByteViewerPluginCharFormatTest extends AbstractByteViewerPluginTest {

	@Override
	protected List<Class<? extends Plugin>> getDefaultPlugins() {
		return List.of(NavigationHistoryPlugin.class, NextPrevAddressPlugin.class,
			CodeBrowserPlugin.class);
	}

	@Override
	protected Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test2", "0x1001000", 0x2000);
		builder.setBytes("0x1001000", "abc".getBytes(StandardCharsets.US_ASCII));
		builder.setBytes("0x1001100", "\u6211\u7684\u6c23\u588a\u8239\u88dd\u6eff\u4e86\u9c3b\u9b5a"
				.getBytes(StandardCharsets.UTF_16BE));
		Program p = builder.getProgram();
		p.clearUndo();
		return p;
	}

	@Test
	public void testASCII() throws Exception {
		loadViews("Chars");

		ByteViewerComponent c = setView("Chars");
		goTo(addr(0x1001000));

		assertEquals("a", getField(c, addr(0x1001000)).getText());
		assertEquals("b", getField(c, addr(0x1001001)).getText());
		assertEquals("c", getField(c, addr(0x1001002)).getText());
		assertEquals(".", getField(c, addr(0x1001003)).getText());
	}

	@Test
	public void testIBM037() throws Exception {
		// IBM code page 37 (EBCDIC, completely unrelated to ASCII)
		loadViews("Chars");
		provider.setCharsetInfo(CharsetInfoManager.getInstance().get("IBM037"));

		ByteViewerComponent c = setView("Chars");
		goTo(addr(0x1001000));

		// instead of 'a', 'b', 'c', we get '/', 'A-accent', 'A-otheraccent'
		assertEquals("/", getField(c, addr(0x1001000)).getText());
		assertEquals("\u00c2", getField(c, addr(0x1001001)).getText());
		assertEquals("\u00c4", getField(c, addr(0x1001002)).getText());
		assertEquals(".", getField(c, addr(0x1001003)).getText());
	}

	@Test
	public void testUTF16_alignment_off() throws Exception {
		ByteViewerConfigOptions configOptions = provider.getConfigOptions().clone();
		configOptions.setUseCharAlignment(false);
		provider.updateConfigOptions(configOptions, null);

		loadViews("Chars");

		provider.setCharsetInfo(CharsetInfoManager.getInstance().get("UTF-16"));

		ByteViewerComponent c = setView("Chars");
		goTo(addr(0x1001100));

		// overlapping UTF-16 chars [62 11] [11 76]
		assertEquals("\u6211", getField(c, addr(0x1001100)).getText());
		assertEquals("\u1176", getField(c, addr(0x1001101)).getText());

		assertEquals(16, c.getNumberOfFields()); // should have 16 (overlapping) chars per row
	}

	@Test
	public void testUTF16_alignment_on() throws Exception {
		ByteViewerConfigOptions configOptions = provider.getConfigOptions().clone();
		configOptions.setUseCharAlignment(true);
		provider.updateConfigOptions(configOptions, null);

		loadViews("Chars");

		provider.setCharsetInfo(CharsetInfoManager.getInstance().get("UTF-16"));

		ByteViewerComponent c = setView("Chars");
		goTo(addr(0x1001100));

		assertEquals("\u6211", getField(c, addr(0x1001100)).getText());
		assertEquals("\u6211", getField(c, addr(0x1001101)).getText()); // still same value because addr is offcut

		assertEquals("\u7684", getField(c, addr(0x1001102)).getText());

		assertEquals(16 / 2, c.getNumberOfFields()); // should only have 8 chars per row instead of 16
	}

	@Test
	public void testUTF32_badval() throws Exception {
		ByteViewerConfigOptions configOptions = provider.getConfigOptions().clone();
		configOptions.setUseCharAlignment(true);
		provider.updateConfigOptions(configOptions, null);

		loadViews("Chars");

		provider.setCharsetInfo(CharsetInfoManager.getInstance().get("UTF-32"));

		ByteViewerComponent c = setView("Chars");
		goTo(addr(0x1001000));

		assertEquals(".", getField(c, addr(0x1001100)).getText());
	}

	@Test
	public void testWideChars() throws Exception {
		loadViews("Chars");

		provider.setCompactChars(true);
		provider.setCharsetInfo(CharsetInfoManager.getInstance().get("UTF-16"));

		ByteViewerComponent c = setView("Chars");
		goTo(addr(0x1001100));

		ByteField field = getField(c, addr(0x1001100));
		int compactWidth = field.getWidth();

		provider.setCompactChars(false);

		field = getField(c, addr(0x1001100));
		int wideWidth = field.getWidth();

		assertTrue(wideWidth == compactWidth * 2); // we know wide mode is 2x compact mode
	}
}
