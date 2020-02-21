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
package help.screenshot;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import javax.swing.table.TableColumn;

import org.junit.Test;

import ghidra.app.plugin.core.strings.ViewStringsProvider;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.test.ToyProgramBuilder;

public class ViewStringsPluginScreenShots extends GhidraScreenShotGenerator {

	public ViewStringsPluginScreenShots() {
		super();
	}

	@Override
	public void loadProgram() throws Exception {

		ToyProgramBuilder builder = new ToyProgramBuilder("String Examples", false);
		builder.createMemory("RAM", "0x0", 0x2000);

		builder.createString("0x100", "Hello World!\n", StandardCharsets.US_ASCII, true,
			StringDataType.dataType);

		Data nonStringBytes =
			builder.createString("0x150", bytes(0, 1, 2, 3, 4, 0x80, 0x81, 0x82, 0x83),
				StandardCharsets.US_ASCII, StringDataType.dataType);

		Data CN_HOVERCRAFT =
			builder.createString("0x200", "\u6211\u96bb\u6c23\u588a\u8239\u88dd\u6eff\u6652\u9c54",
				StandardCharsets.UTF_16, true, UnicodeDataType.dataType);

		builder.createString("0x250", "Exception %s\n\tline: %d\n", StandardCharsets.US_ASCII, true,
			StringDataType.dataType);

		builder.createString("0x450",
			"Roses are \u001b[0;31mred\u001b[0m, violets are \u001b[0;34mblue. Hope you enjoy terminal hue",
			StandardCharsets.US_ASCII, true, StringDataType.dataType);

		Data tempDegrees = builder.createString("0x500", "Temp \u2103", Charset.forName("UTF-32LE"),
			true, Unicode32DataType.dataType);

		builder.withTransaction(() -> {
			RenderUnicodeSettingsDefinition.RENDER.setEnumValue(nonStringBytes,
				RenderUnicodeSettingsDefinition.RENDER_ENUM.BYTE_SEQ);
			RenderUnicodeSettingsDefinition.RENDER.setEnumValue(tempDegrees,
				RenderUnicodeSettingsDefinition.RENDER_ENUM.ESC_SEQ);
			TranslationSettingsDefinition.TRANSLATION.setTranslatedValue(CN_HOVERCRAFT,
				"My hovercraft is full of eels");
			TranslationSettingsDefinition.TRANSLATION.setShowTranslated(CN_HOVERCRAFT, true);
		});

		program = builder.getProgram();

		runSwing(() -> {
			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.openProgram(program.getDomainFile());
		});

	}

	@Test
	public void testDefined_String_Table() {
		ViewStringsProvider provider = showProvider(ViewStringsProvider.class);
		TableColumn addrCol = provider.getTable().getColumnModel().getColumn(0);
		addrCol.setMaxWidth(200);

		TableColumn dataTypeCol = provider.getTable().getColumnModel().getColumn(3);
		dataTypeCol.setMaxWidth(200);

		captureIsolatedProvider(ViewStringsProvider.class, 600, 300);
	}

}
