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
package ghidra.features.base.values;

import static org.junit.Assert.*;

import org.junit.Test;

import docking.widgets.values.AbstractValue;
import ghidra.app.script.SelectLanguageDialog;
import ghidra.features.base.values.LanguageValue;
import ghidra.features.base.values.LanguageValue.LangaugeValuePanel;
import ghidra.program.model.lang.LanguageCompilerSpecPair;

public class LanguageValueTest extends AbstractValueIntegrationTest {
	private static final String NAME = "Lang";
	private static final LanguageCompilerSpecPair LANG1 =
		new LanguageCompilerSpecPair("6502:LE:16:default", "default");
	private static final LanguageCompilerSpecPair LANG2 =
		new LanguageCompilerSpecPair("ARM:BE:32:v7", "default");

	@Test
	public void testLanguageValueNoDefault() {
		values.defineLanguage(NAME, null);

		assertTrue(values.isDefined(NAME));
		assertFalse(values.hasValue(NAME));

		values.setLanguage(NAME, LANG1);
		assertTrue(values.hasValue(NAME));

		assertEquals(LANG1, values.getLanguage(NAME));
	}

	@Test
	public void testLanguageValueWithDefault() {
		values.defineLanguage(NAME, LANG1);

		assertTrue(values.isDefined(NAME));
		assertTrue(values.hasValue(NAME));
		assertEquals(LANG1, values.getLanguage(NAME));

		values.setLanguage(NAME, LANG2);
		assertTrue(values.hasValue(NAME));

		assertEquals(LANG2, values.getLanguage(NAME));

		values.setLanguage(NAME, null);
		assertFalse(values.hasValue(NAME));
	}

	@Test
	public void testGetAsText() {
		LanguageValue value1 = new LanguageValue(NAME);
		LanguageValue value2 = new LanguageValue(NAME, LANG1);
		assertNull(value1.getAsText());
		assertEquals("6502:LE:16:default:default", value2.getAsText());
	}

	@Test
	public void testSetAsText() {
		LanguageValue v = new LanguageValue(NAME);
		assertEquals(LANG1, v.setAsText("6502:LE:16:default:default"));
		try {
			v.setAsText(null);
			fail("Expected exception");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testNoDefaultValueWithNoDialogInput() {
		values.defineLanguage(NAME, null);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertFalse(values.hasValue(NAME));
		assertNull(values.getLanguage(NAME));
	}

	@Test
	public void testNoDefaultValueWithDialogInput() {
		values.defineLanguage(NAME, null);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setLanguage(values.getAbstractValue(NAME), LANG1);
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(LANG1, values.getLanguage(NAME));
	}

	@Test
	public void testNoDefaultValueWithBadDialogInput() {
		values.defineLanguage(NAME, null);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setLanguage(values.getAbstractValue(NAME), "asdfa");
		pressOk();

		assertTrue(dialog.isShowing());
		pressCancel();
	}

	@Test
	public void testDefaultValueWithNoDialogInput() {
		values.defineLanguage(NAME, LANG1);
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(LANG1, values.getLanguage(NAME));
	}

	@Test
	public void testDefaultValueWithDialogInput() {
		values.defineLanguage(NAME, LANG1);
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setLanguage(values.getAbstractValue(NAME), LANG2);
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(LANG2, values.getLanguage(NAME));
	}

	protected void setLanguage(AbstractValue<?> nameValue, LanguageCompilerSpecPair lang) {
		LangaugeValuePanel languageWidget = (LangaugeValuePanel) nameValue.getComponent();
		pressButtonByName(languageWidget, "BrowseButton", false);
		SelectLanguageDialog langDialog = waitForDialogComponent(SelectLanguageDialog.class);
		runSwing(() -> {
			langDialog.setSelectedLanguage(lang);
		});

		pressButtonByText(langDialog, "Ok");

	}

	protected void setLanguage(AbstractValue<?> nameValue, String val) {
		LangaugeValuePanel languageWidget = (LangaugeValuePanel) nameValue.getComponent();
		runSwing(() -> {
			languageWidget.setText(val);
		});
	}
}
