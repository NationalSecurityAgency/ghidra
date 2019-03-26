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
package ghidra.app.plugin.core.stackeditor;

import static org.junit.Assert.assertNotNull;

import java.awt.Window;

import org.junit.Assert;
import org.junit.Before;

import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.UsrException;

public abstract class AbstractStackEditorProviderTest extends AbstractStackEditorTest {

	protected AbstractStackEditorProviderTest() {
		super(false);
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		setErrorGUIEnabled(false);
		env.showTool();
	}

	

//==================================================================================================
// Private Methods
//==================================================================================================	

	protected void setType(DataType dt, int row) {
		runSwing(() -> {
			getTable().requestFocus();
			model.setSelection(new int[] { row });
			try {
				model.add(dt);
			}
			catch (UsrException e) {
				Assert.fail(e.getMessage());
			}
		}, false);
		waitForSwing();
	}

	protected void assertStackEditorHidden(Function f) {
		String subTitle = StackEditorProvider.getProviderSubTitle(f);
		waitForCondition(() -> {
			return !isProviderShown(tool.getToolFrame(), "Stack Editor", subTitle);
		}, "Stack editor should not be showing: '" + subTitle + "'");
	}

	protected void assertStackEditorShowing(Function f) {
		String subTitle = StackEditorProvider.getProviderSubTitle(f);
		waitForCondition(() -> {
			return isProviderShown(tool.getToolFrame(), "Stack Editor", subTitle);
		}, "Stack editor should not be showing: '" + subTitle + "'");
	}

	protected void chooseOverwrite() throws Exception {
		Window dialog = waitForWindow("Overwrite Program Changes?", DEFAULT_WINDOW_TIMEOUT);
		assertNotNull("Did not get expected overwrite dialog prompt", dialog);
		pressButtonByText(dialog, "Overwrite");

		program.flushEvents();
		waitForSwing();
	}

	protected void chooseCancel() throws Exception {
		Window dialog = waitForWindow("Overwrite Program Changes?", DEFAULT_WINDOW_TIMEOUT);
		assertNotNull("Did not get expected overwrite dialog prompt", dialog);
		pressButtonByText(dialog, "Cancel");

		program.flushEvents();
		waitForSwing();
	}

	protected void apply() {
		performAction(applyAction, false);
	}

	protected String getParameterNameFromListing(int parameterIndex) {
		Parameter parameter = function.getParameter(parameterIndex);
		return parameter.getName();
	}

	protected String getParameterNameFromModel(int parameterIndex) {
		Parameter parameter = function.getParameter(parameterIndex);
		final int stackOffset = parameter.getStackOffset();

		return runSwing(() -> {
			int rowCount = model.getRowCount();
			for (int i = 0; i < rowCount; i++) {
				Object value = model.getValueAt(i, 0 /* Offset column */);
				if (NumericUtilities.parseHexLong(value.toString()) == stackOffset) {
					return model.getComponent(i).getFieldName();
				}
			}
			return null;
		});
	}

	protected void renameParameterInProvider(int parameterIndex, final String newName) {
		Parameter parameter = function.getParameter(parameterIndex);
		final int stackOffset = parameter.getStackOffset();
		runSwing(() -> {
			int rowCount = model.getRowCount();
			for (int i = 0; i < rowCount; i++) {
				Object value = model.getValueAt(i, 0 /* Offset column */);
				if (NumericUtilities.parseHexLong(value.toString()) == stackOffset) {
					model.setValueAt(newName, i, 3);
					break;
				}
			}
		});
	}

	protected Parameter renameParameterInListing(int parameterIndex, String newName) {
		Parameter parameter = function.getParameter(parameterIndex);
		SetVariableNameCmd cmd =
			new SetVariableNameCmd(parameter, newName, SourceType.USER_DEFINED);
		applyCmd(program, cmd);
		return parameter;
	}

}
