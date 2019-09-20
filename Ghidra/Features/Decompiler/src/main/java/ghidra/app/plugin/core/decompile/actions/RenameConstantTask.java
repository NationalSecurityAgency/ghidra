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
package ghidra.app.plugin.core.decompile.actions;

import ghidra.app.util.bean.SetEquateDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighConstant;
import ghidra.util.HelpLocation;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class RenameConstantTask extends RenameTask {

	private HighConstant high;
	private Program program;

	public RenameConstantTask(PluginTool tool, String old, HighConstant h, Program program) {
		super(tool, old);
		high = h;
		this.program = program;
	}

	@Override
	public void commit() throws DuplicateNameException, InvalidInputException {
		// TODO: Constant equates do not work properly with decompiler
		//high.rename(newName,SourceType.USER_DEFINED);
	}

	@Override
	public String getTransactionName() {
		return "Set Equate";
	}

	@Override
	public boolean isValid(String newNm) {
		newName = newNm;
		return true;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.decompile.actions.RenameTask#runDialog()
	 */
	@Override
	public boolean runDialog() {
		// NOTE: acstion must ensure that HighConstant datatype produces Scalar value and is integer type
		// BooleanDataType and CharDataType do not produce scalar values in assembly listing.
		SetEquateDialog setEquateDialog = new SetEquateDialog(tool, program, high.getScalar());
		setEquateDialog.setHelpLocation(new HelpLocation("EquatesPlugin", "Set_Equate"));

		if (setEquateDialog.showSetDialog() == SetEquateDialog.CANCELED) {
			return false;
		}
		isValid(setEquateDialog.getEquateName());
		return true;
	}
}
