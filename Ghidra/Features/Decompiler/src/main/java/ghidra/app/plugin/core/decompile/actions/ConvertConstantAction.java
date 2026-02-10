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

import java.awt.Font;
import java.awt.FontMetrics;

import javax.swing.JMenuItem;

import ghidra.app.decompiler.ClangCaseToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

/**
 * Abstract pop-up menu convert action for the decompiler. If triggered, it lays down
 * a new EquateReference that forces the selected constant to be displayed using
 * the desired integer format.
 */
public abstract class ConvertConstantAction extends AbstractDecompilerAction {

	protected DecompilePlugin plugin;
	private FontMetrics metrics = null;
	protected int convertType;				// The conversion type performed by the action

	/**
	 * Helper class for identifying integer values that are "near" a given value.
	 * "Near" can mean off by 1, negated, or inverted.
	 */
	public static class NearMatchValues {
		private long[] values;
		private long mask;

		public NearMatchValues(long value, int size) {
			mask = -1;
			if (size < 8) {
				mask = mask >>> (8 - size) * 8;
			}
			values = new long[4];
			values[0] = value & mask;
			values[1] = (value - 1) & mask;
			values[2] = (value + 1) & mask;
			values[3] = (-value) & mask;
		}

		public NearMatchValues(Scalar scalar) {
			this(scalar.getValue(), scalar.bitLength() / 8);
		}

		/**
		 * @param value is the value to match
		 * @return true if the value matches
		 */
		public boolean isMatch(long value) {
			value = value & mask;
			for (long match : values) {
				if (match == value)
					return true;
			}
			return false;
		}
	}

	public ConvertConstantAction(DecompilePlugin plugin, String name, int convertType) {
		super(name);
		this.plugin = plugin;
		this.convertType = convertType;
	}

	private int stringWidth(String s) {
		if (metrics == null) {
			JMenuItem item = new JMenuItem();
			Font font = item.getFont();
			metrics = plugin.getTool().getActiveWindow().getFontMetrics(font);
		}
		int w = metrics.stringWidth(s);
		if (w == 0) {
			// use default computation if metrics report 0
			return 10 * s.length();
		}
		return w;
	}

	protected String getStandardLengthString(String baseString) {
		int baseWidth = stringWidth(baseString);
		int spaceWidth = stringWidth(" ");
		int paddingSize = (140 - baseWidth) / spaceWidth;
		if (paddingSize <= 0) {
			return baseString;
		}
		StringBuilder buf = new StringBuilder(baseString);
		for (int i = 0; i < paddingSize; i++) {
			buf.append(" ");
		}
		return buf.toString();
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Scalar scalar;
		scalar = getCaseConstant(context, convertType);
		if (scalar == null) {
			scalar = ConvertConstantEquateTask.getConvertibleConstant(context, convertType);
		}
		if (scalar == null) {
			return false;
		}
		String convDisplay = getMenuDisplay(scalar, context.getProgram());
		if (convDisplay == null) {
			return false;
		}
		if (convDisplay.equals(context.getTokenAtCursor().getText())) {
			return false;
		}
		String menuString = getStandardLengthString(getMenuPrefix()) + convDisplay;
		getPopupMenuData().setMenuItemNamePlain(menuString);

		return true;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		if (context.getTokenAtCursor() instanceof ClangCaseToken) {
			writeSwitchFormat(context);
			return;
		}
		ConvertConstantEquateTask task = ConvertConstantEquateTask.establishTask(context, this);
		if (task == null) {
			return;
		}
		task.runTask();
	}

	/**
	 * If the mouse context is a constant from a switch case that is suitable for conversion
	 * return a description of the constant. Otherwise return null.
	 * @param context is the mouse context
	 * @param convertType is the type of conversion being selected (FORMAT_DEC FORMAT_HEX etc.)
	 * @return the constant description or null
	 */
	static protected Scalar getCaseConstant(DecompilerActionContext context,
			int convertType) {
		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (!(tokenAtCursor instanceof ClangCaseToken)) {
			return null;
		}
		if (convertType == EquateSymbol.FORMAT_DEFAULT ||
			convertType == EquateSymbol.FORMAT_DOUBLE || convertType == EquateSymbol.FORMAT_FLOAT) {
			return null;
		}
		ClangCaseToken caseToken = (ClangCaseToken) tokenAtCursor;
		HighVariable high = caseToken.getHighVariable();
		if (high == null) {
			return null;
		}
		DataType convertDataType = high.getDataType();
		boolean convertIsSigned = false;
		if (convertDataType instanceof AbstractIntegerDataType) {
			if (convertDataType instanceof BooleanDataType) {
				return null;
			}
			convertIsSigned = ((AbstractIntegerDataType) convertDataType).isSigned();
		}
		else if (convertDataType instanceof Enum) {
			return null;
		}
		return new Scalar(high.getSize() * 8, caseToken.getValue(), convertIsSigned);
	}

	private void writeSwitchFormat(DecompilerActionContext context) {
		ClangCaseToken caseToken = (ClangCaseToken) context.getTokenAtCursor();
		PcodeOp switchOp = caseToken.getSwitchOp();
		Function func = context.getFunction();
		Program program = context.getProgram();
		int transaction = program.startTransaction("Convert case constants");
		boolean commit = false;
		try {
			JumpTable.writeFormat(func, switchOp.getSeqnum().getTarget(), convertType);
			commit = true;
		}
		catch (InvalidInputException ex) {
			Msg.error(this, ex);
		}
		finally {
			program.endTransaction(transaction, commit);
		}
	}

	/**
	 * The menu option for this kind of action is intended to look like:
	 *    {@literal Hexadecimal: 0x2408}
	 *  This method establishes the first part of this string, up to the colon.
	 * @return the menu prefix
	 */
	public abstract String getMenuPrefix();

	/**
	 * The menu option for this kind of action is intended to look like:
	 *    {@literal Hexadecimal: 0x2408}
	 * This method constructs the final part of this string, after the colon by
	 * formatting the actual value that is to be converted.
	 * @param scalar is the constant being converted
	 * @param program the program
	 * @return the formatted String
	 */
	public abstract String getMenuDisplay(Scalar scalar, Program program);

	/**
	 * Construct the name of the Equate, either absolutely for a conversion or
	 * by preventing the user with a dialog to select a name.
	 * @param scalar is the constant being converted
	 * @param program is the current Program
	 * @return the equate name
	 */
	public abstract String getEquateName(Scalar scalar, Program program);
}
