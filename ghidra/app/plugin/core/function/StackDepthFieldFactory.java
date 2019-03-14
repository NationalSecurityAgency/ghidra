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
package ghidra.app.plugin.core.function;

import java.awt.Color;
import java.math.BigInteger;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.StackDepthFieldLocation;

public class StackDepthFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "Stack Depth";
	private Address lastEntry = null;
	private CallDepthChangeInfo depth = null;
	private long lastModNumber = -1;

	/**
	 * 
	 */
	public StackDepthFieldFactory() {
		super(FIELD_NAME);
		// TODO Auto-generated constructor stub
	}

	private StackDepthFieldFactory(FieldFormatModel model, HighlightProvider hsProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hsProvider, displayOptions, fieldOptions);
		color = displayOptions.getColor(OptionsGui.BYTES.getColorOptionName(),
			OptionsGui.BYTES.getDefaultColor());

	}

	@Override
	public FieldFactory newInstance(FieldFormatModel newModel, HighlightProvider highlightProvider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new StackDepthFieldFactory(newModel, highlightProvider, displayOptions,
			fieldOptions);
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getField(ProxyObj, int)
	 */
	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof Instruction)) {
			return null;
		}
		Instruction cu = (Instruction) obj;

		Function func = cu.getProgram().getListing().getFunctionContaining(cu.getMinAddress());
		if (func == null) {
			return null;
		}

		long modNumber = func.getProgram().getModificationNumber() ^ cu.getProgram().hashCode();
		// if different function, or program was modified
		if (!func.getEntryPoint().equals(lastEntry) || modNumber != lastModNumber) {
			lastModNumber = modNumber;
			depth = new CallDepthChangeInfo(func);
			lastEntry = func.getEntryPoint();
		}

		//Register stackReg = cu.getProgram().getCompilerSpec().getStackPointer();
		int depthChange = depth.getDepth(cu.getMinAddress());

		String depthString = getDepthString(depthChange);

		// This can be used to display the value of any register symbolically flowing over the program.
		// depthString = depth.getRegValueRepresentation(cu.getMinAddress(), cu.getProgram().getRegister("ESP"));

		AttributedString as = new AttributedString(depthString, Color.BLUE, getMetrics());

		Integer overrideDepth =
			CallDepthChangeInfo.getStackDepthChange(cu.getProgram(), cu.getMinAddress());
		if (overrideDepth != null) {
			String grows = (func.getStackFrame().growsNegative() ? " - " : " + ");
			depthString = depthString + grows + Integer.toString(overrideDepth, 16);
			as = new AttributedString(depthString, Color.RED, getMetrics());
		}

		FieldElement text = new TextFieldElement(as, 0, 0);
		return ListingTextField.createSingleLineTextField(this, proxy, text, startX + varWidth,
			width, hlProvider);
	}

	/**
	 * @param depthChange
	 * @return
	 */
	private String getDepthString(int depthChange) {
		String stringDepth = "- ? -";
		if (depthChange != Function.UNKNOWN_STACK_DEPTH_CHANGE &&
			depthChange != Function.INVALID_STACK_DEPTH_CHANGE) {
			if (depthChange > 0) {
				stringDepth = "-" + Integer.toString(depthChange, 16);
			}
			else {
				stringDepth = Integer.toString(-depthChange, 16);
			}
			int len = stringDepth.length();
			String filler = (depthChange < 0 ? "000" : "   ");
			if (len < 3) {
				stringDepth = filler.substring(len) + stringDepth;
			}
		}
		return stringDepth;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getFieldLocation(ghidra.app.util.viewer.field.ListingField, BigInteger, int, ghidra.program.util.ProgramLocation)
	 */
	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {
		if (loc instanceof StackDepthFieldLocation) {
			StackDepthFieldLocation stackDepthLoc = (StackDepthFieldLocation) loc;
			return new FieldLocation(index, fieldNum, 0, stackDepthLoc.getCharOffset());
		}
		return null;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getProgramLocation(int, int, ghidra.app.util.viewer.field.ListingField)
	 */
	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof Instruction) || row < 0 || col < 0) {
			return null;
		}

		Instruction instr = (Instruction) obj;

		return new StackDepthFieldLocation(instr.getProgram(), instr.getMinAddress(), col);
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#acceptsType(int, java.lang.Class)
	 */
	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!CodeUnit.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.INSTRUCTION_OR_DATA);
	}

}
