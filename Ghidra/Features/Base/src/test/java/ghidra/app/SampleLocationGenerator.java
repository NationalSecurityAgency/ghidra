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
package ghidra.app;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Composite;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.exception.InvalidInputException;

public class SampleLocationGenerator implements GhidraLocationGenerator {
	Program program;
	Namespace global;

	/**
	 * Constructor for SampleLocationGenerator.  
	 */
	public SampleLocationGenerator(Program program) {
		this.program = program;
		global = program.getGlobalNamespace();
	}

	public Address addr(long a) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(a);
	}

	public Address extAddr(long a) {
		return AddressSpace.EXTERNAL_SPACE.getAddress(a);
	}

	/**
	 * Toggle open composite locations within Code Browser
	 * which have locations generated
	 * @param cb
	 */
	public void toggleOpenComposites(final CodeBrowserPlugin cb) {
		AbstractGenericTest.runSwing(() -> {
			Data data = program.getListing().getDataAt(addr(0x100d0f3));
			if (data.getDataType() instanceof Composite) {
				cb.toggleOpen(data);
			}

			data = program.getListing().getDataAt(addr(0xf0000290));
			if (data.getDataType() instanceof Composite) {
				cb.toggleOpen(data);
			}
		});
	}

	@Override
	public ProgramLocation[] getAddressLocations() {
		ProgramLocation[] locs = new ProgramLocation[4];
		locs[0] = new AddressFieldLocation(program, addr(0x01006420));
		locs[1] = new AddressFieldLocation(program, addr(0x010066c0));
		locs[2] = new AddressFieldLocation(program, addr(0x01002a5f));
		locs[3] = new AddressFieldLocation(program, addr(0));
		return locs;
	}

	@Override
	public ProgramLocation[] getBytesLocations() {
		Memory mem = program.getMemory();
		ProgramLocation[] locs = new ProgramLocation[3];
		try {
			Address a = addr(0x1006420);
			byte[] bytes = new byte[1];
			mem.getBytes(a, bytes);
			locs[0] = new BytesFieldLocation(program, a);

			a = addr(0x100643d);
			bytes = new byte[3];
			mem.getBytes(a, bytes);
			locs[1] = new BytesFieldLocation(program, a.add(2), a.add(2), null, 4);

			a = addr(0x10064f1);
			bytes = new byte[5];
			mem.getBytes(a, bytes);
			locs[2] = new BytesFieldLocation(program, a.add(1));

		}
		catch (MemoryAccessException e) {
			throw new RuntimeException("Unexpected exception reading bytes!", e);
		}
		return locs;
	}

	@Override
	public ProgramLocation[] getCodeUnitLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		locs[0] = new CodeUnitLocation(program, addr(0x1006521), 0, 0, 0);
		return locs;
	}

	@Override
	public ProgramLocation[] getCommentFieldLocations() {
		ProgramLocation[] locs = new ProgramLocation[8];

		Address a = addr(0x100101c);
		CodeUnit cu = program.getListing().getCodeUnitAt(a);
		String[] comment = cu.getCommentAsArray(CodeUnit.PRE_COMMENT);
		locs[0] = new CommentFieldLocation(program, a, null, comment, CodeUnit.PRE_COMMENT, 0, 5);

		a = addr(0x10030e4);
		cu = program.getListing().getCodeUnitAt(a);
		comment = cu.getCommentAsArray(CodeUnit.PRE_COMMENT);
		locs[1] = new CommentFieldLocation(program, a, null, comment, CodeUnit.PRE_COMMENT, 0, 5);

		a = addr(0x100352f);
		cu = program.getListing().getCodeUnitAt(a);
		comment = cu.getCommentAsArray(CodeUnit.EOL_COMMENT);
		locs[2] = new CommentFieldLocation(program, a, null, comment, CodeUnit.EOL_COMMENT, 0, 5);

		a = addr(0x10030e4);
		cu = program.getListing().getCodeUnitAt(a);
		comment = cu.getCommentAsArray(CodeUnit.EOL_COMMENT);
		locs[3] = new CommentFieldLocation(program, a, null, comment, CodeUnit.EOL_COMMENT, 1, 5);

		a = addr(0x10075ff);
		cu = program.getListing().getCodeUnitAt(a);
		comment = cu.getCommentAsArray(CodeUnit.POST_COMMENT);
		locs[4] = new PostCommentFieldLocation(program, a, null, comment, 0, 5);

		a = addr(0x1003cf3);
		cu = program.getListing().getCodeUnitAt(a);
		comment = cu.getCommentAsArray(CodeUnit.POST_COMMENT);
		locs[5] = new PostCommentFieldLocation(program, a, null, comment, 0, 0);

		a = addr(0x10030f0);
		cu = program.getListing().getCodeUnitAt(a);
		comment = cu.getCommentAsArray(CodeUnit.PLATE_COMMENT);
		locs[6] = new PlateFieldLocation(program, a, null, 0, 5, comment, -1);

		a = addr(0x1003efc);
		cu = program.getListing().getCodeUnitAt(a);
		comment = cu.getCommentAsArray(CodeUnit.PLATE_COMMENT);
		locs[7] = new PlateFieldLocation(program, a, null, 0, 3, comment, -1);

// TODO add test for repeatable comments.

		return locs;
	}

	@Override
	public ProgramLocation[] getPreCommentLocations() {
		ProgramLocation[] locs = new ProgramLocation[2];

		Address a = addr(0x100101c);
		CodeUnit cu = program.getListing().getCodeUnitAt(a);
		String[] comment = cu.getCommentAsArray(CodeUnit.PRE_COMMENT);
		locs[0] = new CommentFieldLocation(program, a, null, comment, CodeUnit.PRE_COMMENT, 0, 5);

		a = addr(0x10030e4);
		cu = program.getListing().getCodeUnitAt(a);
		comment = cu.getCommentAsArray(CodeUnit.PRE_COMMENT);
		locs[1] = new CommentFieldLocation(program, a, null, comment, CodeUnit.PRE_COMMENT, 0, 5);
		return locs;
	}

	@Override
	public ProgramLocation[] getEolCommentLocations() {
		ProgramLocation[] locs = new ProgramLocation[2];

		Address a = addr(0x100352f);
		CodeUnit cu = program.getListing().getCodeUnitAt(a);
		String[] comment = cu.getCommentAsArray(CodeUnit.EOL_COMMENT);
		locs[0] = new CommentFieldLocation(program, a, null, comment, CodeUnit.EOL_COMMENT, 0, 5);

		a = addr(0x10030e4);
		cu = program.getListing().getCodeUnitAt(a);
		comment = cu.getCommentAsArray(CodeUnit.EOL_COMMENT);
		locs[1] = new CommentFieldLocation(program, a, null, comment, CodeUnit.EOL_COMMENT, 1, 5);
		return locs;
	}

	@Override
	public ProgramLocation[] getPostCommentLocations() {
		ProgramLocation[] locs = new ProgramLocation[2];
		Address a = addr(0x10075ff);

		CodeUnit cu = program.getListing().getCodeUnitAt(a);
		String[] comment = cu.getCommentAsArray(CodeUnit.POST_COMMENT);
		locs[0] = new PostCommentFieldLocation(program, a, null, comment, 0, 5);

		a = addr(0x1003cf3);
		cu = program.getListing().getCodeUnitAt(a);
		comment = cu.getCommentAsArray(CodeUnit.POST_COMMENT);
		locs[1] = new PostCommentFieldLocation(program, a, null, comment, 0, 0);
		return locs;
	}

	@Override
	public ProgramLocation[] getPlateCommentLocations() {
		ProgramLocation[] locs = new ProgramLocation[2];
		Address a = addr(0x10030f0);

		CodeUnit cu = program.getListing().getCodeUnitAt(a);
		String[] comment = cu.getCommentAsArray(CodeUnit.PLATE_COMMENT);
		locs[0] = new PlateFieldLocation(program, a, null, 0, 5, comment, -1);

		a = addr(0x1003efc);
		cu = program.getListing().getCodeUnitAt(a);
		comment = cu.getCommentAsArray(CodeUnit.PLATE_COMMENT);
		locs[1] = new PlateFieldLocation(program, a, null, 0, 3, comment, -1);
		return locs;
	}

	@Override
	public ProgramLocation[] getDividerLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		locs[0] = new DividerLocation(program, addr(0x1008000), null, 3);
		return locs;
	}

	@Override
	public ProgramLocation[] getFieldNameLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		locs[0] = new FieldNameFieldLocation(program, addr(0x100a748), null, "d", 0);
		return locs;
	}

	@Override
	public ProgramLocation[] getFunctionCommentLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		Address a = addr(0x0100415a);
		Function f = program.getListing().getFunctionAt(a);
		String[] comment = f.getCommentAsArray();
		locs[0] = new FunctionRepeatableCommentFieldLocation(program, a, null, comment, 10, 3);
		return locs;
	}

	@Override
	public ProgramLocation[] getFunctionSignatureLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		Address a = addr(0x100415a);
		Function f = program.getListing().getFunctionAt(a);
		String signature = f.getPrototypeString(false, false);
		locs[0] = new FunctionSignatureFieldLocation(program, a, null, 15, signature);
		return locs;
	}

	@Override
	public ProgramLocation[] getIndentLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		locs[0] = new IndentFieldLocation(program, addr(0x100bf9b), null);
		return locs;
	}

	@Override
	public ProgramLocation[] getLabelLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		Address a = addr(0x100415a);
		Symbol s = program.getSymbolTable().getPrimarySymbol(a);
		locs[0] = s.getProgramLocation();

		return locs;
	}

	@Override
	public ProgramLocation[] getMnemonicLocations() {
		ProgramLocation[] locs = new ProgramLocation[3];
		locs[0] = new MnemonicFieldLocation(program, addr(0x1004523), null, "pushl", 2);
		locs[1] = new MnemonicFieldLocation(program, addr(0x1004543), null, "call", 0);
		locs[2] =
			new MnemonicFieldLocation(program, addr(0x100d0f3), null, new int[] { 1 }, "dw", 0); // inside union
		return locs;
	}

	@Override
	public ProgramLocation[] getOperandLocations() {
		ProgramLocation[] locs = new ProgramLocation[3];
		locs[0] = new OperandFieldLocation(program, addr(0x1004523), null, null, "%eax", 0, 0);
		locs[1] = new OperandFieldLocation(program, addr(0x1004531), null, addr(0x1008918),
			"DAT_01008918", 0, 0);
		locs[2] =
			new OperandFieldLocation(program, addr(0x100d0f3), new int[] { 1 }, null, "400h", 0, 0); // inside union
		return locs;
	}

	@Override
	public ProgramLocation[] getOperandScalarLocations() {
		ProgramLocation[] locs = new ProgramLocation[3];
		locs[0] = new OperandFieldLocation(program, addr(0x10047b8), null, null, "0x4", 0, 0);
		locs[1] = new OperandFieldLocation(program, addr(0x1004741), null, null, "-0x1", 1, 0);
		locs[2] =
			new OperandFieldLocation(program, addr(0x100d0f3), new int[] { 1 }, null, "400h", 0, 0); // inside union
		return locs;
	}

	@Override
	public ProgramLocation[] getOperandLabelLocations() {
		ProgramLocation[] locs = new ProgramLocation[5];
		locs[0] = new OperandFieldLocation(program, addr(0x1004747), null, addr(0x10062a6),
			"SUB_010062a7", 0, 0);
		locs[1] = new OperandFieldLocation(program, addr(0x10045b6), null, addr(0x10087e4),
			"DAT_010087e4", 0, 4);
		locs[2] = new OperandFieldLocation(program, addr(0x1001000), null, extAddr(0x1),
			"->ADVAPI32.dll::IsTextUnicode", 0, 4); // pointer operand with external reference
		locs[3] = new OperandFieldLocation(program, addr(0x100d0f3), new int[] { 4 },
			addr(0xe8000400), "DAT_e8000400", 0, 0); // inside union
		locs[4] = new OperandFieldLocation(program, addr(0xf0000290), new int[] { 2 }, null,
			"MSVCRT", 0, 0); // inside structure
		return locs;
	}

	@Override
	public ProgramLocation[] getFieldNameFieldLocations() {
		ProgramLocation[] locs = new ProgramLocation[4];
		locs[0] =
			new FieldNameFieldLocation(program, addr(0x100d0f3), new int[] { 4 }, "field4", 0); // inside union
		locs[1] =
			new FieldNameFieldLocation(program, addr(0x100d0f3), new int[] { 3 }, "field3", 0); // inside union
		locs[2] =
			new FieldNameFieldLocation(program, addr(0xf0000290), new int[] { 0 }, "COMDLG32", 0); // inside structure
		locs[3] =
			new FieldNameFieldLocation(program, addr(0xf0000290), new int[] { 2 }, "MSVCRT", 0); // inside structure
		return locs;
	}

	@Override
	public ProgramLocation[] getProgramLocations() {
		ProgramLocation[] locs = new ProgramLocation[4];
		locs[0] = new ProgramLocation(program, addr(0x10045a9));
		locs[1] = new ProgramLocation(program, addr(0x0));
		locs[2] = new ProgramLocation(program, addr(0xffffffffL));
		locs[3] = new ProgramLocation(program, addr(0x10045cb));
		return locs;
	}

	@Override
	public ProgramLocation[] getRegisterVarCommentLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		return locs;
	}

	@Override
	public ProgramLocation[] getRegisterVarDescriptionLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		return locs;
	}

	@Override
	public ProgramLocation[] getRegisterVarLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		return locs;
	}

	@Override
	public ProgramLocation[] getRegisterVarNameLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		return locs;
	}

	@Override
	public ProgramLocation[] getRegisterVarTypeLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		return locs;
	}

	@Override
	public ProgramLocation[] getSpaceLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		return locs;
	}

	@Override
	public ProgramLocation[] getSpacerLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		return locs;
	}

	@Override
	public ProgramLocation[] getStackVarCommentLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		return locs;
	}

	@Override
	public ProgramLocation[] getStackVarLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		return locs;
	}

	@Override
	public ProgramLocation[] getStackVarNameLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		return locs;
	}

	@Override
	public ProgramLocation[] getStackVarOffsetLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		return locs;
	}

	@Override
	public ProgramLocation[] getStackVarTypeLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		return locs;
	}

	@Override
	public ProgramLocation[] getStackVarXrefLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		return locs;
	}

	@Override
	public ProgramLocation[] getSubDataLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		return locs;
	}

	@Override
	public ProgramLocation[] getXrefLocations() {
		ProgramLocation[] locs = new ProgramLocation[1];
		return locs;
	}

	@Override
	public void generateLocations(LocationCallback callback) {
		Class<?> c = getClass();
		Method[] methods = c.getDeclaredMethods();
		for (Method method : methods) {
			if (method.getName().startsWith("get")) {
				try {
					ProgramLocation[] locs =
						(ProgramLocation[]) method.invoke(this, (Object[]) null);
					for (ProgramLocation loc : locs) {
						if (loc != null) {
							callback.locationGenerated(loc);
						}
					}
				}
				catch (IllegalAccessException e) {
					e.printStackTrace();
				}
				catch (InvocationTargetException e) {
					e.printStackTrace();
				}
			}
		}
	}

	@Override
	public ProgramLocation[] getLocationsWithNoLabels() {
		ProgramLocation[] locs = new ProgramLocation[1];
		locs[0] = new AddressFieldLocation(program, addr(0x1005e05));
		return locs;
	}

	@Override
	public ProgramLocation[] getLocationsWithDefaultLabel() {
		ProgramLocation[] locs = new ProgramLocation[1];
		locs[0] = new LabelFieldLocation(program, addr(0x10049f9), "LAB_010049f9");
		return locs;
	}

	@Override
	public ProgramLocation[] getLocationsWithMultipleLabels() {
		ProgramLocation[] locs = new ProgramLocation[1];
		createLabel(addr(0x10049e4), "two");

		locs[0] = new LabelFieldLocation(program, addr(0x10049e4), "two");
		return locs;
	}

	public ProgramLocation[] getLocationsWithFunctionStackVarReference() {
		ProgramLocation[] locs = new ProgramLocation[1];
		locs[0] =
			new OperandFieldLocation(program, addr(0x1004116), null, null, "param_2[ESP]", 1, 0);
		return locs;
	}

	private void createLabel(Address addr, String name) {
		SymbolTable st = program.getSymbolTable();
		Symbol s = st.getGlobalSymbol(name, addr);
		if (s == null) {
			int transactionID = program.startTransaction("Create label");
			try {
				st.createLabel(addr(0x10049e4), name, SourceType.USER_DEFINED);
			}
			catch (InvalidInputException e) {
				// don't care
			}
			finally {
				program.endTransaction(transactionID, true);
			}
		}
	}

	@Override
	public ProgramLocation[] getLocationsWithNonDefaultLabel() {
		createLabel(addr(0x100eb90), "rsrc_String_4_5c8");
		ProgramLocation[] locs = new ProgramLocation[1];
		locs[0] = new LabelFieldLocation(program, addr(0x100eb90), "rsrc_String_4_5c8");
		return locs;
	}

	@Override
	public ProgramLocation[] getLocationsWithInstructions() {
		createLabel(addr(0x10049f9), "two");
		ProgramLocation[] locs = new ProgramLocation[6];
		locs[0] = new AddressFieldLocation(program, addr(0x1005e05));
		locs[1] = new LabelFieldLocation(program, addr(0x10049f9), "LAB_010049f9");
		locs[2] = new LabelFieldLocation(program, addr(0x10049e4), "two");
		locs[3] = new AddressFieldLocation(program, addr(0x1004f3b));
		locs[4] = new AddressFieldLocation(program, addr(0x1006648));
		locs[5] = new AddressFieldLocation(program, addr(0x1006630));

		return locs;
	}

	@Override
	public ProgramLocation[] getLocationsWithLocalLabels() {
		ProgramLocation[] locs = new ProgramLocation[2];
		locs[0] =
			new LabelFieldLocation(program, addr(0x1002d1f), "MyLocal");
		locs[1] = new LabelFieldLocation(program, addr(0x1002d2b), "AnotherLocal");
		return locs;
	}

}
