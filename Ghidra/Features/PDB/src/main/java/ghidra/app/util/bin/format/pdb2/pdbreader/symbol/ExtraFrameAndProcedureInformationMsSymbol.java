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
package ghidra.app.util.bin.format.pdb2.pdbreader.symbol;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents the Extra Frame And Procedure Information symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class ExtraFrameAndProcedureInformationMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x1012;

	private long procedureFrameTotalLength;
	private long procedureFramePaddingLength;
	private long paddingOffset;
	private long calleeSaveRegistersByteCount;
	private long exceptionHandlerOffset;
	private int exceptionHandlerSectionID;
	private long flags;
	private boolean usesAlloca;
	private boolean usesSetJmp;
	private boolean usesLongJmp;
	private boolean usesInlineAsm;
	private boolean hasExceptionHandlingStates;
	private boolean wasInlineSpec;
	private boolean wasStructuredExceptionHandling;
	private boolean isDeclspecNaked;
	private boolean hasGsBufferSecurityCheck;
	private boolean compiledWithAsyncExceptionHandling;
	private boolean couldNotDoStackOrderingWithGsBufferSecurityChecks;
	private boolean wasInlinedWithinAnotherFunction;
	private boolean isDeclspecStrictGsCheck;
	private boolean isDeclspecSafeBuffers;
	private RegisterName explicitlyEncodedLocalBasePointer;
	private RegisterName explicitlyEncodedParameterPointer;
	private boolean wasCompiledWithPgoPgu; // (Procedure Guided Optimization?)
	private boolean hasvalidPogoCounts; // (Procedure Guided Optimization)
	private boolean optimizedForSpeed;
	private boolean containsCfgChecksButNoWriteChecks;
	private boolean containsCfwChecksAndOrInstrumentation;
	private int padding;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public ExtraFrameAndProcedureInformationMsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		procedureFrameTotalLength = reader.parseUnsignedIntVal();
		procedureFramePaddingLength = reader.parseUnsignedIntVal();
		paddingOffset = reader.parseVarSizedOffset(32);
		calleeSaveRegistersByteCount = reader.parseUnsignedIntVal();
		exceptionHandlerOffset = reader.parseVarSizedOffset(32);
		exceptionHandlerSectionID = reader.parseUnsignedShortVal();
		//padding?
		flags = reader.parseUnsignedIntVal();
		processFlags(flags);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the procedure frame total length.
	 * @return Procedure frame total length.
	 */
	public long getProcedureFrameTotalLength() {
		return procedureFrameTotalLength;
	}

	/**
	 * Returns the procedure frame padding length.
	 * @return Procedure frame padding length.
	 */
	public long getProcedureFramePaddingLength() {
		return procedureFramePaddingLength;
	}

	/**
	 * Returns the padding offset.
	 * @return Padding offset.
	 */
	public long getPaddingOffset() {
		return paddingOffset;
	}

	/**
	 * Returns the callee save registers byte count.
	 * @return Callee save registers byte count.
	 */
	public long getCalleeSaveRegistersByteCount() {
		return calleeSaveRegistersByteCount;
	}

	/**
	 * Returns the exception handler offset.
	 * @return Exception handler offset.
	 */
	public long getExceptionHandlerOffset() {
		return exceptionHandlerOffset;
	}

	/**
	 * Returns the exception handler section ID.
	 * @return Exception handler section ID.
	 */
	public int getExceptionHandlerSectionID() {
		return exceptionHandlerSectionID;
	}

	/**
	 * Returns the flags.
	 * @return Flags.
	 */
	public long getFlags() {
		return flags;
	}

	/**
	 * Tells whether the function uses alloca().
	 * @return True if it uses alloca().
	 */
	public boolean usesAlloca() {
		return usesAlloca;
	}

	/**
	 * Tells whether the function uses setjmp().
	 * @return True if it uses setjmp().
	 */
	public boolean usesSetJmp() {
		return usesSetJmp;
	}

	/**
	 * Tells whether the function uses longjmp().
	 * @return True if it uses longjmp().
	 */
	public boolean usesLongJmp() {
		return usesLongJmp;
	}

	/**
	 * Tells whether the function uses inline asm.
	 * @return True if it uses inline asm.
	 */
	public boolean usesInlineAsm() {
		return usesInlineAsm;
	}

	/**
	 * Tells whether the function has exception handling states.
	 * @return True if it has exception handling states.
	 */
	public boolean hasExceptionHandlingStates() {
		return hasExceptionHandlingStates;
	}

	/**
	 * Tells whether the function "was specified" as inline.
	 * @return True if the function was specified" as inline.
	 */
	public boolean wasInlineSpec() {
		return wasInlineSpec;
	}

	/**
	 * Tells whether the function has structured exception handling.
	 * @return True if it has structured exception handling.
	 */
	public boolean wasStructuredExceptionHandling() {
		return wasStructuredExceptionHandling;
	}

	/**
	 * Tells if the function is __declspec(naked).
	 * @return True if it is __declspec(naked).
	 */
	public boolean isDeclspecNaked() {
		return isDeclspecNaked;
	}

	/**
	 * Tells whether the function has buffer security check due to /GS.
	 * @return True if it has buffer security due to /GS.
	 */
	public boolean hasGsBufferSecurityCheck() {
		return hasGsBufferSecurityCheck;
	}

	/**
	 * Tells whether the function was compiled with /EHa.
	 * @return True if it was compiled with /EHa.
	 */
	public boolean isCompiledWithAsyncExceptionHandling() {
		return compiledWithAsyncExceptionHandling;
	}

	/**
	 * Tells if stack ordering couldn't be done on the function even though it has /GS buffer
	 * checks.
	 * @return True if stack ordering couldn't be done even with /GS buffer checks.
	 */
	public boolean couldNotDoStackOrderingWithGsBufferSecurityChecks() {
		return couldNotDoStackOrderingWithGsBufferSecurityChecks;
	}

	/**
	 * Tells whether the function was inlined within another.
	 * @return True if the function was inlined within another.
	 */
	public boolean wasInlinedWithinAnotherFunction() {
		return wasInlinedWithinAnotherFunction;
	}

	/**
	 * Tells if the function is __declspec(strict_gs_check).
	 * @return True if it is __declspec(strict_gs_check).
	 */
	public boolean isDeclspecStrictGsCheck() {
		return isDeclspecStrictGsCheck;
	}

	/**
	 * Tells if the function is __declspec(safebuffers).
	 * @return True if it is __declspec(safebuffers).
	 */
	public boolean isDeclspecSafeBuffers() {
		return isDeclspecSafeBuffers;
	}

	/**
	 * Returns the explicitly encoded local base pointer.
	 * @return Explicitly encoded local base pointer.
	 */
	public RegisterName getExplicitlyEncodedLocalBasePointer() {
		return explicitlyEncodedLocalBasePointer;
	}

	/**
	 * Returns the explicitly encoded parameter pointer.
	 * @return Excplicitly encoded parameter pointer.
	 */
	public RegisterName getExplicitlyEncodedParameterPointer() {
		return explicitlyEncodedParameterPointer;
	}

	/**
	 * Tells whether the function was compiled with Procedure Guided Optimization.
	 * <P>
	 * Note: Believe this relates to Procedure Guided Optimization 
	 * @return True if compiled with Procedure Guided Optimization.
	 */
	public boolean wasCompiledWithPgoPgu() {
		return wasCompiledWithPgoPgu;
	}

	/**
	 * Tells whether there are valid Procedure Guided Optimization counts.
	 * <P>
	 * Note: Believe this relates to Procedure Guided Optimization 
	 * @return True if there are Procedure Guided Optimization counts.
	 */
	public boolean hasvalidPogoCounts() {
		return hasvalidPogoCounts;
	}

	/**
	 * Tells whether the function was optimized for speed.
	 * @return True if it was optimized for speed.
	 */
	public boolean isOptimizedForSpeed() {
		return optimizedForSpeed;
	}

	/**
	 * Tells whether the function contains Guard CF checks but no write checks.
	 * @return True if it has Guard CF checks and not write checks.
	 */
	public boolean containsCfgChecksButNoWriteChecks() {
		return containsCfgChecksButNoWriteChecks;
	}

	/**
	 * Tells whether the function has Guard CFW checks and/or instrumentation.
	 * @return True if has Guard CFW checks and/or instrumentation.
	 */
	public boolean containsCfwChecksAndOrInstrumentation() {
		return containsCfwChecksAndOrInstrumentation;
	}

	/**
	 * Returns the padding.
	 * @return Padding.
	 */
	public int getPadding() {
		return padding;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s:\n", getSymbolTypeName()));
		builder.append(String.format("   Frame size = %08X bytes\n", procedureFrameTotalLength));
		builder.append(String.format("   Pad size = %08X bytes\n", procedureFramePaddingLength));
		builder.append(String.format("   Offset of pad in frame = %08X\n", paddingOffset));
		builder.append(String.format("   Size of callee save registers = %08X\n",
			calleeSaveRegistersByteCount));
		builder.append(String.format("   Address of exception handler = %04X:%08X\n",
			exceptionHandlerSectionID, exceptionHandlerOffset));
		builder.append("   Function info: ");
		builder.append(usesAlloca ? "alloca " : "");
		builder.append(usesSetJmp ? "setjmp " : "");
		builder.append(usesLongJmp ? "longjmp " : "");
		builder.append(usesInlineAsm ? "inlasm " : "");
		builder.append(hasExceptionHandlingStates ? "eh  " : "");
		builder.append(wasInlineSpec ? "inl_specified " : "");
		builder.append(wasStructuredExceptionHandling ? "seh " : "");
		builder.append(isDeclspecNaked ? "naked " : "");
		builder.append(hasGsBufferSecurityCheck ? "gschecks " : "");
		builder.append(compiledWithAsyncExceptionHandling ? "asynceh " : "");
		builder.append(
			couldNotDoStackOrderingWithGsBufferSecurityChecks ? "gsnostackordering " : "");
		builder.append(wasInlinedWithinAnotherFunction ? "wasinlined " : "");
		builder.append(isDeclspecStrictGsCheck ? "strict_gs_check " : "");
		builder.append(isDeclspecSafeBuffers ? "safebuffers " : "");

		builder.append(wasCompiledWithPgoPgu ? "pgo_on " : "");
		builder.append(hasvalidPogoCounts ? "valid_pgo_counts " : "invalid_pgo_counts ");
		builder.append(optimizedForSpeed ? "opt_for_speed " : "");

		builder.append("Local=");
		explicitlyEncodedLocalBasePointer.emit(builder);
		builder.append(" ");
		builder.append("Param=");
		explicitlyEncodedParameterPointer.emit(builder);
		builder.append(" ");

		builder.append(containsCfgChecksButNoWriteChecks ? "guardcf " : "");
		builder.append(containsCfwChecksAndOrInstrumentation ? "guardcfw " : "");

		builder.append(String.format("(%08X)", flags));
	}

	@Override
	protected String getSymbolTypeName() {
		return "FRAMEPROCSYM";
	}

	private void processFlags(long flagsIn) {
		usesAlloca = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		usesSetJmp = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		usesLongJmp = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		usesInlineAsm = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		hasExceptionHandlingStates = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		wasInlineSpec = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		wasStructuredExceptionHandling = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		isDeclspecNaked = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		hasGsBufferSecurityCheck = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		compiledWithAsyncExceptionHandling = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		couldNotDoStackOrderingWithGsBufferSecurityChecks = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		wasInlinedWithinAnotherFunction = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		isDeclspecStrictGsCheck = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		isDeclspecSafeBuffers = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;

		explicitlyEncodedLocalBasePointer = new RegisterName(pdb, (int) (flagsIn & 0x0003));
		flagsIn >>= 2;
		explicitlyEncodedParameterPointer = new RegisterName(pdb, (int) (flagsIn & 0x0003));
		flagsIn >>= 2;

		wasCompiledWithPgoPgu = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		hasvalidPogoCounts = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		optimizedForSpeed = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		containsCfgChecksButNoWriteChecks = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		containsCfwChecksAndOrInstrumentation = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;

		padding = (int) (flagsIn & 0x01ff);
	}

}
