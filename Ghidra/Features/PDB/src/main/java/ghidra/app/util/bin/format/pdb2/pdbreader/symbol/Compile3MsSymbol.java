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
 * This class represents the Compile 3 symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class Compile3MsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x113c;

	protected LanguageName language;
	protected boolean compiledForEditAndContinue;
	protected boolean notCompiledWithDebugInfo;
	protected boolean compiledWithLinkTimeCodeGeneration;
	protected boolean compiledWithBzalignNoDataAlign;
	protected boolean managedCodeDataPresent;
	protected boolean compiledWithGsBufferSecurityChecks;
	protected boolean compiledWithHotPatch;
	// Converted from (.NET IL) Common Intermediate Language Module
	protected boolean convertedWithCvtcil;
	protected boolean microsoftIntermediateLanguageNetModule;
	protected boolean compiledWithSdl;
	protected boolean compiledWithLtcgPgoOrPgu;
	protected boolean dotExpModule;
	protected Processor processor;
	protected int frontEndMajorVersionNumber;
	protected int frontEndMinorVersionNumber;
	protected int frontEndBuildVersionNumber;
	protected int frontEndQuickFixEngineeringVersionNumber;
	protected int backEndMajorVersionNumber;
	protected int backEndMinorVersionNumber;
	protected int backEndBuildVersionNumber;
	protected int backEndQuickFixEngineeringVersionNumber;
	protected String compilerVersionString;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public Compile3MsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		processFlags(reader.parseUnsignedIntVal());
		processor = Processor.fromValue(reader.parseUnsignedShortVal());
		frontEndMajorVersionNumber = reader.parseUnsignedShortVal();
		frontEndMinorVersionNumber = reader.parseUnsignedShortVal();
		frontEndBuildVersionNumber = reader.parseUnsignedShortVal();
		frontEndQuickFixEngineeringVersionNumber = reader.parseUnsignedShortVal();
		backEndMajorVersionNumber = reader.parseUnsignedShortVal();
		backEndMinorVersionNumber = reader.parseUnsignedShortVal();
		backEndBuildVersionNumber = reader.parseUnsignedShortVal();
		backEndQuickFixEngineeringVersionNumber = reader.parseUnsignedShortVal();
		compilerVersionString = reader.parseString(pdb, StringParseType.StringUtf8Nt);

		// Very important: sStore target machine information.  It is used elsewhere, including
		//  in RegisterName.
		pdb.setTargetProcessor(processor);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the language.
	 * @return Language.
	 */
	public String getLanguage() {
		return language.toString();
	}

	/**
	 * Tells whether the target was compiled for "Edit and Continue."
	 * @return True if it was compiled for "Edit and Continue."
	 */
	public boolean isCompiledForEditAndContinue() {
		return compiledForEditAndContinue;
	}

	/**
	 * Tells whether the target was not compiled with debug information.
	 * @return True if it was not compiled with debug information.
	 */
	public boolean isNotCompiledWithDebugInfo() {
		return notCompiledWithDebugInfo;
	}

	/**
	 * Tells whether the target was compiled with link-time code generation.
	 * @return True if it was compiled with link-time code generation.
	 */
	public boolean isCompiledWithLinkTimeCodeGeneration() {
		return compiledWithLinkTimeCodeGeneration;
	}

	/**
	 * Tells whether the target was compiled with Bzalign.
	 * @return True if compiled with Bzalign.
	 */
	public boolean isCompiledWithBzalignNoDataAlign() {
		return compiledWithBzalignNoDataAlign;
	}

	/**
	 * Tells whether the target has managed code and/or data present.
	 * @return True if has managed code/data present.
	 */
	public boolean isManagedCodeDataPresent() {
		return managedCodeDataPresent;
	}

	/**
	 * Tells whether the target was compiled with /GS buffer security checks.
	 * @return True if it was compiled with /GS buffer security checks.
	 */
	public boolean isCompiledWithGsBufferSecurityChecks() {
		return compiledWithGsBufferSecurityChecks;
	}

	/**
	 * Tells whether the target was compiled with /hotpatch.
	 * @return True if it was compiled with /hotpatch.
	 */
	public boolean isCompiledWithHotPatch() {
		return compiledWithHotPatch;
	}

	/**
	 * Tells whether the target was converted with CVTCIL.
	 * @return True if was converted with CVTCIL.
	 */
	public boolean wasConvertedWithCvtcil() {
		return convertedWithCvtcil;
	}

	/**
	 * Tells whether the target is a Microsoft Intermediate Language netmodule.
	 * @return True if it is a Microsoft Intermediate Language netmodule.
	 */
	public boolean isMicrosoftIntermediateLanguageNetModule() {
		return microsoftIntermediateLanguageNetModule;
	}

	/**
	 * Tells whether the target is compiled with /sdl.
	 * @return True if it was compiled with /sdl.
	 */
	public boolean isCompiledWithSdl() {
		return compiledWithSdl;
	}

	/**
	 * Tells whether the target is compiled with /ltcg:pgo or pgu.
	 * @return True if compiled with /ltcg:pgo or pgu.
	 */
	public boolean isCompiledWithLtcgPgoOrPgu() {
		return compiledWithLtcgPgoOrPgu;
	}

	/**
	 * Tells whether the target is a .exp module.
	 * @return True if a .exp module.
	 */
	public boolean isDotExpModule() {
		return dotExpModule;
	}

	/**
	 * Returns the processor.
	 * @return the processor.
	 */
	public Processor getProcessor() {
		return processor;
	}

	/**
	 * Returns the front end major version number.
	 * @return Front end major version number.
	 */
	public int getFrontEndMajorVersionNumber() {
		return frontEndMajorVersionNumber;
	}

	/**
	 * Returns the front end minor version number.
	 * @return Front end minor version number.
	 */
	public int getFrontEndMinorVersionNumber() {
		return frontEndMinorVersionNumber;
	}

	/**
	 * Returns the front end build version number.
	 * @return Front end build version number.
	 */
	public int getFrontEndBuildVersionNumber() {
		return frontEndBuildVersionNumber;
	}

	/**
	 * Returns the front end quick fix engineering version number.
	 * @return Front end quick fix engineering version number.
	 */
	public int getFrontEndQuickFixEngineeringVersionNumber() {
		return frontEndQuickFixEngineeringVersionNumber;
	}

	/**
	 * Returns the back end major version number.
	 * @return Back end major version number.
	 */
	public int getBackEndMajorVersionNumber() {
		return backEndMajorVersionNumber;
	}

	/**
	 * Returns the back end minor version number.
	 * @return Back end minor version number.
	 */
	public int getBackEndMinorVersionNumber() {
		return backEndMinorVersionNumber;
	}

	/**
	 * Returns the back end build version number.
	 * @return Back end build version number.
	 */
	public int getBackEndBuildVersionNumber() {
		return backEndBuildVersionNumber;
	}

	/**
	 * Returns the back end quick fix engineering version number.
	 * @return Back end quick fix engineering version number.
	 */
	public int getBackEndQuickFixEngineeringVersionNumber() {
		return backEndQuickFixEngineeringVersionNumber;
	}

	/**
	 * Returns the compiler version string.
	 * @return Compiler version string.
	 */
	public String getCompilerVersionString() {
		return compilerVersionString;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		builder.append(":\n   Language: ");
		builder.append(language.toString());
		builder.append("\n   Target Processor: ");
		builder.append(processor.toString());

		builder.append(
			"\n   Compiled for edit and continue: " + (compiledForEditAndContinue ? "yes" : "no"));
		builder.append(
			"\n   Compiled withoug debugging info: " + (notCompiledWithDebugInfo ? "yes" : "no"));
		builder.append(
			"\n   Compiled with LTCG: " + (compiledWithLinkTimeCodeGeneration ? "yes" : "no"));
		builder.append(
			"\n   Compiled with /bzalign: " + (compiledWithBzalignNoDataAlign ? "yes" : "no"));
		builder.append("\n   Managed code present: " + (managedCodeDataPresent ? "yes" : "no"));
		builder.append(
			"\n   Compiled with /GS: " + (compiledWithGsBufferSecurityChecks ? "yes" : "no"));
		builder.append("\n   Compiled with /hotpatch: " + (compiledWithHotPatch ? "yes" : "no"));
		builder.append("\n   Converted by CVTCIL: " + (convertedWithCvtcil ? "yes" : "no"));
		builder.append("\n   Microsoft Intermediate Language Module: " +
			(microsoftIntermediateLanguageNetModule ? "yes" : "no"));
		builder.append("\n   Compiled with /sdl: " + (compiledWithSdl ? "yes" : "no"));
		builder.append("\n   Compiled with Profile Guided Optimization (PGO): " +
			(compiledWithLtcgPgoOrPgu ? "yes" : "no"));
		builder.append("\n   .EXP module: " + (dotExpModule ? "yes" : "no"));

		builder.append(
			String.format("\n   Frontend Version: Major = %d, Minor = %d, Build = %d, QFE = %d",
				frontEndMajorVersionNumber, frontEndMinorVersionNumber, frontEndBuildVersionNumber,
				frontEndQuickFixEngineeringVersionNumber));
		builder.append(
			String.format("\n   Backend Version: Major = %d, Minor = %d, Build = %d, QFE = %d",
				backEndMajorVersionNumber, backEndMinorVersionNumber, backEndBuildVersionNumber,
				backEndQuickFixEngineeringVersionNumber));
		builder.append("\n   Version String:" + compilerVersionString);
		builder.append("\n");
	}

	@Override
	protected String getSymbolTypeName() {
		return "COMPILE3";
	}

	/**
	 * Internal method that breaks out the flag values from the aggregate integral type.
	 * @param flagsIn {@code long} containing unsigned int value.
	 */
	protected void processFlags(long flagsIn) {
		language = LanguageName.fromValue((int) (flagsIn & 0xff));
		flagsIn >>= 8;

		compiledForEditAndContinue = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		notCompiledWithDebugInfo = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		compiledWithLinkTimeCodeGeneration = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		compiledWithBzalignNoDataAlign = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		managedCodeDataPresent = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		compiledWithGsBufferSecurityChecks = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		compiledWithHotPatch = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		convertedWithCvtcil = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		microsoftIntermediateLanguageNetModule = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		compiledWithSdl = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		compiledWithLtcgPgoOrPgu = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		dotExpModule = ((flagsIn & 0x0001) == 0x0001);
	}

}
