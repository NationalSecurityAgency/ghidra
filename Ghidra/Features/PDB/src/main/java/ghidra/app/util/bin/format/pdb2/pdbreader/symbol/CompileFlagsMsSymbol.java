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
 * This class represents the Compiler Flags symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class CompileFlagsMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x0001;

	protected Processor processor;
	protected LanguageName language;
	protected boolean pcodePresent;
	protected int floatingPrecision;
	protected int floatPackage;
	protected int ambiantDataModel;
	protected int ambiantCodeModel;
	protected boolean compiled32BitMode;
	protected String compilerVersionString;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a string.
	 */
	public CompileFlagsMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		processor = Processor.fromValue(reader.parseUnsignedByteVal());
		//Possible padding here for structure???
		byte[] flags = reader.parseBytes(3);
		processFlags(flags);
		compilerVersionString = reader.parseString(pdb, StringParseType.StringUtf8St);

		// Very important: sStore target machine information.  It is used elsewhere, including
		//  in RegisterName.
		pdb.setTargetProcessor(processor);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the processor.
	 * @return the processor.
	 */
	public Processor getProcessor() {
		return processor;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		builder.append(":\n   Language: ");
		builder.append(language.toString());
		builder.append("\n   Target Processor: ");
		builder.append(processor.toString());
		builder.append("\n   Floating-point precision: " + floatingPrecision);
		builder.append("\n   Floating-point package: " + floatPackage);
		builder.append("\n   Ambiant data: " + ambiantDataModel);
		builder.append("\n   Ambiant code: " + ambiantCodeModel);
		builder.append("\n   PCode present: " + (compiled32BitMode ? "yes" : "no"));
		builder.append("\n   Version String:" + compilerVersionString);
		builder.append("\n");
	}

	@Override
	protected String getSymbolTypeName() {
		return "COMPILE";
	}

	/**
	 * Internal method that breaks out the flag values {@code byte[3]} array.  Method does not
	 * check size.
	 * @param flagsIn {@code byte[]} that needs to have 3 bytes.
	 */
	protected void processFlags(byte[] flagsIn) {
		int flagsByte = flagsIn[0];
		language = LanguageName.fromValue(flagsByte);

		flagsByte = flagsIn[1];
		pcodePresent = ((flagsByte & 0x0001) == 0x0001);
		flagsByte >>= 1;
		floatingPrecision = (flagsByte & 0x03);
		flagsByte >>= 2;
		floatPackage = (flagsByte & 0x03);
		flagsByte >>= 2;
		ambiantDataModel = (flagsByte & 0x07);

		flagsByte = flagsIn[2];
		ambiantCodeModel = (flagsByte & 0x07);
		flagsByte >>= 3;
		compiled32BitMode = ((flagsByte & 0x0001) == 0x0001);

	}

}
