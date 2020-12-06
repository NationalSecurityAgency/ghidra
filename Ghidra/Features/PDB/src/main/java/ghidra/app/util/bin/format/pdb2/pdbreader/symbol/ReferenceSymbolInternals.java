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
 * This class represents various flavors of Internals of Reference symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class ReferenceSymbolInternals extends AbstractSymbolInternals {

	/**
	 * Factory for "regular" version of {@link DataHighLevelShaderLanguageSymbolInternals}.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static ReferenceSymbolInternals parseSt(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		ReferenceSymbolInternalsSt result = new ReferenceSymbolInternalsSt(pdb);
		result.sumName = reader.parseUnsignedIntVal();
		result.offsetActualSymbolInDollarDollarSymbols = reader.parseUnsignedIntVal();
		result.moduleIndex = reader.parseUnsignedShortVal();
		reader.align4();
		return result;
	}

	/**
	 * Factory for "32" version of {@link DataHighLevelShaderLanguageSymbolInternals}.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static ReferenceSymbolInternals parse2(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		ReferenceSymbolInternals2 result = new ReferenceSymbolInternals2(pdb);
		result.sumName = reader.parseUnsignedIntVal();
		result.offsetActualSymbolInDollarDollarSymbols = reader.parseUnsignedIntVal();
		result.moduleIndex = reader.parseUnsignedShortVal();
		result.name = reader.parseString(pdb, StringParseType.StringUtf8Nt);
		reader.align4();
		return result;
	}

	protected long sumName; // Says SUC of the name???
	protected long offsetActualSymbolInDollarDollarSymbols;
	protected int moduleIndex;

	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public ReferenceSymbolInternals(AbstractPdb pdb) {
		super(pdb);
	}

	/**
	 * Returns "sum" (or "suc" or ?) name.
	 * @return Name.
	 */
	public long getSumName() {
		return sumName;
	}

	/**
	 * Returns the actual offset in $$symbol.
	 * @return Actual offset in $$symbol.
	 */
	public long getOffsetActualSymbolInDollarDollarSymbols() {
		return offsetActualSymbolInDollarDollarSymbols;
	}

	/**
	 * Returns the module index.
	 * @return Module index.
	 */
	public int getModuleIndex() {
		return moduleIndex;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format(": %08X: (%4d, %08X)", sumName, moduleIndex,
			offsetActualSymbolInDollarDollarSymbols));
	}

//--------------------------------------------------------------------------------------------------

	/**
	 * This class represents <B>St</B> Internals of the Reference symbol.
	 */
	public static class ReferenceSymbolInternalsSt extends ReferenceSymbolInternals {

		/**
		 * Constructor for this symbol internals.
		 * @param pdb {@link AbstractPdb} to which this symbol belongs.
		 */
		public ReferenceSymbolInternalsSt(AbstractPdb pdb) {
			super(pdb);
		}

	}

	/**
	* This class represents <B>2</B> Internals of the Reference symbol.
	*/
	public static class ReferenceSymbolInternals2 extends ReferenceSymbolInternals {

		protected String name; // Hidden name made into a first class member?

		/**
		 * Constructor for this symbol internals.
		 * @param pdb {@link AbstractPdb} to which this symbol belongs.
		 */
		public ReferenceSymbolInternals2(AbstractPdb pdb) {
			super(pdb);
		}

		/**
		 * Returns the name field of this symbol internals.
		 * @return the name.
		 */
		public String getName() {
			return name;
		}

		@Override
		public void emit(StringBuilder builder) {
			super.emit(builder);
			builder.append(" ");
			builder.append(name);
		}

	}

}
