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
 * This class represents various flavors of Internals of the High Level Shader Language symbol.
 * <P>
 * Note: we have guessed that HLSL means High Level Shader Language.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class DataHighLevelShaderLanguageSymbolInternals extends AbstractSymbolInternals {

	/**
	 * Factory for "regular" version of {@link DataHighLevelShaderLanguageSymbolInternals}.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static DataHighLevelShaderLanguageSymbolInternals parse(AbstractPdb pdb,
			PdbByteReader reader) throws PdbException {
		DataHighLevelShaderLanguageSymbolInternals32 result =
			new DataHighLevelShaderLanguageSymbolInternals32(pdb);
		result.typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		result.registerType = HLSLRegisterType.fromValue(reader.parseUnsignedShortVal());
		result.dataSlot = reader.parseUnsignedShortVal();
		result.dataOffset = reader.parseUnsignedShortVal();
		result.textureSlotStart = reader.parseUnsignedShortVal();
		result.samplerSlotStart = reader.parseUnsignedShortVal();
		result.uavSlotStart = reader.parseUnsignedShortVal();
		result.name = reader.parseString(pdb, StringParseType.StringUtf8Nt);
		return result;
	}

	/**
	 * Factory for "32" version of {@link DataHighLevelShaderLanguageSymbolInternals}.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static DataHighLevelShaderLanguageSymbolInternals parse32(AbstractPdb pdb,
			PdbByteReader reader) throws PdbException {
		DataHighLevelShaderLanguageSymbolInternals32 result =
			new DataHighLevelShaderLanguageSymbolInternals32(pdb);
		result.typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		result.dataSlot = reader.parseUnsignedIntVal();
		result.dataOffset = reader.parseUnsignedIntVal();
		result.textureSlotStart = reader.parseUnsignedIntVal();
		result.samplerSlotStart = reader.parseUnsignedIntVal();
		result.uavSlotStart = reader.parseUnsignedIntVal();
		result.registerType = HLSLRegisterType.fromValue(reader.parseUnsignedShortVal());
		result.name = reader.parseString(pdb, StringParseType.StringUtf8Nt);
		return result;
	}

	/**
	 * Factory for "32Ext" version of {@link DataHighLevelShaderLanguageSymbolInternals}.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static DataHighLevelShaderLanguageSymbolInternals parse32Ext(AbstractPdb pdb,
			PdbByteReader reader) throws PdbException {
		DataHighLevelShaderLanguageSymbolInternals32Extended result =
			new DataHighLevelShaderLanguageSymbolInternals32Extended(pdb);
		result.typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		result.registerIndex = reader.parseUnsignedIntVal();
		result.dataOffset = reader.parseUnsignedIntVal();
		result.bindSpace = reader.parseUnsignedIntVal();
		result.bindSlot = reader.parseUnsignedIntVal();
		result.registerType = HLSLRegisterType.fromValue(reader.parseUnsignedShortVal());
		result.name = reader.parseString(pdb, StringParseType.StringUtf8Nt);
		return result;
	}

	protected RecordNumber typeRecordNumber;
	protected long dataOffset;
	protected HLSLRegisterType registerType;
	protected String name;

	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public DataHighLevelShaderLanguageSymbolInternals(AbstractPdb pdb) {
		super(pdb);
	}

	public long getDataOffset() {
		return dataOffset;
	}

	public HLSLRegisterType getRegisterType() {
		return registerType;
	}

	/**
	 * Returns the type record number.
	 * @return Type record number.
	 */
	public RecordNumber getTypeRecordNumber() {
		return typeRecordNumber;
	}

	public String getName() {
		return name;
	}

//--------------------------------------------------------------------------------------------------

	/**
	 * This class represents Internals  and Internal 32 of the High Level Shader Language symbol.
	 * <P>
	 * Note: we have guessed that HLSL means High Level Shader Language.
	 */
	public static class DataHighLevelShaderLanguageSymbolInternals32
			extends DataHighLevelShaderLanguageSymbolInternals {

		protected long dataSlot;
		protected long textureSlotStart;
		protected long samplerSlotStart;
		protected long uavSlotStart;

		/**
		 * Constructor for this symbol internals.
		 * @param pdb {@link AbstractPdb} to which this symbol belongs.
		 */
		public DataHighLevelShaderLanguageSymbolInternals32(AbstractPdb pdb) {
			super(pdb);
		}

		/**
		 * Return the data slot.
		 * @return the data slot.
		 */
		public long getDataSlot() {
			return dataSlot;
		}

		/**
		 * Return the texture slot start.
		 * @return the texture slot start.
		 */
		public long getTextureSlotStart() {
			return textureSlotStart;
		}

		/**
		 * Return the sampler slot start.
		 * @return the sampler slot start.
		 */
		public long getSamplerSlotStart() {
			return samplerSlotStart;
		}

		/**
		 * Return the UAV slot start.
		 * @return the UAV slot start.
		 */
		public long getUavSlotStart() {
			return uavSlotStart;
		}

		@Override
		public void emit(StringBuilder builder) {
			builder.append(String.format(": Type: %s. %s\n", pdb.getTypeRecord(typeRecordNumber),
				getRegisterType().toString()));
			builder.append(String.format(
				"   base data: slot = %d offset = %d, texture slot = %d, sampler slot = %d, UAV slot = %d\n",
				dataSlot, dataOffset, textureSlotStart, samplerSlotStart, uavSlotStart));
		}

	}

	/**
	 * This class represents Extended Internals 32 of the High Level Shader Language symbol.
	 * <P>
	 * Note: we have guessed that HLSL means High Level Shader Language.
	 * <P>
	 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
	 *  base class for more information.
	 */
	public static class DataHighLevelShaderLanguageSymbolInternals32Extended
			extends DataHighLevelShaderLanguageSymbolInternals {

		protected long registerIndex;
		protected long bindSpace;
		protected long bindSlot;

		/**
		 * Constructor for this symbol internals.
		 * @param pdb {@link AbstractPdb} to which this symbol belongs.
		 */
		public DataHighLevelShaderLanguageSymbolInternals32Extended(AbstractPdb pdb) {
			super(pdb);
		}

		/**
		 * Return the register index.
		 * @return the register index.
		 */
		public long getRegisterIndex() {
			return registerIndex;
		}

		/**
		 * Return the bind space.
		 * @return the bind space.
		 */
		public long getBindSpace() {
			return bindSpace;
		}

		/**
		 * Return the bind slot.
		 * @return the bind slot.
		 */
		public long getBindSlot() {
			return bindSlot;
		}

		@Override
		public void emit(StringBuilder builder) {
			builder.append(String.format(": Type: %s. %s\n", pdb.getTypeRecord(typeRecordNumber),
				getRegisterType().toString()));
			builder.append(String.format(
				"   register index = %d, base data offset start = %d, bind space = %d, bind slot = %d\n",
				registerIndex, dataOffset, bindSpace, bindSlot));
		}

	}

}
