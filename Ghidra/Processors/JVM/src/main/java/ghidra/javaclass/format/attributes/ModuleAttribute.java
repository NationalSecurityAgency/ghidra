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
package ghidra.javaclass.format.attributes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.javaclass.format.constantpool.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Note: text in comments taken from jvms12.pdf
 * <p>
 * The {@code Module} attribute indicates:
 * <ul>
 *  <li> the modules required by a module </li>
 *  <li> the packages exported and opened by a module </li>
 *  <li> the services used and provided by a module </li>
 * </ul>  
 */
public class ModuleAttribute extends AbstractAttributeInfo {

	private short module_name_index;
	private short module_flags;
	private short module_version_index;
	private short requires_count;
	private ModuleAttributeRequires[] moduleAttributeRequires;
	private short exports_count;
	private ModuleAttributeExports[] moduleAttributeExports;
	private short opens_count;
	private ModuleAttributeOpens[] moduleAttributeOpens;
	private short uses_count;
	private short[] uses_index;
	private short provides_count;
	private ModuleAttributeProvides[] moduleAttributeProvides;

	protected ModuleAttribute(BinaryReader reader) throws IOException {
		super(reader);
		module_name_index = reader.readNextShort();
		module_flags = reader.readNextShort();
		module_version_index = reader.readNextShort();
		requires_count = reader.readNextShort();
		moduleAttributeRequires = new ModuleAttributeRequires[getRequiresCount()];
		for (int i = 0; i < getRequiresCount(); i++) {
			moduleAttributeRequires[i] = new ModuleAttributeRequires(reader);
		}
		exports_count = reader.readNextShort();
		moduleAttributeExports = new ModuleAttributeExports[getExportsCount()];
		for (int i = 0; i < getExportsCount(); i++) {
			moduleAttributeExports[i] = new ModuleAttributeExports(reader);
		}
		opens_count = reader.readNextShort();
		moduleAttributeOpens = new ModuleAttributeOpens[getOpensCount()];
		for (int i = 0; i < getOpensCount(); i++) {
			moduleAttributeOpens[i] = new ModuleAttributeOpens(reader);
		}
		uses_count = reader.readNextShort();
		uses_index = new short[getUsesCount()];
		for (int i = 0; i < getUsesCount(); i++) {
			uses_index[i] = reader.readNextShort();
		}
		provides_count = reader.readNextShort();
		moduleAttributeProvides = new ModuleAttributeProvides[getProvidesCount()];
		for (int i = 0; i < getProvidesCount(); i++) {
			moduleAttributeProvides[i] = new ModuleAttributeProvides(reader);
		}

	}

	/**
	 * Returns {@code module_name_index}, which must be a valid index into the constant pool.
	 * The constant_pool entry at that index must be a {@link ConstantPoolModuleInfo} structure
	 * denoting the current module.
	 * @return the module name index
	 */
	public int getModuleNameIndex() {
		return module_name_index & 0xffff;
	}

	/**
	 * The value of the {@code module_flags} item is as follows:
	 * <ul>
	 * <li> 0x0020 (ACC_OPEN): indicates that this module is open </li>
	 * <li> 0x10000 (ACC_SYNTHETIC): Indicates that this module was not explicitly or implicitly
	 * declared </li>
	 * <li> 0x8000 (ACC_MANDATED) indicates that this module was implicitly declared </li>
	 * </ul>
	 * @return the module flags
	 */
	public int getModuleFlags() {
		return module_flags & 0xffff;
	}

	/**
	 * The value of the {@code module_version_index} item must be either zero or a valid index
	 * into the constant pool table.  If the value is zero, no version information about the
	 * current module is present. If the value is nonzero, the constant pool entry at that index
	 * must be a {@link ConstantPoolUtf8Info} structure representing the version of the current module.
	 * @return the module version index.
	 */
	public int getModuleVersionIndex() {
		return module_version_index & 0xffff;
	}

	/**
	 * The value of the {@code requires_count} item indicates the number of entries in the 
	 * {@code requires} table.
	 * @return the requires count
	 */
	public int getRequiresCount() {
		return requires_count & 0xffff;
	}

	/**
	 * Indicates the number of entries in the exports table
	 * @return the exports count
	 */
	public int getExportsCount() {
		return exports_count & 0xffff;
	}

	/**
	 * {@code opens_count} indicates the number of entries in the {@code opens} table.
	 * @return the opens count
	 */
	public int getOpensCount() {
		return opens_count & 0xffff;
	}

	/**
	 * {@code uses_count} indicates the number of entries in the {@code uses_index} table.
	 * @return {@code uses_count}
	 */
	public int getUsesCount() {
		return uses_count & 0xffff;
	}

	/**
	 * The value of each entry in the uses_index table must be a valid index into the constant
	 * pool. The entry at that index must be a {@link ConstantPoolClassInfo} structure representing
	 * a service interface which the current module may discover via {@link java.util.ServiceLoader}.
	 * @param i entry
	 * @return index at entry {@code i}
	 */
	public int getUsesEntry(int i) {
		return uses_index[i] & 0xffff;
	}

	/**
	 * {@code provides_count} indicates the number of entries in the {@code provides} table.
	 * @return {@code provides_count}
	 */
	public int getProvidesCount() {
		return provides_count & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure("Module_attribute");
		structure.add(WORD, "module_name_index", null);
		structure.add(WORD, "module_flags", null);
		structure.add(WORD, "module_version_index", null);
		structure.add(WORD, "requires_count", null);
		for (int i = 0; i < getRequiresCount(); i++) {
			structure.add(moduleAttributeRequires[i].toDataType(), "requires_" + i, null);
		}
		structure.add(WORD, "exports_count", null);
		for (int i = 0; i < getExportsCount(); i++) {
			structure.add(moduleAttributeExports[i].toDataType(), "exports_" + i, null);
		}
		structure.add(WORD, "opens_count", null);
		for (int i = 0; i < getOpensCount(); i++) {
			structure.add(moduleAttributeOpens[i].toDataType(), "opens_" + i, null);
		}
		structure.add(WORD, "uses_count", null);
		for (int i = 0; i < getUsesCount(); i++) {
			structure.add(WORD, "uses_" + i, null);
		}
		structure.add(WORD, "provides_count", null);
		for (int i = 0; i < getProvidesCount(); i++) {
			structure.add(WORD, "provides_" + i, null);
		}

		return structure;
	}

	/**
	 * Objects of this class specify a dependence of the current module.
	 */
	static class ModuleAttributeRequires implements StructConverter {

		private short requires_index;
		private short requires_flags;
		private short requires_version_index;

		public ModuleAttributeRequires(BinaryReader reader) throws IOException {
			requires_index = reader.readNextShort();
			requires_flags = reader.readNextShort();
			requires_version_index = reader.readNextShort();
		}

		/**
		 * The value of the {@code requires_index} item must be a valid index into
		 * the constant pool.  The entry at that index must be a {@link ConstantPoolModuleInfo} structure
		 * denoting a module that the current module depends on.
		 * @return the requires index
		 */
		public int getRequiresIndex() {
			return requires_index & 0xffff;
		}

		/**
		 * The value of the {@code requires_flags} item is as follows:
		 * <ul>
		 * <li> 0x0020 ACC_TRANSITIVE </li>
		 * <li> 0x0040 ACC_STATIC_PHASE </li>
		 * <li> 0x1000 ACC_SYNTHETIC </li>
		 * <li> 0x8000 ACC_MANDATED </li>
		 * </ul>
		 * @return the requires flags
		 */
		public short getRequiresFlags() {
			return requires_flags;
		}

		/**
		 * Must be either 0 or a valid index into the constant pool.  If the value of the
		 * item is nonzero, the constant pool entry at that index must be a {@link ConstantPoolUtf8Info}
		 * structure representing the version of the module specified by {@code requires_index}.
		 * @return requires_index
		 */
		public int getRequiresVersionIndex() {
			return requires_version_index & 0xffff;
		}

		@Override
		public DataType toDataType() throws DuplicateNameException, IOException {
			Structure structure = new StructureDataType("requires", 0);
			structure.add(WORD, "requires_index", null);
			structure.add(WORD, "requires_flags", null);
			structure.add(WORD, "requires_version_index", null);
			return structure;
		}

	}

	/**
	 * Each entry in the {@code exports} table specifies a package exported by the current module.
	 */
	static class ModuleAttributeExports implements StructConverter {

		private short exports_index;
		private short exports_flags;
		private short exports_to_count;
		private short[] exports_to_index;

		public ModuleAttributeExports(BinaryReader reader) throws IOException {
			exports_index = reader.readNextShort();
			exports_flags = reader.readNextShort();
			exports_to_count = reader.readNextShort();
			exports_to_index = new short[getExportsToCount()];
			for (int i = 0; i < getExportsToCount(); i++) {
				exports_to_index[i] = reader.readNextShort();
			}
		}

		/**
		 * {@code exports_index} must be a valid index into the constant pool.  The
		 * entry at that index must be a {@link ConstantPoolPackageInfo} structure
		 * representing a package exported by the current module.
		 * @return exports_index
		 */
		public int getExportsIndex() {
			return exports_index & 0xffff;
		}

		/**
		 * The value of {@code exports_flags} is as follows:
		 * <ul>
		 * <li> 0x1000 (ACC_SYNTHETIC) </li>
		 * <li> 0x8000 (ACC_MANDATED)  </li>
		 * </ul>
		 * @return exports_flags
		 */
		public short getExportsFlags() {
			return exports_flags;
		}

		/**
		 * {@code exports_to_count} indicates the number of entries in the
		 * {@code exports_to_index} table
		 * @return {@code exports_to_count}
		 */
		public int getExportsToCount() {
			return exports_to_count & 0xffff;
		}

		/**
		 * The value of each entry in the {@cod exports_to_index} must be a valid index
		 * into the constant pool.  The entry at that index must be a {@link ConstantPoolModuleInfo}
		 * structure denoting a module whose code can access the types and members in this exported
		 * package
		 * @param i the entry to retrieve 
		 * @return module index
		 */
		public int getExportsToEntry(int i) {
			return exports_to_index[i] & 0xffff;
		}

		@Override
		public DataType toDataType() throws DuplicateNameException, IOException {
			Structure structure = new StructureDataType("exports", 0);
			structure.add(WORD, "exports_index", null);
			structure.add(WORD, "exports_flags", null);
			structure.add(WORD, "exports_to_counts", null);
			for (int i = 0; i < getExportsToCount(); i++) {
				structure.add(WORD, "exports_to_index_" + i, null);
			}
			return structure;
		}

	}

	/**
	 * An object of this class specifies a package opened by the current module.
	 */
	static class ModuleAttributeOpens implements StructConverter {

		private short opens_index;
		private short opens_flags;
		private short opens_to_count;
		private short[] opens_to_index;

		public ModuleAttributeOpens(BinaryReader reader) throws IOException {
			opens_index = reader.readNextShort();
			opens_flags = reader.readNextShort();
			opens_to_count = reader.readNextShort();
			opens_to_index = new short[getOpensToCount()];
			for (int i = 0; i < getOpensToCount(); i++) {
				opens_to_index[i] = reader.readNextShort();
			}

		}

		/**
		 * {@code opens_index} must be a valid index into the constant pool. The entry at this
		 * index must be a {@link ConstantPoolPackageInfo} structure representing a package
		 * opened by the current module.
		 * @return {@code opens_index}
		 */
		public int getOpensIndex() {
			return opens_index & 0xffff;
		}

		/**
		 * The value of {@code opens_flags} is as follows:
		 * <ul>
		 * <li> 0x1000 (ACC_SYNTHETIC) </li>
		 * <li> 0x8000 (ACC_MANDATED) </li>
		 * </ul>
		 * @return {@code opens_flags}
		 */
		public short getOpensFlags() {
			return opens_flags;
		}

		/**
		 * {@code opens_to_count} indicates the number of entries in the {@code opens_to_index}
		 * table.
		 * @return {@code opens_to_count}
		 */
		public int getOpensToCount() {
			return opens_to_count & 0xffff;
		}

		/**
		 * Each entry in the {@code opens_to_index} table must be a valid index into
		 * the constant pool. The entry at that index must be a {@link ConstantPoolModuleInfo} structure
		 * denoting a module whose code can access the types and members in this opened package.
		 * @param i desired entry
		 * @return index
		 */
		public int getOpensToEntry(int i) {
			return opens_to_index[i] & 0xffff;
		}

		@Override
		public DataType toDataType() throws DuplicateNameException, IOException {
			Structure structure = new StructureDataType("exports", 0);
			structure.add(WORD, "opens_index", null);
			structure.add(WORD, "opens_flags", null);
			structure.add(WORD, "opens_to_counts", null);
			for (int i = 0; i < getOpensToCount(); i++) {
				structure.add(WORD, "opens_to_index_" + i, null);
			}
			return structure;
		}

	}

	/**
	 * Each entry in the {@code provides} table represents a service implementation for a
	 * given service interface.
	 */
	static class ModuleAttributeProvides implements StructConverter {

		private short provides_index;
		private short provides_with_count;
		private short[] provides_with_index;

		public ModuleAttributeProvides(BinaryReader reader) throws IOException {
			provides_index = reader.readNextShort();
			provides_with_count = reader.readNextShort();
			provides_with_index = new short[getProvidesWithCount()];
			for (int i = 0; i < getProvidesWithCount(); i++) {
				provides_with_index[i] = reader.readNextShort();
			}
		}

		/**
		 * {@code provides_index} must be a valid index into the constant pool. The entry
		 * at that index must be a {@link ConstantPoolClassInfo} structure representing a
		 * service interface for which the current module provides a service implementation.
		 * @return {@code provides_index}
		 */
		public int getProvidesIndex() {
			return provides_index & 0xffff;
		}

		/**
		 * {@code provides_with_count} indicates the number of entries in the {@code provides_with_index} table
		 * @return {@code provides_with_count}
		 */
		public int getProvidesWithCount() {
			return provides_with_count & 0xffff;
		}

		/**
		 * The value of each entry in the {@code provides_with_index} table must be a valid
		 * index into the constant pool. The entry at that index must be a {@link ConstantPoolClassInfo}
		 * structure representing a service implementation for the service interface specified by
		 * {@code provides_index}.
		 * @param i entry
		 * @return index
		 */
		public int getProvidesWithIndexEntry(int i) {
			return provides_with_index[i];
		}

		@Override
		public DataType toDataType() throws DuplicateNameException, IOException {
			Structure structure = new StructureDataType("provides", 0);
			structure.add(WORD, "provides_index", null);
			structure.add(WORD, "provides_with_counts", null);
			for (int i = 0; i < getProvidesWithCount(); i++) {
				structure.add(WORD, "provides_with_index_" + i, null);
			}
			return structure;
		}

	}

}
