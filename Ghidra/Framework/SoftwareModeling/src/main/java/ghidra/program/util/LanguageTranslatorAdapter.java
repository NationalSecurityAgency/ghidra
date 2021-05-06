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
package ghidra.program.util;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.datastruct.RangeMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>LanguageTranslatorAdapter</code> provides a default language translator 
 * behavior which may be extended to provide customized language translations.
 */
public abstract class LanguageTranslatorAdapter implements LanguageTranslator {

	protected static final String DEFAULT_COMPILER_SPEC_ID = "default";

	private final LanguageID oldLanguageID;
	private final LanguageID newLanguageID;
	private final int oldLanguageVersion;
	private final int newLanguageVersion;

	private Language oldLanguage;
	private Language newLanguage;

	private HashMap<String, Register> newRegisterNameMap; // maps new register name to new register
	private HashMap<String, AddressSpace> spaceMap;

	private RangeMap oldRegisterRangeMap;

	/**
	 * Constructor for default translator.
	 * @param oldLanguage
	 * @param newLanguage
	 */
	private LanguageTranslatorAdapter(Language oldLanguage, Language newLanguage) {
		this.oldLanguage = oldLanguage;
		this.newLanguage = newLanguage;
		oldLanguageID = oldLanguage.getLanguageID();
		newLanguageID = newLanguage.getLanguageID();
		oldLanguageVersion = oldLanguage.getVersion();
		newLanguageVersion = newLanguage.getVersion();
		buildRegisterNameMap();
		buildRegisterRangeMap();
	}

	/**
	 * Constructor for customized language translators which want to leverage 
	 * some of the default language mappings.  Successful construction does not
	 * guarantee the two languages can utilize the default address space mapping.
	 * This constructor
	 * @param oldLanguageID
	 * @param oldLanguageVersion
	 * @param newLanguageID
	 * @param newLanguageVersion
	 * @see #validateDefaultSpaceMap()
	 */
	protected LanguageTranslatorAdapter(LanguageID oldLanguageID, int oldLanguageVersion,
			LanguageID newLanguageID, int newLanguageVersion) {
		this.oldLanguageID = oldLanguageID;
		this.oldLanguageVersion = oldLanguageVersion;
		this.newLanguageID = newLanguageID;
		this.newLanguageVersion = newLanguageVersion;
	}

	/**
	 * Build register name map - assumes register names have not changed
	 * and that newLanguage has been established
	 */
	private void buildRegisterNameMap() {
		newRegisterNameMap = new HashMap<String, Register>();
		for (Register r : newLanguage.getRegisters()) {
			newRegisterNameMap.put(r.getName().toUpperCase(), r);
			for (String alias : r.getAliases()) {
				newRegisterNameMap.put(alias.toUpperCase(), r);
			}
		}
	}

	/**
	 * Build old register range map - assumes oldLanguage has been established
	 * NOTE: use of RangeMap assumes max register space size of 32-bits
	 */
	private void buildRegisterRangeMap() {
		oldRegisterRangeMap = new RangeMap();
		for (Register reg : oldLanguage.getRegisters()) {
			if (reg.isBaseRegister()) {
				long min = reg.getAddress().getOffset();
				long max = min + reg.getMinimumByteSize() - 1;
				oldRegisterRangeMap.paintRange(min, max, (int) min);
			}
		}
	}

	@Override
	public boolean isValid() {
		if (oldLanguage == null) {
			oldLanguage = findLanguage(oldLanguageID, oldLanguageVersion);
		}
		if (newLanguage == null) {
			newLanguage = findLanguage(newLanguageID, newLanguageVersion);
		}
		if (newRegisterNameMap == null && newLanguage != null) {
			buildRegisterNameMap();
		}
		if (oldRegisterRangeMap == null && oldLanguage != null) {
			buildRegisterRangeMap();
		}
		return oldLanguage != null && newLanguage != null;
	}

	private static Language findLanguage(LanguageID languageID, int languageVersion) {
		OldLanguageFactory oldLanguageFactory = OldLanguageFactory.getOldLanguageFactory();
		LanguageService languageService = DefaultLanguageService.getLanguageService();
		Language language = oldLanguageFactory.getOldLanguage(languageID, languageVersion);
		if (language == null) {
			try {
				language = languageService.getLanguage(languageID);
				if (language.getVersion() != languageVersion) {
					language = null;
				}
			}
			catch (LanguageNotFoundException e) {
			}
		}
		if (language == null) {
			Msg.error(LanguageTranslatorAdapter.class, "Old language version not found: " +
				languageID + " (Version " + languageVersion + ")");
		}
		return language;
	}

	/**
	 * Build and validate the default address space map.  This method must be invoked following instantiation
	 * if the default address space mapping will be used.
	 * @throws IncompatibleLanguageException if a default mapping of the address spaces could not be identified.
	 * @see #getNewAddressSpace(String)
	 */
	protected final void validateDefaultSpaceMap() throws IncompatibleLanguageException {

		if (spaceMap != null) {
			return;
		}

		AddressFactory oldFactory = oldLanguage.getAddressFactory();
		AddressFactory newFactory = newLanguage.getAddressFactory();

		ArrayList<AddressSpace> oldSpaces =
			new ArrayList<AddressSpace>(Arrays.asList(oldFactory.getAddressSpaces()));
		ArrayList<AddressSpace> newSpaces =
			new ArrayList<AddressSpace>(Arrays.asList(newFactory.getAddressSpaces()));

		AddressSpace oldDefaultSpace = oldFactory.getDefaultAddressSpace();
		AddressSpace newDefaultSpace = newFactory.getDefaultAddressSpace();
		if (oldDefaultSpace.getSize() > newDefaultSpace.getSize()) {
			throw new IncompatibleLanguageException(
				"Old language has larger default address space (" + oldDefaultSpace.getSize() +
					"-bit vs. " + newDefaultSpace.getSize() + "-bit) than the new language");
		}

		spaceMap = new HashMap<String, AddressSpace>();

		spaceMap.put(oldDefaultSpace.getName(), newDefaultSpace);
		spaceMap.put(oldFactory.getRegisterSpace().getName(), newFactory.getRegisterSpace());
		oldSpaces.remove(oldDefaultSpace);
		newSpaces.remove(newDefaultSpace);

		// first try to match spaces by name
		Iterator<AddressSpace> spaceIt = oldSpaces.iterator();
		while (spaceIt.hasNext()) {
			AddressSpace oldSpace = spaceIt.next();
			if (!oldSpace.isLoadedMemorySpace() || oldSpace.getType() == AddressSpace.TYPE_CODE) {
				spaceIt.remove();
			}
			else {
				AddressSpace newSpace = findSpaceSameName(oldSpace, newSpaces);
				if (newSpace != null) {
					spaceMap.put(oldSpace.getName(), newSpace);
					newSpaces.remove(newSpace);
					spaceIt.remove();
				}
			}
		}

		// now try to match spaces by attributes
//		spaceIt = oldSpaces.iterator();
//		while(spaceIt.hasNext()) {
//			AddressSpace oldSpace = spaceIt.next();
//			AddressSpace newSpace = findSpaceSameName(oldSpace, newSpaces);
//			if (newSpace != null) {
//				spaceMap.put(oldSpace.getName(), newSpace);
//				newSpaces.remove(newSpace);
//			}
//		}

		if (!oldSpaces.isEmpty()) {
//			spaceMap = null;
			throw new IncompatibleLanguageException(
				"Failed to map one or more address spaces: " + oldSpaces);
		}

	}

	protected static AddressSpace findSpaceSameName(AddressSpace oldSpace,
			ArrayList<AddressSpace> newSpaces) throws IncompatibleLanguageException {

		Iterator<AddressSpace> it = newSpaces.iterator();
		while (it.hasNext()) {
			AddressSpace space = it.next();
			if (space.getName().equals(oldSpace.getName())) {
				if (oldSpace.getSize() > space.getSize()) {
					throw new IncompatibleLanguageException("Old language space (" +
						oldSpace.getName() + ") has larger address space than the new language");
				}
				return space;
			}
		}
		return null;
	}

	@Override
	public Language getOldLanguage() {
		if (oldLanguage == null) {
			throw new IllegalStateException("Translator has not been validated");
		}
		return oldLanguage;
	}

	@Override
	public LanguageID getOldLanguageID() {
		return oldLanguageID;
	}

	@Override
	public int getOldVersion() {
		return oldLanguageVersion;
	}

	@Override
	public Language getNewLanguage() {
		if (newLanguage == null) {
			throw new IllegalStateException("Translator has not been validated");
		}
		return newLanguage;
	}

	@Override
	public LanguageID getNewLanguageID() {
		return newLanguageID;
	}

	@Override
	public int getNewVersion() {
		return newLanguageVersion;
	}

	@Override
	public Register getOldRegister(Address oldAddr, int size) {
		if (oldLanguage == null) {
			throw new IllegalStateException("Translator has not been validated");
		}
		return oldLanguage.getRegister(oldAddr, size);
	}

	@Override
	public Register getOldRegisterContaining(Address oldAddr) {
		int value = oldRegisterRangeMap.getValue(oldAddr.getOffset());
		Register oldReg = oldLanguage.getRegister(oldAddr.getNewAddress(value), 0);
		if (value == 0 && oldReg != null) {
			// NOTE: range map will return 0 if range not found - additional checking will be 
			// required to eliminate potential match
			long oldOffset = oldAddr.getOffset();
			if (oldOffset < 0 || oldOffset >= (oldReg.getOffset() + oldReg.getMinimumByteSize())) {
				return null;
			}
		}
		return oldReg;
	}

	@Override
	public Register getOldContextRegister() {
		return oldLanguage.getContextBaseRegister();
	}

	@Override
	public Register getNewRegister(Register oldReg) {
		if (newRegisterNameMap == null) {
			throw new IllegalStateException("Translator has not been validated");
		}
		return newRegisterNameMap.get(oldReg.getName().toUpperCase());
	}

	@Override
	public Register getNewContextRegister() {
		return newLanguage.getContextBaseRegister();
	}

	@Override
	public AddressSpace getNewAddressSpace(String oldSpaceName) {
		if (spaceMap == null) {
			throw new IllegalStateException("Address space map has not been validated");
		}
		return spaceMap.get(oldSpaceName);
	}

	@Override
	public boolean isValueTranslationRequired(Register oldReg) {
		Register newReg = getNewRegister(oldReg);
		if (newReg == null || !oldReg.isBaseRegister()) {
			return false;
		}
		return !isSameRegisterConstruction(oldReg, newReg);
	}

	protected boolean isSameRegisterConstruction(Register oldReg, Register newReg) {
		if (oldReg.getLeastSignificatBitInBaseRegister() != newReg
				.getLeastSignificatBitInBaseRegister() ||
			oldReg.getBitLength() != newReg.getBitLength()) {
			return false;
		}
		List<Register> oldChildren = oldReg.getChildRegisters();
		for (Register oldChild : oldChildren) {
			Register newChild = getNewRegister(oldChild);
			if (newChild == null || !isSameRegisterConstruction(oldChild, newChild)) {
				return false;
			}
		}
		return true;
	}

	private RegisterValue translateContextValue(Register newReg, RegisterValue oldValue) {
		Register reg = oldValue.getRegister();
		if (!reg.hasChildren()) {
			if (!oldValue.hasValue()) {
				return null;
			}
			return new RegisterValue(newReg, oldValue.getUnsignedValueIgnoreMask());
		}
		RegisterValue value = null;
		for (Register child : reg.getChildRegisters()) {
			RegisterValue oldChildValue = new RegisterValue(child, oldValue.toBytes());
			Register newChild = newLanguage.getRegister(child.getName());
			if (newChild != null && newChild.getParentRegister() == newReg) {
				RegisterValue childValue = translateContextValue(newChild, oldChildValue);
				if (childValue != null) {
					value = childValue.combineValues(value);
				}
			}
			else {
				newChild = newRegisterNameMap.get(child.getName());
				if (newChild != null && newChild.getParentRegister() == newReg) {
					RegisterValue childValue = translateContextValue(newChild, oldChildValue);
					if (childValue != null) {
						value = childValue.combineValues(value);
					}
				}
			}
		}
		return value;
	}

	@Override
	public RegisterValue getNewRegisterValue(RegisterValue oldValue) {
		Register oldReg = oldValue.getRegister();
		if (!oldReg.isBaseRegister()) {
			throw new IllegalArgumentException("oldValue must correspond to an old base register");
		}

		Register newReg = getNewRegister(oldReg);
		if (newReg == null) {
			return null;
		}

		if (newReg.isProcessorContext()) {
			return translateContextValue(newReg, oldValue);
		}

		return new RegisterValue(newReg, oldValue.toBytes());
	}

	@Override
	public String toString() {
		return "[" + getOldLanguageID() + " (Version " + getOldVersion() + ")] -> [" +
			getNewLanguageID() + " (Version " + getNewVersion() + " )] {" + getClass().getName() +
			"}";
	}

	/**
	 * Default language translator.
	 */
	private static class DefaultLanguageTranslator extends LanguageTranslatorAdapter {

		DefaultLanguageTranslator(Language oldLanguage, Language newLanguage) {
			super(oldLanguage, newLanguage);
		}

		@Override
		public boolean isValid() {
			if (super.isValid()) {
				try {
					validateDefaultSpaceMap();
				}
				catch (IncompatibleLanguageException e) {
					Msg.error(this, "Translator can not map address spaces: " + this);
					return false;
				}
				Register newContextReg = getNewLanguage().getContextBaseRegister();
				if (newContextReg != null) {
					Register oldContextReg = getOldLanguage().getContextBaseRegister();
					if (oldContextReg == null ||
						!isSameRegisterConstruction(oldContextReg, newContextReg)) {
						Msg.error(this, "Translator can not map context register: " + this);
						return false;
					}
				}
				return true;
			}
			return false;
		}

		@Override
		public String toString() {
			return "[" + getOldLanguageID() + " (Version " + getOldVersion() + ")] -> [" +
				getNewLanguageID() + " (Version " + getNewVersion() + ")] {Default Translator}";
		}

	}

	@Override
	public CompilerSpecID getNewCompilerSpecID(CompilerSpecID oldCompilerSpecID) {

		Language newLang = getNewLanguage();
		List<CompilerSpecDescription> compilerSpecDescriptions =
			newLang.getCompatibleCompilerSpecDescriptions();
		for (CompilerSpecDescription descr : compilerSpecDescriptions) {
			if (descr.getCompilerSpecID().equals(oldCompilerSpecID)) {
				return oldCompilerSpecID;
			}
		}
		if (compilerSpecDescriptions.size() != 0) {
			return compilerSpecDescriptions.get(0).getCompilerSpecID();
		}
		return oldCompilerSpecID;
	}

	@Override
	public CompilerSpec getOldCompilerSpec(CompilerSpecID oldCompilerSpecID)
			throws CompilerSpecNotFoundException {
		return new TemporaryCompilerSpec(this, oldCompilerSpecID);
	}

	@Override
	public void fixupInstructions(Program program, Language oldLanguage, TaskMonitor monitor)
			throws Exception, CancelledException {
		// do nothing
	}

	/**
	 * Return a validated default translator if one can be determined.
	 * @param oldLanguage
	 * @param newLanguage
	 * @return default translator or null if reasonable mappings can not be determined.
	 */
	static LanguageTranslator getDefaultLanguageTranslator(Language oldLanguage,
			Language newLanguage) {

		DefaultLanguageTranslator translator =
			new DefaultLanguageTranslator(oldLanguage, newLanguage);
		if (!translator.isValid()) {
			translator = null;
		}
		return translator;
	}

	/**
	 * Return a validated default translator between two versions of the same language or null
	 * if one can not be determined.
	 * @param languageID
	 * @param fromVersion
	 * @param toVersion
	 * @return
	 */
	static LanguageTranslator getDefaultLanguageTranslator(LanguageID languageID, int fromVersion,
			int toVersion) {

		Language toLanguage = findLanguage(languageID, toVersion);
		Language fromLanguage = findLanguage(languageID, fromVersion);
		if (toLanguage == null || fromLanguage == null) {
			return null;
		}
		return getDefaultLanguageTranslator(fromLanguage, toLanguage);
	}
}

class TemporaryCompilerSpec implements CompilerSpec {

	private final CompilerSpecID oldCompilerSpecID;
	private final CompilerSpec newCompilerSpec;
	private final CompilerSpecDescription description;
	private final LanguageTranslator translator;

	public TemporaryCompilerSpec(LanguageTranslator translator, CompilerSpecID oldCompilerSpecID)
			throws CompilerSpecNotFoundException {
		this.translator = translator;
		this.oldCompilerSpecID = oldCompilerSpecID;
		newCompilerSpec = translator.getNewLanguage()
				.getCompilerSpecByID(translator.getNewCompilerSpecID(oldCompilerSpecID));
		description = new BasicCompilerSpecDescription(oldCompilerSpecID,
			newCompilerSpec.getCompilerSpecDescription().getCompilerSpecName());
	}

	@Override
	public boolean doesCDataTypeConversions() {
		return newCompilerSpec.doesCDataTypeConversions();
	}

	@Override
	public void applyContextSettings(DefaultProgramContext ctx) {
	}

	@Override
	public PrototypeModel[] getCallingConventions() {
		return new PrototypeModel[0];
	}

	@Override
	public PrototypeModel getCallingConvention(String name) {
		return null;
	}

	@Override
	public PrototypeModel[] getAllModels() {
		return new PrototypeModel[0];
	}

	@Override
	public CompilerSpecDescription getCompilerSpecDescription() {
		return description;
	}

	@Override
	public CompilerSpecID getCompilerSpecID() {
		return oldCompilerSpecID;
	}

	@Override
	public PrototypeModel getDefaultCallingConvention() {
		return null;
	}

	@Override
	public DecompilerLanguage getDecompilerOutputLanguage() {
		return DecompilerLanguage.C_LANGUAGE;
	}

	@Override
	public PrototypeModel getPrototypeEvaluationModel(EvaluationModelType modelType) {
		return newCompilerSpec.getPrototypeEvaluationModel(modelType);
	}

	@Override
	public Language getLanguage() {
		return translator.getOldLanguage();
	}

	@Override
	public Register getStackPointer() {
		throw new UnsupportedOperationException("Language for upgrade use only (getStackPointer)");
	}

	public void reloadCompilerSpec() {
		throw new UnsupportedOperationException(
			"Language for upgrade use only (reloadCompilerSpec)");
	}

	@Override
	public boolean stackGrowsNegative() {
		return newCompilerSpec.stackGrowsNegative();
	}

	@Override
	public AddressSpace getAddressSpace(String spaceName) {
		return newCompilerSpec.getAddressSpace(spaceName);
	}

	@Override
	public AddressSpace getStackSpace() {
		return newCompilerSpec.getStackSpace();
	}

	@Override
	public AddressSpace getStackBaseSpace() {
		return newCompilerSpec.getStackBaseSpace();
	}

	@Override
	public boolean isGlobal(Address addr) {
		return newCompilerSpec.isGlobal(addr);
	}

	@Override
	public DataOrganization getDataOrganization() {
		return newCompilerSpec.getDataOrganization();
	}

	@Override
	public PrototypeModel matchConvention(GenericCallingConvention genericCallingConvention) {
		throw new UnsupportedOperationException("Language for upgrade use only (matchConvention)");
	}

	@Override
	public PrototypeModel findBestCallingConvention(Parameter[] params) {
		throw new UnsupportedOperationException(
			"Language for upgrade use only (findBestCallingConvention)");
	}

	public int getDefaultStackAlignment() {
		throw new UnsupportedOperationException(
			"Language for upgrade use only (getDefaultStackAlignment)");
	}

	@Override
	public boolean isStackRightJustified() {
		throw new UnsupportedOperationException(
			"Language for upgrade use only (isStackRightJustified)");
	}

	@Override
	public String getProperty(String key) {
		return newCompilerSpec.getProperty(key);
	}

	@Override
	public Set<String> getPropertyKeys() {
		return newCompilerSpec.getPropertyKeys();
	}

	@Override
	public String getProperty(String key, String defaultString) {
		return newCompilerSpec.getProperty(key, defaultString);
	}

	@Override
	public boolean getPropertyAsBoolean(String key, boolean defaultBoolean) {
		return newCompilerSpec.getPropertyAsBoolean(key, defaultBoolean);
	}

	@Override
	public int getPropertyAsInt(String key, int defaultInt) {
		return newCompilerSpec.getPropertyAsInt(key, defaultInt);
	}

	@Override
	public boolean hasProperty(String key) {
		return newCompilerSpec.hasProperty(key);
	}

	@Override
	public PcodeInjectLibrary getPcodeInjectLibrary() {
		return newCompilerSpec.getPcodeInjectLibrary();
	}
}
