/* ###
 * IP: GHIDRA
 *
 * Copyright 2011-2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package ghidra.app.util.exporter;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.security.zynamics.BinExport.BinExport2;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.OptionException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Exports Ghidra disassembly into BinExport v2 format.
 * <p>
 * This is the native format used by BinDiff.
 */
public class BinExportExporter extends Exporter {
	/**
	 * File extension. For historical reasons, this does not include a version nubmer and is usually
	 * stylized in Pascal case.
	 */
	public static final String EXTENSION = "BinExport";
	public static final String SUFFIX = "." + EXTENSION;

	/** Display name that appears in the export dialog. */
	public static final String NAME = "Binary BinExport (v2, for BinDiff)";

	// Option names
	private static final String IDAPRO_COMPAT_OPTGROUP = "IDA Pro Compatibility";
	private static final String IDAPRO_COMPAT_OPT_SUBTRACT_IMAGEBASE =
		"Subtract Imagebase";
	private static final String IDAPRO_COMPAT_OPT_REMAP_MNEMONICS =
		"Remap mnemonics";
	private static final String IDAPRO_COMPAT_OPT_PREPEND_NAMESPACE =
		"Prepend Namespace to Function Names";

	/** Whether to subtract the program image base from addresses for export. */
	private boolean subtractImagebase = false;

	/**
	 * Whether to remap Ghidra's mnemonics into IDA Pro style ones. Note that this is does not performa
	 * comprehensive remapping, but is rather a best effort to somewhat minimize the differences between
	 * disassembly representations.
	 */
	private boolean remapMnemonics = false;

	/** Whether to prepend "namespace::" to function names where the namespace is not "Global". */
	private boolean prependNamespace = false;

	/** Remaps Ghidra instruction mnemonics. */
	public interface MnemonicMapper {

		/**
		 * Returns the remapped instruction mnemonic for a Ghidra instruction.
		 * <p>
		 * The default implementation maps each instruction to itself.
		 */
		default String getInstructionMnemonic(Instruction instr) {
			return instr.getMnemonicString();
		}
	}

	/** Default implementation of the {@code MnemonicMapper} interface. */
	public static class IdentityMnemonicMapper implements MnemonicMapper {
	}

	/**
	 * IDA uses lowercase instruction mnemonics for some architectures (notably X86).
	 */
	public static class IdaProMnemonicMapper implements MnemonicMapper {

		private enum IdaProArchitecture {
			ARM, DALVIK, METAPC, MIPS, PPC, GENERIC
		}

		private final IdaProArchitecture idaArch;

		private final Map<String, String> mapCache = new HashMap<>();

		public IdaProMnemonicMapper(Language language) {
			switch (language.getProcessor().toString().toLowerCase()) {
				case "x86":
					idaArch = IdaProArchitecture.METAPC;
					mapCache.put("RET", "retn");
					break;
				default:
					idaArch = IdaProArchitecture.GENERIC;
			}
		}

		@Override
		public String getInstructionMnemonic(Instruction instr) {
			// TODO(cblichmann): Implement a more sophisticated scheme close to what IDA Pro does.
			final String mnemnonic = instr.getMnemonicString();
			if (idaArch != IdaProArchitecture.METAPC) {
				return mnemnonic;
			}
			return mapCache.computeIfAbsent(mnemnonic, String::toLowerCase);
		}
	}

	public BinExportExporter() {
		// TODO(cblichmann): Add help location.
		super(NAME, EXTENSION, null);
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		return List.of(
			new Option(IDAPRO_COMPAT_OPTGROUP, IDAPRO_COMPAT_OPT_SUBTRACT_IMAGEBASE,
				Boolean.FALSE),
			new Option(IDAPRO_COMPAT_OPTGROUP, IDAPRO_COMPAT_OPT_REMAP_MNEMONICS,
				Boolean.FALSE),
			new Option(IDAPRO_COMPAT_OPTGROUP, IDAPRO_COMPAT_OPT_PREPEND_NAMESPACE,
				Boolean.FALSE));
	}

	@Override
	public void setOptions(List<Option> options) throws OptionException {
		for (final Option option : options) {
			switch (option.getName()) {
				case IDAPRO_COMPAT_OPT_SUBTRACT_IMAGEBASE:
					subtractImagebase = (boolean) option.getValue();
					break;
				case IDAPRO_COMPAT_OPT_REMAP_MNEMONICS:
					remapMnemonics = (boolean) option.getValue();
					break;
				case IDAPRO_COMPAT_OPT_PREPEND_NAMESPACE:
					prependNamespace = (boolean) option.getValue();
					break;
			}
		}
	}

	/**
	 * Returns false. BinExport export only supports entire databases.
	 */
	@Override
	public boolean supportsAddressRestrictedExport() {
		return false;
	}

	@Override
	public boolean export(File file, DomainObject domainObj,
			AddressSetView addrSet, TaskMonitor monitor)
			throws ExporterException, IOException {
		if (!(domainObj instanceof Program)) {
			log.appendMsg("Unsupported type: " + domainObj.getClass().getName());
			return false;
		}
		final Program program = (Program) domainObj;

		monitor.setCancelEnabled(true);
		try {
			final BinExport2Builder builder = new BinExport2Builder(program);
			if (remapMnemonics) {
				builder.setMnemonicMapper(new IdaProMnemonicMapper(program.getLanguage()));
			}
			if (subtractImagebase) {
				builder.setAddressOffset(program.getImageBase().getOffset());
			}
			if (prependNamespace) {
				builder.setPrependNamespace(true);
			}
			final BinExport2 proto = builder.build(monitor);

			monitor.setMessage("Writing BinExport2 file");
			try (final FileOutputStream outputStream = new FileOutputStream(file)) {
				proto.writeTo(outputStream);
			}
		}
		catch (final CancelledException e) {
			return false;
		}
		catch (Exception e) {
			log.appendMsg("Unexpected exception exporting file: " + e.getMessage());
			throw new ExporterException(e);
		}
		return true;
	}
}
