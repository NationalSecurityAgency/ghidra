package ghidra.app.util.bin.format.elf.extend;

import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.program.model.lang.Language;

public class I960_ElfExtension extends ElfExtension {

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_960;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		return canHandle(elfLoadHelper.getElfHeader()) &&
			"I960".equals(language.getProcessor().toString());
	}

	@Override
	public String getDataTypeSuffix() {
		return "_I960";
	}

}
