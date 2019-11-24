package ghidra.app.cmd.data.rtti.gcc.builder;

import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Map;
import java.util.Map.Entry;
import java.util.List;

import ghidra.app.cmd.data.rtti.gcc.GccUtils;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.app.cmd.data.rtti.gcc.VtableUtils;
import ghidra.app.cmd.data.rtti.gcc.VttModel;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.util.Msg;

import static ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory.getTypeInfo;

public abstract class AbstractTypeInfoProgramBuilder extends ProgramBuilder {

	private Map<Long, String> typeMap;
	private Map<Long, String> nameMap;
	private Map<Long, String> vtableMap;
	private Map<Long, String> vttMap;
	private Long[] functionOffsets;

	protected AbstractTypeInfoProgramBuilder(String languageName, String compilerSpecID)
		throws Exception {
			super("TestProgram", languageName, compilerSpecID, null);
			setupProgram();
	}

	protected abstract void setupMemory();
	
	private void setupProgram() {
		setupMemory();
		Program program = getProgram();
		typeMap = getTypeInfoMap();
		nameMap = getTypeNameMap();
		vtableMap = getVtableMap();
		vttMap = getVttMap();
		functionOffsets = getFunctionOffsets();
		Map<Long, String> relocationMap = getRelocationMap();
		try {
			for (Long offset : typeMap.keySet()) {
				setBytes(addr(offset).toString(), typeMap.get(offset));
			}
			for (Long offset : nameMap.keySet()) {
				createString(addr(offset).toString(), nameMap.get(offset));
			}
			for (Long offset : vtableMap.keySet()) {
				setBytes(addr(offset).toString(), vtableMap.get(offset));
			}
			for (Long offset : vttMap.keySet()) {
				setBytes(addr(offset).toString(), vttMap.get(offset));
			}
			MemoryBlock codeBlock = program.getMemory().getBlock(addr(functionOffsets[0]));
			if (!codeBlock.isExecute()) {
				setExecute(codeBlock, true);
			}
			for (Long offset : functionOffsets) {
				try {
					setBytes(addr(offset).toString(), getReturnInstruction(), true);
				} catch (Exception e) {}
			}
			if (GccUtils.hasFunctionDescriptors(program)) {
				MemoryBlock block = program.getMemory().getBlock(".opd");
				setBytes(block.getStart().toString(), getFunctionDescriptors());
			}
		} catch (Exception e) {
			Msg.error(this, e);
			return;
		}
		RelocationTable table = program.getRelocationTable();
		for (Long offset : relocationMap.keySet()) {
			table.add(addr(offset), 1, null, null, relocationMap.get(offset));
		}
	}

	protected abstract Map<Long, String> getTypeInfoMap();
	protected abstract Map<Long, String> getTypeNameMap();
	protected abstract Map<Long, String> getVtableMap();
	protected abstract Map<Long, String> getVttMap();
	protected abstract Map<Long, String> getRelocationMap();
	protected abstract Long[] getFunctionOffsets();
	protected abstract String getReturnInstruction();
	protected abstract String getFunctionDescriptors();

	public List<TypeInfo> getTypeInfoList() {
		List<TypeInfo> list = new ArrayList<>(typeMap.size());
		Program program = getProgram();
		typeMap.keySet().forEach((a) -> list.add(getTypeInfo(program, addr(a))));
		return list;
	}

	public List<VtableModel> getVtableList() {
		List<VtableModel> list = new ArrayList<>(vtableMap.size());
		Program program = getProgram();
		for (Long offset : vtableMap.keySet()) {
			ClassTypeInfo type = VtableUtils.getTypeInfo(program, addr(offset));
			list.add(new VtableModel(program, addr(offset), type));
		}
		return list;
	}

	public List<VttModel> getVttList() {
		List<VttModel> list = new ArrayList<>(vttMap.size());
		Program program = getProgram();
		vttMap.keySet().forEach((a) -> list.add(new VttModel(program, addr(a))));
		return list;
	}

	protected static Entry<Long, String> getEntry(Long offset, String bytes) {
		return new AbstractMap.SimpleImmutableEntry<>(offset, bytes);
	}
	
	private void createString(String address, String string) throws Exception {
		createString(address, string, StandardCharsets.US_ASCII,
				true, StringDataType.dataType);
	}

}