package ghidra.app.cmd.data.rtti.gcc;

import java.util.*;

import ghidra.program.model.data.DataType;
import ghidra.app.util.demangler.DemangledDataType;
import ghidra.app.util.demangler.DemangledFunction;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.Tool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.DummyCancellableTaskMonitor;
import ghidra.util.task.TaskMonitor;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;
import static ghidra.app.util.demangler.DemanglerUtil.demangle;
import static ghidra.plugins.fsbrowser.FSBUtils.getProgramManager;
import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;

public final class GccUtils {

	private static final String PTRDIFF = "ptrdiff_t";
	private static final String PPC = "PowerPC";
	private static final String CXXABI = "__cxxabiv1";
	private static final String EXTERNAL = "<EXTERNAL>";
	private static final String DATA = "data";

	public static final Set<String> COMPILER_NAMES = Set.of("gcc", "default");
	public static final String PURE_VIRTUAL_FUNCTION_NAME = "__cxa_pure_virtual";
	public static final int UNSUPPORTED_RELOCATION = 5;

	private static final CategoryPath CXXABI_PATH = new CategoryPath(CategoryPath.ROOT, CXXABI);

	private GccUtils() {
	}

	/**
	 * Gets the __cxxabiv1 CategoryPath.
	 * 
	 * @return the __cxxabiv1 CategoryPath.
	 */
	public static CategoryPath getCxxAbiCategoryPath() {
		return CXXABI_PATH;
	}

	/**
	 * Checks if GCC LLP64 preprocessor definition was defined.
	 * 
	 * @param dtm the programs datatype manager.
	 * @return true if LLP64 was defined
	 */
	public static boolean isLLP64(DataTypeManager dtm) {
		return dtm.getDataOrganization().getPointerSize() == 8;
	}

	private static DataType getPointerSizedInteger(DataTypeManager dtm) {
		DataOrganization org = dtm.getDataOrganization();
		String dtName = org.getIntegerCTypeApproximation(org.getPointerSize(), true);

		DemangledDataType dt = new DemangledDataType(dtName);
		return dt.getDataType(null);
	}

	private static DataType createPtrDiff(DataTypeManager dtm) {
		DataType dataType = getPointerSizedInteger(dtm);
		return new TypedefDataType(CategoryPath.ROOT, PTRDIFF, dataType, dtm);
	}

	/**
	 * Gets the appropriate TypeDefDataType for the builtin __PTRDIFF_TYPE__
	 * 
	 * @param dtm the programs datatype manager.
	 * @return the appropriate TypeDefDataType for the builtin __PTRDIFF_TYPE__
	 */
	public static DataType getPtrDiff_t(DataTypeManager dtm) {
		DataType ptrdiff_t = createPtrDiff(dtm);
		if (dtm.contains(ptrdiff_t)) {
			return dtm.resolve(ptrdiff_t, KEEP_HANDLER);
		}
		return ptrdiff_t;
	}

	/**
	 * Gets the size in bytes of __PTRDIFF_TYPE__
	 * 
	 * @param dtm the programs datatype manager.
	 * @return the size in bytes of __PTRDIFF_TYPE__
	 */
	public static int getPtrDiffSize(DataTypeManager dtm) {
		return getPtrDiff_t(dtm).getLength();
	}

	/**
	 * Gets all MemoryBlocks in a Program which hold non-volatile data
	 * and whose name contains "data".
	 * 
	 * @param program the program to be searched.
	 * @return A list of all memory blocks whose name contains "data" with non-volatile data.
	 */
	public static List<MemoryBlock> getAllDataBlocks(Program program) {
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		List<MemoryBlock> dataBlocks = new ArrayList<MemoryBlock>();
		for (MemoryBlock block : blocks) {
			if (isDataBlock(block) && block.getName().contains(DATA)) {
				if (!block.isVolatile()) {
					dataBlocks.add(block);
				}
			}
		}
		return dataBlocks;
	}

	/**
	 * Returns true if this MemoryBlock has non-volatile data.
	 * 
	 * @param block
	 * @return true if this MemoryBlock has non-volatile data.
	 */
	public static boolean isDataBlock(MemoryBlock block) {
		return block != null ? block.isRead() || block.isWrite() : false;
	}

	/**
	 * Checks if a program's language is PowerPC64.
	 * 
	 * @param program
	 * @return true if the program's language is PowerPC64.
	 */
	public static boolean hasFunctionDescriptors(Program program) {
		Processor processor = program.getLanguage().getProcessor();
		if (!processor.toString().contentEquals(PPC)) {
			return false;
		} return isLLP64(program.getDataTypeManager());
	}

	/**
	 * Checks if the program's compiler was a GCC variant.
	 * 
	 * @param program
	 * @return true if the program's compiler was a GCC variant.
	 */
	public static boolean isGnuCompiler(Program program) {
		String id = program.getCompilerSpec().getCompilerSpecID().getIdAsString().toLowerCase();
		return COMPILER_NAMES.contains(id);
	}

	/**
	 * Checks if a function pointer is located at the specified address.
	 * 
	 * @param program
	 * @param address
	 * @return true if a function pointer is located at the specified address.
	 */
	public static boolean isFunctionPointer(Program program, Address address) {
		RelocationTable table = program.getRelocationTable();
		if (table.isRelocatable()) {
			Relocation reloc = table.getRelocation(address);
			if (reloc != null) {
				String name = reloc.getSymbolName();
				if (name != null) {
					if (name.equals(PURE_VIRTUAL_FUNCTION_NAME)) {
						return true;
					}
					DemangledObject demangled = demangle(name);
					if (demangled != null && demangled instanceof DemangledFunction) {
						return true;
					}
				}
			}
		}
		Address pointee = getAbsoluteAddress(program, address);
		if (pointee == null) {
			return false;
		}
		if (hasFunctionDescriptors(program)) {
			// the PowerPC Elf64 ABI has Function Descriptors :/
			pointee = getAbsoluteAddress(program, pointee);
			if (pointee == null) {
				return false;
			}
		}
		MemoryBlock block = program.getMemory().getBlock(pointee);
		return block != null ? block.isExecute() : false;
	}

	/**
	 * Checks if a null pointer is located at the specified address.
	 * 
	 * @param program
	 * @param address
	 * @return true if a null pointer is located at the specified address.
	 */
	public static boolean isNullPointer(Program program, Address address) {
		return isNullPointer(new MemoryBufferImpl(program.getMemory(), address));
	}

	/**
	 * Checks if a null pointer is located at the specified address.
	 * 
	 * @param buf
	 * @return true if a null pointer is located at the specified address.
	 */
	public static boolean isNullPointer(MemBuffer buf) {
		try {
			return buf.getBigInteger(
				0, buf.getMemory().getProgram().getDefaultPointerSize(), false).longValue() == 0;
		} catch (MemoryAccessException e) {
			return false;
		}  
	}

	/**
	 * Checks if a valid pointer is located at the specified address.
	 * 
	 * @param program
	 * @param address
	 * @return true if a valid pointer is located at the specified address.
	 */
	public static boolean isValidPointer(Program program, Address address) {
		Address pointee = getAbsoluteAddress(program, address);
		if (pointee != null) {
			return program.getMemory().getLoadedAndInitializedAddressSet().contains(pointee);
		} return false;
	}

	/**
	 * Checks if a valid pointer is located at the specified address.
	 * 
	 * @param buf
	 * @return true if a valid pointer is located at the specified address.
	 */
	public static boolean isValidPointer(MemBuffer buf) {
		return buf != null ?
			isValidPointer(buf.getMemory().getProgram(), buf.getAddress()) : false;
	}

	/**
	 * Gets all direct data references to the specified address.
	 * 
	 * @param program
	 * @param address
	 * @return a set of all direct data references to the specified address.
	 */
	public static Set<Address> getDirectDataReferences(Program program, Address address) {
		try {
			return getDirectDataReferences(program, address, new DummyCancellableTaskMonitor());
		} catch (CancelledException e) {
			return null;
		}
	}

	/**
	 * Gets all direct data references to the specified address.
	 * 
	 * @param program
	 * @param dataAddress
	 * @param monitor
	 * @return a set of all direct data references to the specified address.
	 * @throws CancelledException
	 */
	public static Set<Address> getDirectDataReferences(Program program, Address dataAddress,
		TaskMonitor monitor) throws CancelledException {
			if (dataAddress == null)
				return Collections.emptySet();
			List<MemoryBlock> dataBlocks = getAllDataBlocks(program);
			int pointerAlignment =
				program.getDataTypeManager().getDataOrganization().getDefaultPointerAlignment();
			return ProgramMemoryUtil.findDirectReferences(program, dataBlocks,
				pointerAlignment, dataAddress, monitor);
	}

	/**
	 * Attempts to get the Program containing the data for the relocation.
	 * 
	 * @param program the program containing the relocation
	 * @param reloc the relocation
	 * @return the program containing the relocation or null if unresolved.
	 */
	public static Program getExternalProgram(Program program, Relocation reloc) {
		ExternalManager manager = program.getExternalManager();
		SymbolTable table = program.getSymbolTable();
		for (Symbol symbol : table.getSymbols(reloc.getSymbolName())) {
			for (String path : symbol.getPath()) {
				Library library = manager.getExternalLibrary(path);
				if (library != null) {
					return openProgram(library.getAssociatedProgramPath());
				}
			}
		}
		// If still not found, brute force it
		for (String name : manager.getExternalLibraryNames()) {
			if (name.equals(EXTERNAL)) {
				continue;
			}
			String path = manager.getExternalLibraryPath(name);
			if (path == null) {
				continue;
			}
			Program exProgram = openProgram(path);
			Namespace global = exProgram.getGlobalNamespace();
			if (exProgram != null) {
				SymbolTable exTable = exProgram.getSymbolTable();
				if (!exTable.getSymbols(reloc.getSymbolName(), global).isEmpty()) {
					return exProgram;
				}
			}
		}
		return null;
	}

	private static Program openProgram(String path) {
		Project project = AppInfo.getActiveProject();
		DomainFile file = project.getProjectData().getFile(path);
		Tool[] tools = project.getToolManager().getRunningTools();
		for (Tool tool : tools) {
			if (tool instanceof PluginTool) {
				return getProgramManager((PluginTool) tool, false).openProgram(file);
			}
		}
		return null;
	}

}
