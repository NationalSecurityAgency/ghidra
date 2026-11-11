package ghidra.app.util.bin.format.stabs;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A not so simplistic parser for the STABS debug format
 */
public class StabsParser {

	/** The root CategoryPath for types parsed by the StabsParser */
	public final static CategoryPath STABS_PATH = new CategoryPath(CategoryPath.ROOT, "stabs");
	private final static CategoryPath FUN_PATH = new CategoryPath(STABS_PATH, "functions");

	// name can be blank. rarely occurs though
	public static final Pattern NAME_PATTERN = Pattern.compile("^(.*?)(?=(?:(?<!:):(?!:))):");
	private static final Pattern STAB_PATTERN = Pattern.compile(NAME_PATTERN.pattern()+"(.*)");
	private static final Pattern FILE_PATTERN = Pattern.compile("(.*\\.\\w+)/?$");

	private StabsFile currentFile;
	private final Program program;
	private final List<StabsFile> files;
	private final Map<DataType, DataType> defaultFunctions = new HashMap<>();

	/**
	 * Constructs a new StabssParser
	 * @param program the program
	 */
	public StabsParser(Program program) {
		this(program, -1);
	}

	/**
	 * Constructs a new Stabs Parser
	 * @param program the program with stab debug information
	 * @param numFiles the number of files which comprises the program if known.
	 */
	public StabsParser(Program program, int numFiles) {
		this.program = program;
		if (numFiles > 0) {
			files = new ArrayList<>(numFiles);
		} else {
			files = new LinkedList<>();
		}
		// file number 0 is for builtins
		currentFile = new StabsFile(this);
		files.add(currentFile);
	}

	/**
	 * Parses the list of STABS strings
	 * @param stabs the STABS strings
	 * @return the number of successfully parsed strings
	 * @throws CancelledException if the operation is cancelled
	 * @throws StabsParseException if an invalid stab is encountered
	 */
	public int parse(List<String> stabs) throws CancelledException, StabsParseException {
		return parse(stabs, TaskMonitor.DUMMY);
	}

	/**
	 * Parses the list of STABS strings into a StabsFile with the provided fileName
	 * @param stabs the STABS strings
	 * @param fileName the filename
	 * @param monitor the task monitor
	 * @return the StabsFile
	 * @throws CancelledException if the operation is cancelled
	 * @throws StabsParseException if an invalid stab is encountered
	 */
	public StabsFile parseFile(List<String> stabs, String fileName, TaskMonitor monitor)
			throws CancelledException, StabsParseException {
		currentFile = new StabsFile(fileName, this, (int) currentFile.getFileNumber()+1);
		if (parse(stabs, monitor) > 0) {
			return currentFile;
		}
		return null;
	}

	public int parse(List<String> stabs, TaskMonitor monitor)
		throws CancelledException, StabsParseException {
			monitor.initialize(stabs.size());
			monitor.setMessage("Parsing Stabs");
			int parsed = 0;
			for (;parsed < stabs.size(); parsed++) {
				// stab all the stabs!
				// but stop stabbing when requested
				monitor.checkCanceled();
				String stab = stabs.get(parsed);
				Matcher matcher = FILE_PATTERN.matcher(stab);
				if (matcher.lookingAt()) {
					// they are conviently in order
					if (!currentFile.getFilePath().equals(stab)) {
						currentFile = new StabsFile(stab, this, files.size());
						files.add(currentFile);
					}
					monitor.incrementProgress(1);
					continue;
				}
				matcher.usePattern(STAB_PATTERN);
				if (matcher.matches()) {
					long fileIndex = StabsTypeNumber.getFileNumber(matcher.group(2));
					StabsFile file = fileIndex != -1 ?
					files.get((int) fileIndex) : currentFile;
					StabsSymbolDescriptorType type =
						StabsSymbolDescriptorType.getSymbolType(stab);
					/*
					 * all StabTypeDescriptor constructors have the side effect of
					 * adding themselves to the file. It was the only way I could
					 * think of to ensure the type was declared before ever being
					 * referenced.
					 */
					switch (type) {
						case FUNCTION:
							/*
							 * must pass current file for a function because
							 * the type number is the return type
							 */
							List<String> subStabs = stabs.subList(parsed, stabs.size());
							int count = parseFunction(subStabs, currentFile);
							parsed += count;
							break;
						case PARAMETER:
							Msg.error(this, "Parser encountered parameter token");
							// create anyway incase it defines a type
							new StabsParameterSymbolDescriptor(stab, file);
							break;
						case COMPOSITE:
							new StabsCompositeSymbolDescriptor(stab, file);
							break;
						case CLASS:
							file.addClass(new StabsClassSymbolDescriptor(stab, file));
							break;
						case TYPEDEF:
							new StabsTypeDefSymbolDescriptor(stab, file);
							break;
						case VARIABLE:
							new StabsVariableSymbolDescriptor(stab, file);
						case CONSTANT:
						case EXCEPTION:
						case NONE:
							// afaik there is nothing to parse here
							break;
					}
				}
				monitor.setProgress(parsed);
			}
			return parsed;
		}

	static String getNameFromStab(String stab) {
		Matcher matcher = STAB_PATTERN.matcher(stab);
		if (matcher.matches()) {
			return matcher.group(1);
		}
		return "";
	}

	private int parseFunction(List<String> subList, StabsFile file) throws StabsParseException {
		StabsFunctionSymbolDescriptor symbol = new StabsFunctionSymbolDescriptor(subList, file);
		file.addFunction(symbol);
		return symbol.getTokenCount();
	}

	StabsFile getFile(long fileNumber) {
		return files.get((int) fileNumber);
	}

	/**
	 * Gets the stab token for a stab string which has previously been parsed.
	 *
	 * @param stab the parsed stab string
	 * @return the stab token or null if not parsed/invalid.
	 * @see #parse(List, TaskMonitor)
	 */
	public StabsTypeDescriptor getType(String stab) {
		StabsTypeNumber type = new StabsTypeNumber(stab);
		return getType(type);
	}

	public StabsTypeDescriptor getType(long fileNum, long typeNum) {
		StabsTypeNumber type = new StabsTypeNumber(fileNum, typeNum);
		return getType(type);
	}

	StabsTypeDescriptor getType(StabsTypeNumber type) {
		StabsFile file = files.get(type.fileNumber.intValue());
		return file.getType(type);
	}

	/**
	 * @return the program
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Gets a stream of all parsed function descriptors
	 * @return the stream of function descriptors
	 */
	public Stream<StabsFunctionSymbolDescriptor> getFunctions() {
		return files.stream()
					.map(StabsFile::getFunctions)
					.flatMap(Set::stream);
	}

	/**
	 * Gets a stream of all parsed class descriptors
	 * @return the stream of class descriptors
	 */
	public Stream<StabsClassSymbolDescriptor> getClasses() {
		return files.stream()
					.map(StabsFile::getClasses)
					.flatMap(Set::stream);
	}

	/**
	 * Gets a stream of all parsed type descriptors
	 * @return the stream of type descriptors
	 */
	public Stream<StabsTypeDescriptor> getTypes() {
		return files.stream()
					.flatMap(StabsFile::getTypeDescriptors);
	}

	// internal use. this is only used when the parameters and name are unknown
	public DataType getDefaultFunction(DataType returnType) {
		if (defaultFunctions.containsKey(returnType)) {
			return defaultFunctions.get(returnType);
		}
		DataTypeManager dtm = program.getDataTypeManager();
		FunctionDefinition def = new FunctionDefinitionDataType(
			FUN_PATH, String.format("FunDef_%d", defaultFunctions.size()), dtm);
		def.setReturnType(returnType);
		DataType result = dtm.resolve(def, DataTypeConflictHandler.KEEP_HANDLER);
		defaultFunctions.put(returnType, result);
		return result;
	}
}
