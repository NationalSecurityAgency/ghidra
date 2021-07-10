package ghidra.app.util.bin.format.stabs;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.RedBlackEntry;
import ghidra.util.datastruct.RedBlackTree;

/**
 * A Container representing a file which holds all StabDescriptors
 * which may have been declared in the file.
 */
public class StabsFile {

	private static final Pattern INCLUDE_PATTERN =
		Pattern.compile("(?<=(?:(?:include/)|(?:sys\\-include/)))(.*)");
	private static final String BUILTIN_NAME = "__builtin__";
	private static final int BUILTIN_FILE_NUMBER = 0;
	private static final CategoryPath STABS_ROOT = new CategoryPath(CategoryPath.ROOT, "stabs");

	private final long fileNumber;
	private final String fileName;
	private final String fullPath;
	private final StabsParser parser;
	private final CategoryPath path;
	private final RedBlackTree<Long, StabsTypeDescriptor> types = new RedBlackTree<>();
	private final Set<StabsFunctionSymbolDescriptor> functions = new HashSet<>();
	private final Set<StabsClassSymbolDescriptor> classes = new HashSet<>();

	StabsFile(StabsParser parser) {
		this.fileName = BUILTIN_NAME;
		this.fullPath = fileName;
		this.parser = parser;
		this.path = CategoryPath.ROOT;
		this.fileNumber = 0;
	}

	StabsFile(String fileName, StabsParser parser, int fileNumber) {
		this.fullPath = fileName;
		Path path = Paths.get(fileName);
		path.normalize();
		String strPath = path.toString().replaceAll("\\\\", "/").replaceAll("../", "");
		Matcher matcher = INCLUDE_PATTERN.matcher(fileName);
		matcher.reset(strPath);
		if (matcher.find()) {
			strPath = matcher.group(1);
		}
		this.fileName = strPath;
		this.parser = parser;
		this.fileNumber = fileNumber;
		this.path = new CategoryPath(STABS_ROOT, strPath);
	}

	// this shouldn't be public. Not sure how to protect this though.
	public void addType(StabsTypeDescriptor type, StabsTypeNumber typeNumber) {
		if (isThisFile(typeNumber)) {
			if (!typeNumber.hasFileNumber()) {
				StabsFile file = parser.getFile(BUILTIN_FILE_NUMBER);
				file.types.put(typeNumber.typeNumber, type);
			}
			// add to ourselves too so we know where it was defined
			types.put(typeNumber.typeNumber, type);
		} else {
			StabsFile file = parser.getFile(typeNumber.fileNumber);
			file.types.put(typeNumber.typeNumber, type);
		}
	}

	private boolean isThisFile(StabsTypeNumber typeNumber) {
		return typeNumber.fileNumber == fileNumber || !typeNumber.hasFileNumber();
	}

	/**
	 * Returns true if this file or an included file defines the type
	 * @param typeNumber the type number of the type to check for
	 * @return true if the type has been defined
	 */
	public boolean containsType(StabsTypeNumber typeNumber) {
		if (isThisFile(typeNumber)) {
			return types.containsKey(typeNumber.typeNumber);
		}
		StabsFile otherFile = parser.getFile(typeNumber.fileNumber);
		return otherFile.containsType(typeNumber);
	}

	/**
	 * Gets the type descriptor for the provided type number
	 * @param typeNumber the types type number
	 * @return the type descriptor
	 */
	public StabsTypeDescriptor getType(StabsTypeNumber typeNumber) {
		if (isThisFile(typeNumber)) {
			if (!typeNumber.hasFileNumber()) {
				StabsFile file = parser.getFile(BUILTIN_FILE_NUMBER);
				return file.types.getOrCreateEntry(typeNumber.typeNumber).getValue();
			}
			return types.getOrCreateEntry(typeNumber.typeNumber).getValue();
		}
		return parser.getType(typeNumber);
	}

	/**
	 * Gets the program
	 * @return the program
	 */
	public Program getProgram() {
		return parser.getProgram();
	}

	/**
	 * Gets the CategoryPath
	 * @return the category path
	 */
	public CategoryPath getCategoryPath() {
		return path;
	}

	/**
	 * Gets the file name
	 * @return the file name
	 */
	public String getFileName() {
		return fileName;
	}

	/**
	 * Gets the type descriptor which has the typenumber in this file
	 * @param typeNumber the type descriptors type number
	 * @return the type descriptor
	 */
	public StabsTypeDescriptor getType(long typeNumber) {
		RedBlackEntry<Long, StabsTypeDescriptor> entry = types.getOrCreateEntry(typeNumber);
		return entry.getValue();
	}

	/**
	 * Gets a set of all function descriptors
	 * @return the set of function descriptors
	 */
	public Set<StabsFunctionSymbolDescriptor> getFunctions() {
		return Collections.unmodifiableSet(functions);
	}

	/**
	 * Gets a set of all the class descriptors defined in this file
	 * @return the set of class descriptors
	 */
	public Set<StabsClassSymbolDescriptor> getClasses() {
		return Collections.unmodifiableSet(classes);
	}

	boolean addFunction(StabsSymbolDescriptor symbol) {
		if (symbol instanceof StabsFunctionSymbolDescriptor) {
			return functions.add((StabsFunctionSymbolDescriptor) symbol);
		}
		return false;
	}

	boolean addClass(StabsSymbolDescriptor symbol) {
		if (symbol instanceof StabsClassSymbolDescriptor) {
			return classes.add((StabsClassSymbolDescriptor) symbol);
		}
		return false;
	}

	/**
	 * Gets a stream of all type descriptors defined in this file
	 * @return the stream of type descriptors
	 */
	public Stream<StabsTypeDescriptor> getTypeDescriptors() {
		return StreamSupport.stream(types.spliterator(), false)
							.map(RedBlackEntry::getValue);
	}

	/**
	 * @return the fileNumber
	 */
	public long getFileNumber() {
		return fileNumber;
	}

	/**
	 * @return the fullPath
	 */
	public String getFilePath() {
		return fullPath;
	}

	public DataType getDefaultFunction(DataType returnType) {
		return parser.getDefaultFunction(returnType);
	}
}
