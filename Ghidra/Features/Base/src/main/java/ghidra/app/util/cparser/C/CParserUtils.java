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
package ghidra.app.util.cparser.C;

import java.io.*;
import java.util.Arrays;

import javax.help.UnsupportedOperationException;

import generic.theme.GThemeDefaults.Colors;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.cparser.CPP.PreProcessor;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.store.LockException;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class CParserUtils {
	
	private CParserUtils() {
		// utils class
	}
	
	public record CParseResults(PreProcessor preProcessor, String cppParseMessages, String cParseMessages, boolean successful) {
		public String getFormattedParseMessage(String errMsg) {
			String message = "";

			if (errMsg != null) {
				message += errMsg + "\n\n";
			}

			String msg = cppParseMessages;
			if (msg != null && msg.length() != 0) {
				message += "CParser Messages:\n" + msg + "\n\n";
			}

			msg = cppParseMessages;
			if (msg != null && msg.length() != 0) {
				message += "PreProcessor Messages:\n" + msg;
			}

			return message;
		}		
	}

	/**
	 * Parse the given function signature text.  Any exceptions will be handled herein
	 * by showing an error dialog (null is returned in that case).
	 * 
	 * @param serviceProvider the service provider used to access DataTypeManagers
	 * @param program the program against which data types will be resolved
	 * @param signatureText the signature to parse
	 * @return the data type that is created as a result of parsing; null if there was a problem
	 * 
	 * @see #parseSignature(DataTypeManagerService, Program, String)
	 * @see #parseSignature(DataTypeManagerService, Program, String, boolean)
	 */
	public static FunctionDefinitionDataType parseSignature(ServiceProvider serviceProvider,
			Program program, String signatureText) {
		DataTypeManagerService service = serviceProvider.getService(DataTypeManagerService.class);
		return parseSignature(service, program, signatureText);
	}

	/**
	 * Parse the given function signature text.  Any exceptions will be handled herein
	 * by showing an error dialog (null is returned in that case).
	 * 
	 * @param service the service used to access DataTypeManagers or null to use only the program's
	 * data type manager.
	 * @param program the program against which data types will be resolved
	 * @param signatureText the signature to parse
	 * @return the data type that is created as a result of parsing; null if there was a problem
	 * 
	 * @see #parseSignature(DataTypeManagerService, Program, String, boolean)
	 */
	public static FunctionDefinitionDataType parseSignature(DataTypeManagerService service,
			Program program, String signatureText) {
		try {
			return parseSignature(service, program, signatureText, true);
		}
		catch (ParseException e) {
			// Can't happen, as we are passing 'true' above.  Just in case this changes, 
			// log the exception
			Msg.debug(CParserUtils.class,
				"Logging an exception that cannot happen (the code must have changed)", e);
			return null;
		}
	}

	/**
	 * Split function signature into three parts:
	 * [0]= part before function name
	 * [1]= function name
	 * [2]= parameter body after function name
	 * @param signature function signature string to split
	 * @return parts array or null if split failed
	 */
	private static String[] splitFunctionSignature(String signature) {

		int index = signature.lastIndexOf(')');
		if (index < 0) {
			return null;
		}
		int closureCount = 1;
		while (--index > 0) {
			char c = signature.charAt(index);
			if (c == ' ') {
				// ignore
			}
			else if (c == ')') {
				++closureCount;
			}
			else if (c == '(') {
				--closureCount;
			}
			else if (closureCount <= 0) {
				break;
			}
		}

		if (closureCount != 0) {
			return null;
		}

		String[] parts = new String[3];
		parts[2] = signature.substring(index + 1);

		signature = signature.substring(0, index + 1);

		int spaceIndex = signature.lastIndexOf(' ');
		if (spaceIndex <= 0) {
			return null;
		}

		parts[1] = signature.substring(spaceIndex + 1);
		parts[0] = signature.substring(0, spaceIndex);

		return parts;
	}

	/**
	 * Get a temporary name of a specified length (tttt....)
	 * @param length of temporary string
	 * @return temporary name string
	 */
	private static String getTempName(int length) {
		char[] nameChars = new char[length];
		Arrays.fill(nameChars, 't');
		return new String(nameChars);
	}

	/**
	 * Parse the given function signature text.  Any exceptions will be handled herein
	 * by showing an error dialog (null is returned in that case).
	 * 
	 * @param service the service used to access DataTypeManagers or null to use only the program's
	 * data type manager.
	 * @param program the program against which data types will be resolved
	 * @param signatureText the signature to parse
	 * @param handleExceptions true signals that this method should deal with exceptions, 
	 *        showing error messages as necessary; false signals to throw any encountered
	 *        parsing exceptions.  This allows clients to perform exception handling that
	 *        better matches their workflow.
	 * @return the data type that is created as a result of parsing; null if there was a problem
	 * @throws ParseException for catastrophic errors in C parsing
	 */
	public static FunctionDefinitionDataType parseSignature(DataTypeManagerService service,
			Program program, String signatureText, boolean handleExceptions) throws ParseException {

		DataTypeManager[] dataTypeManagers = service != null ? getDataTypeManagers(service)
				: new DataTypeManager[] { program.getDataTypeManager() };

		CParser parser = new CParser(program.getDataTypeManager(), false, dataTypeManagers);

		String[] signatureParts = splitFunctionSignature(signatureText);
		if (signatureParts == null) {
			Msg.debug(CParserUtils.class,
				"Invalid signature: unable to isolate function name : " + signatureText);
			return null;
		}

		String replacedText =
			signatureParts[0] + " " + getTempName(signatureParts[1].length()) + signatureParts[2];

		DataType dt = null;
		try {
			// parse the signature
			parser.setParseFileName("input line");
			dt = parser.parse(replacedText + ";");

			if (!(dt instanceof FunctionDefinitionDataType)) {
				return null;
			}

			// put back the old signature name
			dt.setName(signatureParts[1]);

			return (FunctionDefinitionDataType) dt;
		}
		catch (InvalidNameException | DuplicateNameException e) {
			// can't happen since we are calling setName() with the value that was 
			// previously set (this can change in the future if we ever modify the 
			// name before we restore it) 
			Msg.debug(CParserUtils.class,
				"Logging an exception that cannot happen (the code must have changed)", e);
		}
		catch (Throwable t) {
			if (!handleExceptions) {
				throw t;
			}

			String msg = handleParseProblem(t, signatureText);
			if (msg != null) {
				Msg.showError(CParserUtils.class, null, "Invalid Function Signature", msg);
			}
			else {
				Msg.debug(CParserUtils.class, "Error parsing signature: " + signatureText, t);
			}

		}

		return null;
	}

	/**
	 * Parse a set of C Header files and associated parsing arguments, returning a new File Data TypeManager
	 * with in the provided dataFileName.
	 * 
	 * Note: Using another open archive while parsing will cause:
	 * - a dependence on the other archive
	 * - any missing data types while parsing are supplied if present from an openDTMgr
	 * - after parsing all data types parsed with an equivalent data type in any openDTMgr
	 *     replaced by the data type from the openDTMgr
	 *     
	 * NOTE: This will only occur if the data type from the openDTMgr's is equivalent.
	 * 
	 * @param openDTMgrs array of datatypes managers to use for undefined data types
	 * 
	 * @param filenames names of files in order to parse, could include strings with
	 *        "#" at start, which are ignored as comments
	 * @param args arguments for parsing, "-D<defn>=", "-I<includepath>"
	 * 
	 * @param dataFileName name of data type archive file (include the .gdt extension)
	 * 
	 * @param monitor  used to cancel or provide results
	 * 
	 * @return the data types in the ghidra .gdt archive file
	 * 
	 * @throws ghidra.app.util.cparser.C.ParseException for catastrophic errors in C parsing
	 * @throws ghidra.app.util.cparser.CPP.ParseException for catastrophic errors in Preprocessor macro parsing
	 * @throws IOException    if there io are errors saving the archive
	 *
	 */
	
	public static FileDataTypeManager parseHeaderFiles(DataTypeManager openDTMgrs[], String[] filenames, String args[], String dataFileName,
			TaskMonitor monitor) throws ghidra.app.util.cparser.C.ParseException,
			ghidra.app.util.cparser.CPP.ParseException, IOException {
		
		return parseHeaderFiles(openDTMgrs, filenames, null, args, dataFileName, monitor);
	}
	
	/**
	 * Parse a set of C Header files and associated parsing arguments, returning a new File Data TypeManager
	 * with in the provided dataFileName.
	 * 
	 * Note: Using another open archive while parsing will cause:
	 * - a dependence on the other archive
	 * - any missing data types while parsing are supplied if present from an openDTMgr
	 * - after parsing all data types parsed with an equivalent data type in any openDTMgr
	 *     replaced by the data type from the openDTMgr
	 *     
	 * NOTE: This will only occur if the data type from the openDTMgr's is equivalent.
	 * 
	 * @param openDTMgrs array of datatypes managers to use for undefined data types
	 * 
	 * @param filenames names of files in order to parse, could include strings with
	 *        "#" at start, which are ignored as comments
	 * @param includePaths paths to include files, instead of using "-I<includepath>" in args
	 * @param args arguments for parsing, "-D<defn>=", ( "-I<includepath>" use includePaths parm instead)
	 * 
	 * @param dataFileName name of data type archive file (include the .gdt extension)
	 * 
	 * @param monitor  used to cancel or provide results
	 * 
	 * @return the data types in the ghidra .gdt archive file
	 * 
	 * @throws ghidra.app.util.cparser.C.ParseException for catastrophic errors in C parsing
	 * @throws ghidra.app.util.cparser.CPP.ParseException for catastrophic errors in Preprocessor macro parsing
	 * @throws IOException    if there io are errors saving the archive
	 *
	 */
	
	public static FileDataTypeManager parseHeaderFiles(DataTypeManager openDTMgrs[], String[] filenames, String includePaths[], String args[], String dataFileName,
			TaskMonitor monitor) throws ghidra.app.util.cparser.C.ParseException,
			ghidra.app.util.cparser.CPP.ParseException, IOException {
		
		return parseHeaderFiles(openDTMgrs, filenames, includePaths, args, dataFileName, null, null, monitor);
	}

	
	/**
	 * Parse a set of C Header files and associated parsing arguments, returning a new File Data TypeManager
	 * with in the provided dataFileName.
	 * 
	 * Note: Using another open archive while parsing will cause:
	 * - a dependence on the other archive
	 * - any missing data types while parsing are supplied if present from an openDTMgr
	 * - after parsing all data types parsed with an equivalent data type in any openDTMgr
	 *     replaced by the data type from the openDTMgr
	 *     
	 * NOTE: This will only occur if the data type from the openDTMgr's is equivalent.
	 * 
	 * NOTE: Providing the correct languageID and compilerSpec is very important for header files that might use sizeof()
	 * 
	 * @param openDTMgrs array of datatypes managers to use for undefined data types
	 * 
	 * @param filenames names of files in order to parse, could include strings with
	 *        "#" at start, which are ignored as comments
	 * @param includePaths path to include files, could also be in args with "-I<includepath>"
	 * @param args arguments for parsing, "-D<defn>=", "-I<includepath>"
	 * 
	 * @param dataFileName name of data type archive file (include the .gdt extension)
	 * 
	 * @param languageId language identication to use for data type organization definitions (int, long, ptr size)
	 * @param compileSpecId compiler specification to use for parsing
	 * 
	 * @param monitor  used to cancel or provide results
	 * 
	 * @return the data types in the ghidra .gdt archive file
	 * 
	 * @throws ghidra.app.util.cparser.C.ParseException for catastrophic errors in C parsing
	 * @throws ghidra.app.util.cparser.CPP.ParseException for catastrophic errors in Preprocessor macro parsing
	 * @throws IOException    if there io are errors saving the archive
	 *
	 */
	public static FileDataTypeManager parseHeaderFiles(DataTypeManager openDTMgrs[], String[] filenames, String includePaths[], String args[], String dataFileName,
            String languageId, String compileSpecId, TaskMonitor monitor) throws ghidra.app.util.cparser.C.ParseException,
            ghidra.app.util.cparser.CPP.ParseException, IOException {

        File file = new File(dataFileName);
        FileDataTypeManager dtMgr = FileDataTypeManager.createFileArchive(file);
        
        CParseResults results;
        results = parseHeaderFiles(openDTMgrs, filenames, includePaths, args, dtMgr, languageId, compileSpecId, monitor);
        
        String messages = results.getFormattedParseMessage(null);
        Msg.info(CParserUtils.class, messages);
        
        dtMgr.save();
        
        return dtMgr;
    }

	
	/**
	 * Parse a set of C Header files and associated parsing arguments, data types are added to the provided
	 * DTMgr.
	 *
	 * Note: Using another open archive while parsing will cause:
	 * - a dependence on the other archive
	 * - any missing data types while parsing are supplied if present from an openDTMgr
	 * - after parsing all data types parsed with an equivalent data type in any openDTMgr
	 *     replaced by the data type from the openDTMgr
	 *     
	 * NOTE: This will only occur if the data type from the openDTMgr's is equivalent.
	 * 
	 * NOTE: Providing the correct languageID and compilerSpec is very important for header files that might use sizeof()
	 * @param openDTMgrs array of datatypes managers to use for undefined data types
	 * 
	 * @param filenames names of files in order to parse, could include strings with
	 *        "#" at start, which are ignored as comments
	 * @param args arguments for parsing, "-D<defn>=", ( "-I<includepath>" use includePaths parm instead)
	 * 
	 * @param existingDTMgr datatypes will be populated into this provided DTMgr, can pass Program or File DTMgr
	 * 
	 * @param languageId language identication to use for data type organization definitions (int, long, ptr size)
	 * @param compileSpecId compiler specification to use for parsing
	 * 
	 * @param monitor  used to cancel or provide results
	 * 
	 * @return a formatted string of any output from pre processor parsing or C parsing
	 * 
	 * @throws ghidra.app.util.cparser.C.ParseException for catastrophic errors in C parsing
	 * @throws ghidra.app.util.cparser.CPP.ParseException for catastrophic errors in Preprocessor macro parsing
	 * @throws IOException    if there io are errors saving the archive
	 *
	 */
	public static CParseResults parseHeaderFiles(DataTypeManager openDTMgrs[], String[] filenames, String args[], DataTypeManager existingDTMgr,
            String languageId, String compileSpecId, TaskMonitor monitor) throws ghidra.app.util.cparser.C.ParseException,
            ghidra.app.util.cparser.CPP.ParseException, IOException {
        
		return parseHeaderFiles(openDTMgrs, filenames, null, args, existingDTMgr, languageId, compileSpecId, monitor);
    }
	
	/**
	 * Parse a set of C Header files and associated parsing arguments, data types are added to the provided
	 * DTMgr.
	 *
	 * Note: Using another open archive while parsing will cause:
	 * - a dependence on the other archive
	 * - any missing data types while parsing are supplied if present from an openDTMgr
	 * - after parsing all data types parsed with an equivalent data type in any openDTMgr
	 *     replaced by the data type from the openDTMgr
	 *     
	 * NOTE: This will only occur if the data type from the openDTMgr's is equivalent.
	 * 
	 * NOTE: Providing the correct languageID and compilerSpec is very important for header files that might use sizeof()
	 * @param openDTMgrs array of datatypes managers to use for undefined data types
	 * 
	 * @param filenames names of files in order to parse, could include strings with
	 *        "#" at start, which are ignored as comments
	 * @param includePaths paths to include files, instead of using "-I<includepath>" in args
	 * @param args arguments for parsing, "-D<defn>=", ( "-I<includepath>" use includePaths parm instead)
	 * 
	 * @param existingDTMgr datatypes will be populated into this provided DTMgr, can pass Program or File DTMgr
	 * 
	 * @param languageId language identication to use for data type organization definitions (int, long, ptr size)
	 * @param compileSpecId compiler specification to use for parsing
	 * 
	 * @param monitor  used to cancel or provide results
	 * 
	 * @return a formatted string of any output from pre processor parsing or C parsing
	 * 
	 * @throws ghidra.app.util.cparser.C.ParseException for catastrophic errors in C parsing
	 * @throws ghidra.app.util.cparser.CPP.ParseException for catastrophic errors in Preprocessor macro parsing
	 * @throws IOException    if there io are errors saving the archive
	 *
	 */
	public static CParseResults parseHeaderFiles(DataTypeManager openDTMgrs[], String[] filenames, String includePaths[], String args[], DataTypeManager existingDTMgr,
            String languageId, String compileSpecId, TaskMonitor monitor) throws ghidra.app.util.cparser.C.ParseException,
            ghidra.app.util.cparser.CPP.ParseException, IOException {
        
        Language language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        CompilerSpec compilerSpec = language.getCompilerSpecByID(new CompilerSpecID(compileSpecId));

        if (existingDTMgr instanceof StandAloneDataTypeManager) {
        	try {
				((StandAloneDataTypeManager) existingDTMgr).setProgramArchitecture(language, compilerSpec.getCompilerSpecID(),
					StandAloneDataTypeManager.LanguageUpdateOption.UNCHANGED, monitor);
			}
			catch (CompilerSpecNotFoundException e) {
				e.printStackTrace();
			}
			catch (LanguageNotFoundException e) {
				e.printStackTrace();
			}
			catch (CancelledException e) {
				// ignore
			}
			catch (LockException e) {
				e.printStackTrace();
			}
			catch (UnsupportedOperationException e) {
				e.printStackTrace();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
			catch (IncompatibleLanguageException e) {
				// Shouldn't happen, unless already had a language
				e.printStackTrace();
			}
        }
        
        return parseHeaderFiles(openDTMgrs, filenames, includePaths, args, existingDTMgr, monitor);
    }
	
	/**
	 * Parse a set of C Header files and associated parsing arguments, data types are added to the provided
	 * DTMgr.
	 * 
	 * Note: Using another open archive while parsing will cause:
	 * - a dependence on the other archive
	 * - any missing data types while parsing are supplied if present from an openDTMgr
	 * - after parsing all data types parsed with an equivalent data type in any openDTMgr
	 *     replaced by the data type from the openDTMgr
	 *     
	 * NOTE: This will only occur if the data type from the openDTMgr's is equivalent.
	 * 
	 * NOTE: The DTMgr should have been created with the correct data type organization from a language/compilerspec
	 *       if there could be variants in datatype defintions when using the generic data type manager data organization
	 *       for example in a generic FileDataTypeManager int and long are size 4. This will change in the future,
	 *       but with the current implementation, beware!
	 * 
	 * @param openDTmanagers array of datatypes managers to use for undefined data types
	 * 
	 * @param filenames names of files in order to parse, could include strings with
	 *        "#" at start, which are ignored as comments
	 * @param includePaths paths to include files, instead of using "-I<includepath>" in args
	 * @param args arguments for parsing, "-D<defn>=", ( "-I<includepath>" use includePaths parm instead)
	 * 
	 * @param dtMgr datatypes will be populated into this provided DTMgr, can pass Program or File DTMgr
	 * 
	 * @param monitor  used to cancel or provide results
	 * 
	 * @return a formatted string of any output from pre processor parsing or C parsing
	 * 
	 * @throws ghidra.app.util.cparser.C.ParseException for catastrophic errors in C parsing
	 * @throws ghidra.app.util.cparser.CPP.ParseException for catastrophic errors in Preprocessor macro parsing	
	 */
	public static CParseResults parseHeaderFiles(DataTypeManager[] openDTmanagers, String[] filenames, String[] includePaths,
			String args[], DataTypeManager dtMgr, TaskMonitor monitor)
			throws ghidra.app.util.cparser.C.ParseException,
			ghidra.app.util.cparser.CPP.ParseException {

		String cppMessages = "";
		PreProcessor cpp = new PreProcessor();

		cpp.setArgs(args);
		cpp.addIncludePaths(includePaths);

		PrintStream os = System.out;
		
		String fName = dtMgr.getName();
		
		// make a path to tmpdir with name of data type manager
		String path = System.getProperty("java.io.tmpdir") + File.pathSeparator + fName;
		// if file data type manager, use path to .gdt file
		if (dtMgr instanceof FileDataTypeManager) {
			path = ((FileDataTypeManager) dtMgr).getPath();
		}
		path = path + "_CParser.out";
		
		try {
			os = new PrintStream(new FileOutputStream(path));
		} catch (FileNotFoundException e2) {
			Msg.error(CParserUtils.class, "Unexpected Exception: " + e2.getMessage(), e2);
		}
		// cpp.setOutputStream(os);
		PrintStream old = System.out;
		System.setOut(os);

		cpp.setMonitor(monitor);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		cpp.setOutputStream(bos);

		boolean parseSucceeded = false;
		try {
			for (String filename : filenames) {
				if (monitor.isCancelled()) {
					break;
				}
				if (filename.trim().startsWith("#")) {
					continue;
				}
				File file = new File(filename);
				// process each header file in the directory
				if (file.isDirectory()) {
					String[] children = file.list();
					if (children == null) {
						continue;
					}
					for (String element : children) {
						File child = new File(file.getAbsolutePath() + "/" + element);
						if (child.getName().endsWith(".h")) {
							parseFile(child.getAbsolutePath(), monitor, cpp);
						}
					}
				} else {
					parseFile(filename, monitor, cpp);
				}
			}
			parseSucceeded = true;
		} catch (Throwable e) {
			Msg.info(cpp, cpp.getParseMessages());
		} finally {
			System.out.println(bos);
			os.flush();
			os.close();
			System.setOut(old);
			
		}
		
		cppMessages = cpp.getParseMessages();
		if (!parseSucceeded) {
			return new CParseResults(cpp, "", cppMessages, false);
		}
		
		// process all the defines and add any that are integer values into
		// the Equates table
		cpp.getDefinitions().populateDefineEquates(openDTmanagers, dtMgr);

		String parserMessages = "";
		boolean cparseSucceeded = false;
		if (!monitor.isCancelled()) {
			monitor.setMessage("Parsing C");
			
			CParser cParser = new CParser(dtMgr, true, openDTmanagers);
			ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
			try {
				parserMessages = "";
				cParser.setParseFileName(fName);
				cParser.setMonitor(monitor);
				cParser.parse(bis);
				cparseSucceeded = cParser.didParseSucceed();
			} catch (RuntimeException re) {
				Msg.info(cpp, cpp.getParseMessages());
			} finally {
				parserMessages = cParser.getParseMessages();
			}
		}
		
		return new CParseResults(cpp, parserMessages, cppMessages, cparseSucceeded);
	}
	
	private static String parseFile(String filename, TaskMonitor monitor, PreProcessor cpp)
			throws ghidra.app.util.cparser.CPP.ParseException {
		monitor.setMessage("PreProcessing " + filename);
		try {
			Msg.info(CParserUtils.class, "parse " + filename);
			cpp.parse(filename);
		}
		catch (Throwable e) {
			Msg.error(CParserUtils.class, "Parsing file :" + filename);
			Msg.error(CParserUtils.class, "Unexpected Exception: " + e.getMessage(), e);

			throw new ghidra.app.util.cparser.CPP.ParseException(e.getMessage());
		}
		
		return cpp.getParseMessages();
	}
	
	private static DataTypeManager[] getDataTypeManagers(DataTypeManagerService service) {

		if (service == null) {
			return null;
		}

		DataTypeManager[] openDTmanagers = service.getDataTypeManagers();
		return openDTmanagers;
	}

	/**
	 * Given a throwable, attempt pull out the significant error parts to generate a 
	 * user-friendly error message.
	 * 
	 * @param t the throwable to examine, originating from the {@link CParser}.
	 * @param functionString the full function signature text that was parsed by the parser.
	 * @return a user-friendly error message, or null if this class did not know how to 
	 *         handle the given exception.
	 */
	public static String handleParseProblem(Throwable t, String functionString) {
		if (t instanceof TokenMgrError) {
			return generateTokenErrorMessage((TokenMgrError) t, functionString);
		}
		else if (t instanceof ParseException) {
			return generateParseExceptionMessage((ParseException) t, functionString);
		}
		return null;
	}

	private static String generateTokenErrorMessage(TokenMgrError e, String functionString) {

		// HACKY SMACKY: we have to parse the error message to get out the bits we 
		//               desire.  If we could control the TokeyMgrError.java file 
		//               generation, then we could put the fields in it that we need.

		String message = e.getMessage();

		int errorIndex = getTokenMgrErrorIndexOfInvalidText(message, functionString);
		if (errorIndex < 0) {
			errorIndex = getTokenMgrErrorIndexUsingErrorColumn(message);
		}

		if (errorIndex < 0) {
			return null;
		}

		return generateParsingExceptionMessage(e.getMessage(), errorIndex, functionString);
	}

	// the error message contains an 'after' text, which is the text that comes after the
	// invalid text
	private static int getTokenMgrErrorIndexOfInvalidText(String message, String functionString) {
		String invalidCharMarker = "after : ";
		int index = message.indexOf(invalidCharMarker);
		if (index >= 0) {
			String remainder = message.substring(index + invalidCharMarker.length());
			remainder = remainder.replaceAll("\"", "");
			return functionString.indexOf(remainder);
		}
		return -1;
	}

	// the error message contains a 'column' value that is the character column where
	// the error occurred
	private static int getTokenMgrErrorIndexUsingErrorColumn(String message) {
		String columnMarker = "column ";
		int index = message.indexOf(columnMarker);
		if (index >= 0) {
			String remainder = message.substring(index + columnMarker.length());
			int dotIndex = remainder.indexOf(".");
			String column = remainder.substring(0, dotIndex);

			try {
				return Integer.parseInt(column);
			}
			catch (NumberFormatException nfe) {
				// we tried
			}
		}
		return -1;
	}

	private static String generateParseExceptionMessage(ParseException pe, String functionString) {
		// HACKY SMACKY!....this code is done in lieu of actually putting good data in the 
		// exception itself...we should do that!
		if (pe.currentToken == null) {
			return null;
		}

		int errorIndex = pe.currentToken.beginColumn;
		if (errorIndex < 0) {
			return null;
		}

		return generateParsingExceptionMessage(pe.getMessage(), errorIndex, functionString);
	}

	private static String generateParsingExceptionMessage(String errorMessage, int errorIndex,
			String functionString) {
		String parseMessage = "";
		if (errorMessage != null) {

			// Handle lines that are as big as the screen:
			// -wrap on the given length
			// -remove newlines because the line wrapping utility always breaks on those
			parseMessage = errorMessage.replaceAll("\n", " ");
			parseMessage = HTMLUtilities.lineWrapWithHTMLLineBreaks(
				HTMLUtilities.escapeHTML(parseMessage), 80);
			parseMessage = "<br><br>" + parseMessage + "<br>";
		}

		StringBuffer successFailureBuffer = new StringBuffer();
		successFailureBuffer.append("<blockquote>");
		if (errorIndex == 0) {
			successFailureBuffer.append("<font color=\"" + Messages.ERROR + "\"><b>");
			successFailureBuffer.append(HTMLUtilities.friendlyEncodeHTML(functionString));
			successFailureBuffer.append("</b></font>");
		}
		else {
			successFailureBuffer.append("<font color=\"" + Colors.FOREGROUND + "\">");
			successFailureBuffer.append(
				HTMLUtilities.friendlyEncodeHTML(functionString.substring(0, errorIndex)));
			successFailureBuffer.append("</font>");
			successFailureBuffer.append("<font color=\"" + Messages.ERROR + "\"><b>");
			successFailureBuffer.append(
				HTMLUtilities.friendlyEncodeHTML(functionString.substring(errorIndex)));
			successFailureBuffer.append("</b></font>");
		}
		successFailureBuffer.append("</blockquote>");

		if (errorIndex == 0) {
			return "<html>Function signature parse failed" + parseMessage + "<br>" +
				successFailureBuffer;
		}
		return "<html>Function signature parse failed on token starting near character " +
			errorIndex + "<br>" + successFailureBuffer;
	}


    public static File getFile(String parent, String filename) {
        File file = findFile(parent, filename);
        if (file != null) {
                return file;
        }
        // filename lower
        file = findFile(parent, filename.toLowerCase());
        if (file != null) {
                return file;
        }
        // parent and filename lower
        file = findFile(parent.toLowerCase(), filename.toLowerCase());
        if (file != null) {
                return file;
        }
        // parent and filename upper
        file = findFile(parent.toUpperCase(), filename.toUpperCase());
        return file;
    }

    private static File findFile(String parent, String filename) {
        File iFile = null;

        iFile = new File(parent + File.separator + filename);
        if (iFile.exists())
                return iFile;

        // try just in this directory
        File sameiFile = new File(parent + File.separator
                        + (new File(filename)).getName());
        if (sameiFile.exists())
                return sameiFile;

        // try all files in this directory doing to-lower on both input file and output file
        // if match return it
        File folder = new File(parent);
        if (folder.isDirectory()) {
                File[] listOfFiles = folder.listFiles();

                if (listOfFiles != null) {
                        for (File file : listOfFiles) {
                                if (file.isFile() && filename.compareToIgnoreCase(file.getName()) == 0) {
                                        return file;
                                }
                        }
                }
        }
        return null;
    }
}
