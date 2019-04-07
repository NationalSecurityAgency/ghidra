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
package ghidra.app.util.viewer.field;

import java.util.List;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;

import docking.widgets.fieldpanel.field.AttributedString;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.*;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.project.ProjectDataService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

/**
 * An annotated string handler that allows handles annotations that begin with
 * {@link #SUPPORTED_ANNOTATIONS}.  This class expects one string following the annotation
 * text that is the program name.  The display text will be that of the program name.
 */
public class ProgramAnnotatedStringHandler implements AnnotatedStringHandler {
	private static final String INVALID_SYMBOL_TEXT =
		"@program annotation must have a program name";
	private static final String[] SUPPORTED_ANNOTATIONS = { "program" };

	@Override
	public AttributedString createAnnotatedString(AttributedString prototypeString, String[] text,
			Program program) throws AnnotationException {
		// if the text is not of adequate size, then show an error string
		if (text.length <= 1) {
			throw new AnnotationException(INVALID_SYMBOL_TEXT);
		}

		String displayText = getDisplayText(text);
		if (displayText == null) {
			// some kind of error
			throw new AnnotationException(INVALID_SYMBOL_TEXT);
		}

		return new AttributedString(displayText, prototypeString.getColor(0),
			prototypeString.getFontMetrics(0), true, prototypeString.getColor(0));
	}

	private String getDisplayText(String[] text) {
		// assume that the 'extra text' means that is how the user wants to display the annotation
		if (text.length > 2) {
			StringBuffer buffer = new StringBuffer();
			for (int i = 2; i < text.length; i++) {
				buffer.append(text[i]).append(" ");
			}
			buffer.deleteCharAt(buffer.length() - 1); // remove last space
			return buffer.toString();
		}

		String symbolText = getUnvalidatedDisplayText(text);
		if (symbolText != null) {
			String programName = getProgramText(text);
			return programName + "@" + symbolText;
		}

		return text[1];
	}

	/** This could return a symbol or an address (or any text really, since it is not checked */
	private String getUnvalidatedDisplayText(String[] text) {
		SymbolPath symbolPath = getSymbolPath(text);
		return symbolPath == null ? null : symbolPath.getName();
	}

	private SymbolPath getSymbolPath(String[] text) {
		String rawText = text[1];

		// Look for the '@' symbol, which allows the user to specify an address or symbol to
		// goto within the given program.  If this symbol does not exist, then we are done here
		int atIndex = rawText.indexOf('@');
		if (atIndex < 0) {
			return null; // no symbol text
		}

		// ...now let's work with the symbol text
		rawText = rawText.substring(atIndex + 1);
		return new SymbolPath(rawText);
	}

	private String getProgramText(String[] text) {
		String rawText = text[1];

		// Look for the '@' symbol, which allows the user to specify an address or symbol to
		// goto within the given program.  If this symbol does not exist, then we are done here
		int atIndex = rawText.indexOf('@');
		if (atIndex < 0) {
			return rawText; // no symbol text
		}
		return rawText.substring(0, atIndex);
	}

	@Override
	public String[] getSupportedAnnotations() {
		return SUPPORTED_ANNOTATIONS;
	}

	@Override
	public boolean handleMouseClick(String[] annotationParts, Navigatable navigatable,
			ServiceProvider serviceProvider) {

		ProjectDataService projectDataService =
			serviceProvider.getService(ProjectDataService.class);
		ProjectData projectData = projectDataService.getProjectData();

		// default folder is the root folder
		DomainFolder folder = projectData.getRootFolder();

		// Get program name and folder from program comment annotation 
		// handles forward and back slashes and with and without first slash
		String programText = getProgramText(annotationParts);
		String programName = FilenameUtils.getName(programText);
		String path = FilenameUtils.getFullPathNoEndSeparator(programText);
		if (path.length() > 0) {
			path = StringUtils.prependIfMissing(FilenameUtils.separatorsToUnix(path), "/");
			folder = projectData.getFolder(path);
		}

		if (folder == null) {
			Msg.showInfo(getClass(), null, "No Folder: " + path,
				"Unable to locate folder by the name \"" + path);
			return true;
		}

		DomainFile programFile = findProgramByName(programName, folder);

		if (programFile == null) {
			Msg.showInfo(getClass(), null, "No Program: " + programName,
				"Unable to locate a program by the name \"" + programName +
					"\".\nNOTE: Program name is case-sensitive. ");
			return true;
		}

		SymbolPath symbolPath = getSymbolPath(annotationParts);
		navigate(programFile, symbolPath, navigatable, serviceProvider);

		return true;
	}

	private void navigate(DomainFile programFile, SymbolPath symbolPath, Navigatable navigatable,
			ServiceProvider serviceProvider) {

		GoToService goToService = serviceProvider.getService(GoToService.class);
		if (goToService == null) {
			// shouldn't happen
			Msg.showWarn(this, null, "Service Missing",
				"This annotation requires the GoToService to be enabled");
			return;
		}

		ProgramManager programManager = serviceProvider.getService(ProgramManager.class);
		Program program = programManager.openProgram(programFile, DomainFile.DEFAULT_VERSION,
			ProgramManager.OPEN_HIDDEN);
		if (program == null) {
			return; // cancelled
		}

		if (symbolPath == null) { // no symbol; just open and go to the program
			Address start = program.getMemory().getMinAddress();
			goToService.goTo(navigatable, new ProgramLocation(program, start), program);
			return;
		}

		// try any symbols(s) first
		List<Symbol> symbols = NamespaceUtils.getSymbols(symbolPath.getPath(), program);
		if (goToSymbol(symbols, navigatable, program, goToService)) {
			return;
		}

		String symbolName = symbolPath.getName();
		Address address = getAddress(symbolName, program);
		if (goToAddress(address, program, navigatable, goToService)) {
			return;
		}

		Msg.showInfo(getClass(), null, "No Symbol: " + symbolName,
			"Unable to navigate to '" + symbolName + "' in the program '" + programFile.getName() +
				"'.\nMake sure that the given symbol/address exists.");
		if (!programManager.isVisible(program)) {
			// we opened a hidden program, but could not navigate--close the program
			programManager.closeProgram(program, true);
		}
	}

	private boolean goToAddress(Address address, Program program, Navigatable navigatable,
			GoToService goToService) {

		if (address == null) {
			return false;
		}

		// have an address; try to go there
		return goToService.goTo(navigatable, new ProgramLocation(program, address), program);
	}

	private boolean goToSymbol(List<Symbol> symbols, Navigatable navigatable, Program program,
			GoToService goToService) {

		if (symbols.isEmpty()) {
			return false;
		}

		// if there is only one, just go there directly, otherwise have to do a search
		Symbol symbol = symbols.get(0);
		if (symbols.size() == 1) {
			return goToService.goTo(navigatable, symbol.getProgramLocation(), program);
		}

		Address addr = navigatable.getLocation().getAddress();
		QueryData data = new QueryData(symbol.getName(), true);
		return goToService.goToQuery(navigatable, addr, data, null, null);
	}

	private Address getAddress(String addressText, Program program) {
		if (addressText == null) {
			return null;
		}
		AddressFactory addressFactory = program.getAddressFactory();
		Address address = addressFactory.getAddress(addressText);

		return address;
	}

	// recursive program to find a program by the given name within the given folder
	private DomainFile findProgramByName(String programText, DomainFolder folder) {
		DomainFile[] files = folder.getFiles();
		for (DomainFile file : files) {
			if (file.getName().equals(programText)) {
				return file;
			}
		}

		// not at the current level, then check sub-folders
		DomainFolder[] folders = folder.getFolders();
		for (DomainFolder subFolder : folders) {
			DomainFile domainFile = findProgramByName(programText, subFolder);
			if (domainFile != null) {
				return domainFile;
			}
		}

		return null;
	}

	@Override
	public String getDisplayString() {
		return "Program";
	}

	@Override
	public String getPrototypeString() {
		return "{@program program_name.exe@symbol_name}";
	}

}
