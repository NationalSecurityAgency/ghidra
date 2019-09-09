package ghidra.xtext.sleigh.ui.console

import java.util.HashMap
import java.util.Map
import org.eclipse.core.resources.IFile
import org.eclipse.core.resources.ResourcesPlugin
import org.eclipse.core.runtime.Path
import org.eclipse.debug.ui.console.FileLink
import org.eclipse.jface.text.BadLocationException
import org.eclipse.ui.console.IPatternMatchListenerDelegate
import org.eclipse.ui.console.PatternMatchEvent
import org.eclipse.ui.console.TextConsole

class ConsoleHyperlinking implements IPatternMatchListenerDelegate {

	static final String compilingBase = "Compiling ";
	static final String failedBase = " failed to compile";
	static final String javaPrefix = "[java] ";
	Map<String, IFile> fFileNameToIFile = new HashMap();

	static String lastBase = "";  // last full path base name found

	TextConsole console

	override matchFound(PatternMatchEvent event) {
		try {
			var offset = event.getOffset();
			var length = event.getLength();
			var _str = console.document.get(offset, length);
			var setBase = false;

			if (_str.indexOf(compilingBase) != -1) {
				_str = _str.replace(compilingBase, "");
				setBase = true;
				offset += compilingBase.length
				length -= compilingBase.length
			}

			if (_str.indexOf(failedBase) != -1) {
				_str = _str.replace(failedBase, "");
				_str = _str.replace(javaPrefix, "");
				setBase = true;
				offset += javaPrefix.length
				length -= failedBase.length + javaPrefix.length
			}

		    // get filename and optional linenumber after ':'
			val indexOfColon = _str.indexOf(":")
			var fileName = ""
			var lineNumber = 1
			if (indexOfColon != -1) {
				fileName = _str.substring(0, indexOfColon)
				lineNumber = Integer.valueOf(_str.substring(indexOfColon + 1))
			} else {
				fileName = _str
			}

			var file = getIFile(fileName, setBase);

			if (file !== null) {
				val link = new FileLink(file, null, -1, -1, lineNumber);
				console.addHyperlink(link, offset, length);
			}
		} catch (BadLocationException | NumberFormatException e) {
		}
	}

	override connect(TextConsole console) {
		this.console = console
		lastBase = ""
	}

	override disconnect() {
		this.console = null
		fFileNameToIFile.clear();
	}

	def IFile getIFile(String filePath, boolean setBase) {
		if (filePath === null) {
			return null;
		}
		// check the name to IFile cache
		var file = fFileNameToIFile.get(filePath);
		if (file === null) {
			var f = new Path(filePath).toFile()
			var uri = f.toURI();
			var files = ResourcesPlugin.getWorkspace().getRoot().findFilesForLocationURI(uri);
			if (files.length <= 0) {
				// didn't find the file, try tacking on the lastbase path
				f = new Path(lastBase + Path.SEPARATOR + filePath).toFile()
				f.toURI();
				uri = f.toURI()
				files = ResourcesPlugin.getWorkspace().getRoot().findFilesForLocationURI(uri);
			}
			if (files.length > 0) {
				file = files.get(0);
				fFileNameToIFile.put(filePath, file);
				if (setBase) {
					lastBase = f.parent
				}
			}
		}
		return file;
	}
}
