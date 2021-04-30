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
package ghidra.app.plugin.processors.sleigh;

import java.io.InputStream;

import org.iso_relax.verifier.*;
import org.xml.sax.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;
import utilities.util.FileResolutionResult;
import utilities.util.FileUtilities;

public class SleighLanguageValidator {
	private static final ResourceFile ldefsRelaxSchemaFile;
	private static final ResourceFile pspecRelaxSchemaFile;
	private static final ResourceFile cspecRelaxSchemaFile;

	static {
		ResourceFile file = null;
		try {
			file = Application.getModuleDataFile("languages/language_definitions.rxg");
		}
		catch (Exception e) {
			Msg.error(SleighLanguageValidator.class, "Could not find language_definitions.rxg", e);
		}
		if (file == null) {
			Msg.error(SleighLanguageValidator.class, "Could not find language_definitions.rxg");
		}
		ldefsRelaxSchemaFile = file;

		file = null;
		try {
			file = Application.getModuleDataFile("languages/processor_spec.rxg");
		}
		catch (Exception e) {
			Msg.error(SleighLanguageValidator.class, "Could not find processor_spec.rxg", e);
		}
		if (file == null) {
			Msg.error(SleighLanguageValidator.class, "Could not find processor_spec.rxg");
		}
		pspecRelaxSchemaFile = file;

		file = null;
		try {
			file = Application.getModuleDataFile("languages/compiler_spec.rxg");
		}
		catch (Exception e) {
			Msg.error(SleighLanguageValidator.class, "Could not find compiler_spec.rxg", e);
		}
		if (file == null) {
			Msg.error(SleighLanguageValidator.class, "Could not find compiler_spec.rxg");
		}
		cspecRelaxSchemaFile = file;
	}

	public static void validateLdefsFile(ResourceFile ldefsFile) throws SleighException {
		validateSleighFile(ldefsRelaxSchemaFile, ldefsFile, "language definitions");
	}

	public static void validatePspecFile(ResourceFile pspecFile) throws SleighException {
		validateSleighFile(pspecRelaxSchemaFile, pspecFile, "processor specification");
	}

	public static void validateCspecFile(ResourceFile cspecFile) throws SleighException {
		validateSleighFile(cspecRelaxSchemaFile, cspecFile, "compiler specification");
	}

	private static void validateSleighFile(ResourceFile relaxSchemaFile,
			ResourceFile fileToValidate, String type) throws SleighException {

		FileResolutionResult result = FileUtilities.existsAndIsCaseDependent(fileToValidate);
		if (!result.isOk()) {
			throw new SleighException(fileToValidate + " is not properly case dependent: " +
				result.getMessage());
		}

		Verifier verifier = null;
		try {
			verifier = getVerifier(relaxSchemaFile);
		}
		catch (Exception e) {
			throw new SleighException("Error creating verifier", e);
		}
		try {
			InputStream in = fileToValidate.getInputStream();
			verifier.setErrorHandler(new MyErrorHandler(fileToValidate));
			verifier.verify(new InputSource(in));
			in.close();
		}
		catch (Exception e) {
			throw new SleighException(
				"Invalid " + type + " file: " + fileToValidate.getAbsolutePath(), e);
		}
	}

	private static Verifier getVerifier(ResourceFile relaxSchemaFile) throws Exception {
		VerifierFactory factory = new com.sun.msv.verifier.jarv.TheFactoryImpl();
		Schema schema = factory.compileSchema(relaxSchemaFile.toURL().toExternalForm());
		Verifier verifier = schema.newVerifier();
		return verifier;
	}

	private static class MyErrorHandler implements ErrorHandler {
		final ResourceFile file;

		public MyErrorHandler(ResourceFile file) {
			this.file = file;
		}

		@Override
		public void fatalError(SAXParseException e) throws SAXException {
			error(e);
		}

		@Override
		public void error(SAXParseException e) throws SAXException {
			Msg.error(
				SleighLanguageValidator.class,
				"Error validating " + file + "  at " + e.getLineNumber() + ":" +
					e.getColumnNumber(), e);
			throw e;
		}

		@Override
		public void warning(SAXParseException e) {
			// ignore warnings
		}
	}
}
