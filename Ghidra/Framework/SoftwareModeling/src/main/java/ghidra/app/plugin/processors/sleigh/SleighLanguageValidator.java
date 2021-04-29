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
import java.io.StringReader;

import org.iso_relax.verifier.*;
import org.xml.sax.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;
import utilities.util.FileResolutionResult;
import utilities.util.FileUtilities;

/**
 * Validate SLEIGH related XML configuration files: .cspec .pspec and .ldefs
 * 
 * A ResourceFile containing an XML document can be verified with one of the
 * static methods:
 *    - validateCspecFile
 *    - validateLdefsFile
 *    - validatePspecFile
 * 
 * Alternately the class can be instantiated, which will allocate a single verifier
 * that can be run on multiple files.
 */
public class SleighLanguageValidator {
	private static final ResourceFile ldefsRelaxSchemaFile;
	private static final ResourceFile pspecRelaxSchemaFile;
	private static final ResourceFile cspecRelaxSchemaFile;
	public static final int CSPEC_TYPE = 1;
	public static final int PSPEC_TYPE = 2;
	public static final int LDEFS_TYPE = 3;
	public static final int CSPECTAG_TYPE = 4;
	private static final String LANGUAGE_TYPESTRING = "language definitions";
	private static final String COMPILER_TYPESTRING = "compiler specification";
	private static final String PROCESSOR_TYPESTRING = "processor specification";

	private int verifierType;
	private Verifier verifier;

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

	public SleighLanguageValidator(int type) {
		verifierType = type;
		ResourceFile schemaFile = null;
		switch (type) {
			case CSPEC_TYPE:
			case CSPECTAG_TYPE:
				schemaFile = cspecRelaxSchemaFile;
				break;
			case PSPEC_TYPE:
				schemaFile = pspecRelaxSchemaFile;
				break;
			case LDEFS_TYPE:
				schemaFile = ldefsRelaxSchemaFile;
				break;
			default:
				throw new SleighException("Bad verifier type");
		}
		verifier = null;
		try {
			verifier = getVerifier(schemaFile);
		}
		catch (Exception e) {
			throw new SleighException("Error creating verifier", e);
		}
	}

	private String getTypeString() {
		if (verifierType == PSPEC_TYPE) {
			return PROCESSOR_TYPESTRING;
		}
		if (verifierType == LDEFS_TYPE) {
			return LANGUAGE_TYPESTRING;
		}
		return COMPILER_TYPESTRING;
	}

	/**
	 * Verify the given file against this validator.
	 * @param specFile is the file
	 * @throws SleighException with an explanation if the file does not validate
	 */
	public void verify(ResourceFile specFile) throws SleighException {
		FileResolutionResult result = FileUtilities.existsAndIsCaseDependent(specFile);
		if (!result.isOk()) {
			throw new SleighException(
				specFile + " is not properly case dependent: " + result.getMessage());
		}
		try {
			InputStream in = specFile.getInputStream();
			verifier.setErrorHandler(new VerifierErrorHandler(specFile));
			verifier.verify(new InputSource(in));
			in.close();
		}
		catch (Exception e) {
			throw new SleighException(
				"Invalid " + getTypeString() + " file: " + specFile.getAbsolutePath(), e);
		}
	}

	/**
	 * Verify an XML document as a string against this validator.
	 * Currently this only supports verifierType == CSPECTAG_TYPE.
	 * @param title is a description of the document
	 * @param document is the XML document body
	 * @throws SleighException with an explanation if the document does not validate
	 */
	public void verify(String title, String document) throws SleighException {
		if (verifierType != CSPECTAG_TYPE) {
			throw new SleighException("Only cspec tag verification is supported");
		}
		StringBuilder buffer = new StringBuilder();
		buffer.append("<compiler_spec>\n");
		buffer.append("<default_proto>\n");
		buffer.append("<prototype name=\"a\" extrapop=\"0\" stackshift=\"0\">\n");
		buffer.append("<input/><output/>\n");
		buffer.append("</prototype>\n");
		buffer.append("</default_proto>\n");
		buffer.append(document);
		buffer.append("</compiler_spec>\n");
		ErrorHandler errorHandler = new VerifierErrorHandler(title, 6);
		StringReader reader = new StringReader(buffer.toString());

		verifier.setErrorHandler(errorHandler);
		try {
			verifier.verify(new InputSource(reader));
		}
		catch (Exception e) {
			throw new SleighException("Invalid " + getTypeString() + ": " + title, e);
		}
	}

	public static void validateLdefsFile(ResourceFile ldefsFile) throws SleighException {
		validateSleighFile(ldefsRelaxSchemaFile, ldefsFile, LANGUAGE_TYPESTRING);
	}

	public static void validatePspecFile(ResourceFile pspecFile) throws SleighException {
		validateSleighFile(pspecRelaxSchemaFile, pspecFile, PROCESSOR_TYPESTRING);
	}

	public static void validateCspecFile(ResourceFile cspecFile) throws SleighException {
		validateSleighFile(cspecRelaxSchemaFile, cspecFile, COMPILER_TYPESTRING);
	}

	private static void validateSleighFile(ResourceFile relaxSchemaFile,
			ResourceFile fileToValidate, String type) throws SleighException {

		FileResolutionResult result = FileUtilities.existsAndIsCaseDependent(fileToValidate);
		if (!result.isOk()) {
			throw new SleighException(
				fileToValidate + " is not properly case dependent: " + result.getMessage());
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
			verifier.setErrorHandler(new VerifierErrorHandler(fileToValidate));
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

	private static class VerifierErrorHandler implements ErrorHandler {
		final String documentTitle;
		int lineNumberBase;

		public VerifierErrorHandler(ResourceFile file) {
			documentTitle = file.toString();
			lineNumberBase = 0;
		}

		public VerifierErrorHandler(String title, int base) {
			documentTitle = title;
			lineNumberBase = base;
		}

		@Override
		public void fatalError(SAXParseException e) throws SAXException {
			error(e);
		}

		@Override
		public void error(SAXParseException e) throws SAXException {
			int lineno = e.getLineNumber() - lineNumberBase;
			Msg.error(SleighLanguageValidator.class,
				"Error validating " + documentTitle + "  at " + lineno + ":" + e.getColumnNumber(),
				e);
			throw e;
		}

		@Override
		public void warning(SAXParseException e) {
			// ignore warnings
		}
	}
}
