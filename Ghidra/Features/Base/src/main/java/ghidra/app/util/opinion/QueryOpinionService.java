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
package ghidra.app.util.opinion;

import java.io.IOException;
import java.util.*;

import org.apache.commons.lang3.StringUtils;
import org.xml.sax.*;

import generic.jar.ResourceFile;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;

public class QueryOpinionService {
	private static boolean doInit = true;
	private static Map<String, Map<String, Map<String, Set<QueryResult>>>> DATABASE = null;
	private static LanguageService languageService = null;

	private static synchronized void initialize() {
		if (doInit) {
			DATABASE = new HashMap<>();
			languageService = DefaultLanguageService.getLanguageService();

			List<ResourceFile> files = searchAndFindAllOpinionXMLs();
			for (ResourceFile file : files) {
				try {
					parseFile(file);
				}
				catch (Exception e) {
					Msg.warn(QueryOpinionService.class, "Problem parsing " + file, e);
				}
			}

			doInit = false;
		}
	}

	private static List<ResourceFile> searchAndFindAllOpinionXMLs() {
		return ghidra.framework.Application.findFilesByExtensionInApplication(".opinion");
	}

	private static void parseFile(final ResourceFile file) throws SAXException, IOException {
		ErrorHandler errHandler = new ErrorHandler() {
			@Override
			public void error(SAXParseException exception) throws SAXException {
				Msg.error(QueryOpinionService.class, "Error parsing " + file, exception);
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				Msg.error(QueryOpinionService.class, "Fatal error parsing " + file, exception);
			}

			@Override
			public void warning(SAXParseException exception) throws SAXException {
				Msg.warn(QueryOpinionService.class, "Warning parsing " + file, exception);
			}
		};
		XmlPullParser parser = XmlPullParserFactory.create(file, errHandler, false);
		try {
			QueryOpinionServiceHandler.read(parser);
		}
		finally {
			parser.dispose();
		}
	}

	static void addQuery(String loader, String primary, String secondary,
			LanguageCompilerSpecQuery query) {
		Map<String, Map<String, Set<QueryResult>>> loadersByName = DATABASE.get(loader);
		if (loadersByName == null) {
			loadersByName = new HashMap<>();
			DATABASE.put(loader, loadersByName);
		}

		Map<String, Set<QueryResult>> loaders = loadersByName.get(primary);
		if (loaders == null) {
			loaders = new HashMap<>();
			loadersByName.put(primary, loaders);
		}

		Set<QueryResult> specs = loaders.get(secondary);
		if (specs == null) {
			specs = new HashSet<>();
			loaders.put(secondary, specs);
		}

		LanguageCompilerSpecQuery broadQuery = new LanguageCompilerSpecQuery(query.processor,
			query.endian, query.size, query.variant, null);
		List<LanguageCompilerSpecPair> pairs =
			languageService.getLanguageCompilerSpecPairs(broadQuery);
		for (LanguageCompilerSpecPair pair : pairs) {
			specs.add(new QueryResult(pair, pair.compilerSpecID.equals(query.compilerSpecID)));
		}
	}

	public static List<QueryResult> query(String loaderName, String primaryKey,
			String secondaryKey) {

		initialize();
		List<QueryResult> results = new ArrayList<>();
		String message = "No query results found for loader " + loaderName + " with primary key " +
			primaryKey + " and secondary key " + secondaryKey;

		Map<String, Map<String, Set<QueryResult>>> loadersByName = DATABASE.get(loaderName);
		if (loadersByName == null) {
			Msg.debug(QueryOpinionService.class, message);
			return results;
		}

		Map<String, Set<QueryResult>> loadersById = getPrimaryLoaders(loadersByName, primaryKey);
		if (loadersById == null) {
			Msg.debug(QueryOpinionService.class, message);
			return results;
		}

		getSpecs(loadersById, secondaryKey, results);
		if (results.isEmpty()) {
			Msg.debug(QueryOpinionService.class, message);
		}

		return results;
	}

	private static void getSpecs(Map<String, Set<QueryResult>> loadersById, String secondaryKey,
			List<QueryResult> results) {

		Set<QueryResult> secondarySpecs = loadersById.get(secondaryKey);
		if (secondarySpecs == null) {
			// SCR 10746 - Enhancements to the Opinion file processing,
			// enhance the original signed decimal string matching with don't-cares.
			// If secondarySpecs is null then there was no match, next try the new matching
			secondarySpecs = getQueryResultWithSecondaryMasking(secondaryKey, loadersById);
		}

		if (secondarySpecs == null) {
			secondarySpecs = loadersById.get(null);
		}

		if (secondarySpecs != null) {
			results.addAll(secondarySpecs);
		}
	}

	private static Map<String, Set<QueryResult>> getPrimaryLoaders(
			Map<String, Map<String, Set<QueryResult>>> loadersByName, String primaryKey) {

		Map<String, Set<QueryResult>> loadersById = loadersByName.get(primaryKey);
		if (loadersById != null) {
			return loadersById;
		}

		// Check for primary attribute strings that have a list of comma separated primary values.
		// For example, MIPS can have the primary (e_machine) value 8 or 10.
		for (String primaryKeyOriginal : loadersByName.keySet()) {
			if (primaryKeyOriginal == null) {
				continue; // TODO why would we all a null key???
			}

			String primaryKeyCleaned = primaryKeyOriginal.replaceAll("\\s+", "");

			// Split into comma separated substrings that can each be matched
			String[] tokens = primaryKeyCleaned.split(",");
			for (String token : tokens) {
				if (token.equals(primaryKey)) {
					return loadersByName.get(primaryKeyOriginal);
				}
			}
		}

		return loadersById;
	}

	public static Set<QueryResult> getQueryResultWithSecondaryMasking(String secondaryKey,
			Map<String, Set<QueryResult>> byPrimary) {

		// SCR 10746 - look for a secondary match in the secondary attribute string
		Set<QueryResult> queryResult = new HashSet<>();
		for (Map.Entry<String, Set<QueryResult>> entry : byPrimary.entrySet()) {
			String secondaryAttributeString = entry.getKey();
			if (secondaryAttributeMatches(secondaryKey, secondaryAttributeString)) {
				queryResult.addAll(entry.getValue());
			}
		}

		if (queryResult.isEmpty()) {
			queryResult = null;
		}
		return queryResult;
	}

	static boolean secondaryAttributeMatches(String eFlagsDecimalString, String attribute) {

		// eFlagDecimalString is the elf e_flags value, as a decimal string
		// sa is the secondary attribute string from the opinion file,
		// and it must start with "0x" or "0b"
		if (attribute == null) {
			return false;
		}

		if (!StringUtils.startsWithAny(attribute.toLowerCase(), "0x", "0b")) {
			return false;
		}

		int eFlagsInt = Integer.parseInt(eFlagsDecimalString);
		String eFlagsBinaryString = Integer.toBinaryString(eFlagsInt);
		if (eFlagsBinaryString == null) {
			return false;
		}

		eFlagsBinaryString = StringUtils.leftPad(eFlagsBinaryString, 32, "0");
		String eFlagsHexString = Integer.toHexString(eFlagsInt);
		eFlagsHexString = StringUtils.leftPad(eFlagsHexString, 8, "0");

		// Remove '_' and whitespace from the attribute string
		String cleaned = attribute.replace("_", "").replaceAll("\\s+", "").trim();
		String prefix = cleaned.substring(0, 2);
		String value = cleaned.substring(2);
		if (prefix.toLowerCase().startsWith("0x")) {

			// It's a hex string
			value = StringUtils.leftPad(value, 8, "0");
			return value.equals(eFlagsHexString);
		}

		// It's a binary string
		value = StringUtils.leftPad(value, 32, "0");
		for (int i = 0; i < 32; i++) {
			char c = value.charAt(i);
			if (c == '.') { // wildcard
				continue;
			}

			if (eFlagsBinaryString.charAt(i) != c) {
				return false;
			}
		}

		return true;
	}
}
