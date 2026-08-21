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
package ghidra.util.charset;

import static java.lang.Character.UnicodeScript.*;
import static java.nio.charset.StandardCharsets.*;

import java.io.*;
import java.lang.Character.UnicodeScript;
import java.nio.charset.Charset;
import java.util.*;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;

/**
 * Maintains a list of charsets and info about each charset.  More common charsets are ordered
 * toward the beginning of the list.
 * <p>
 * Created instances are immutable, but the "INSTANCE" singleton can be replaced by a new value
 * when {@link #reinitializeWithUserDefinedCharsets()} is called.  (This is done to avoid reading
 * the user config file and causing slow downs during certain stages of the startup)
 */
public class CharsetInfoManager {
	public static final String UTF8 = "UTF-8";
	public static final String UTF16 = "UTF-16";
	public static final String UTF32 = "UTF-32";
	public static final String USASCII = "US-ASCII";

	/**
	 * Comparator that ignores charset name "x-" prefixes
	 */
	public static Comparator<String> CHARSET_NAME_COMP = (s1, s2) -> {
		return stripCharsetX(s1).compareToIgnoreCase(stripCharsetX(s2));
	};

	/**
	 * Comparator that ignores charset name "x-" prefixes
	 */
	public static Comparator<CharsetInfo> CHARSET_COMP = (csi1, csi2) -> {
		return stripCharsetX(csi1.getName()).compareToIgnoreCase(stripCharsetX(csi2.getName()));
	};

	private static final class Singleton {
		private static CharsetInfoManager INSTANCE = new CharsetInfoManager();
	}

	private static final class CharSetsSingleton {
		// decouple loading these 'non-standard' (but actually standard) charsets to a different
		// class so their initialization can happen before the manager singleton instance
		private static final Charset UTF_32 = Charset.forName(UTF32);
		private static final Charset UTF_32LE = Charset.forName("UTF-32LE");
		private static final Charset UTF_32BE = Charset.forName("UTF-32BE");
	}

	/**
	 * Get the global singleton instance of this {@link CharsetInfoManager}.
	 * <p>
	 * This singleton will only have generic information until 
	 * {@link CharsetInfoManager#reinitializeWithUserDefinedCharsets()} is called.
	 *
	 * @return global singleton instance
	 */
	public static CharsetInfoManager getInstance() {
		return Singleton.INSTANCE;
	}

	/**
	 * {@return true if the specified charset needs additional care for handling byte-order-mark
	 * byte values (eg. UTF-16/32).  If the charset is a LE/BE variant, no extra care is needed.}
	 * @param charsetName name of charset
	 */
	public static boolean isBOMCharset(String charsetName) {
		return UTF32.equals(charsetName) || UTF16.equals(charsetName);
	}

	private static String stripCharsetX(String csName) {
		return csName.startsWith("x-") ? csName.substring(2) : csName;
	}

	private Map<String, CharsetInfo> charsets = new LinkedHashMap<>(); // preserve addition order

	private CharsetInfoManager() {
		this(List.of());
	}

	private CharsetInfoManager(List<CharsetInfo> userDefinedInfo) {
		// add ASCII+UTF-NN charsets first (these are the most commonly used)
		getStandardCharsets().forEach(csi -> charsets.put(csi.getName(), csi));

		// add user defined charsets (that are present in the jvm)
		userDefinedInfo.forEach(csi -> {
			if (Charset.isSupported(csi.getName())) {
				charsets.put(csi.getName(), csi);
			}
		});

		// last, add any charsets that are not covered by the standard and user-defined charsets 
		List<String> availCSNames = new ArrayList<>(Charset.availableCharsets().keySet());
		availCSNames.sort(CHARSET_NAME_COMP);
		for (String csName : availCSNames) {
			if (!charsets.containsKey(csName)) {
				charsets.put(csName, new CharsetInfo(Charset.forName(csName)));
			}
		}
	}

	/**
	 * {@return List of names of current configured charsets}
	 */
	public List<String> getCharsetNames() {
		return List.copyOf(charsets.keySet());
	}

	/**
	 * {@return list of all available charsets}
	 */
	public List<CharsetInfo> getCharsets() {
		return List.copyOf(charsets.values());
	}

	/**
	 * Returns the number of bytes that the specified charset needs to specify a
	 * character.
	 *
	 * @param charsetName charset name
	 * @return number of bytes in a character, ie. 1, 2, 4, etc, defaults to 1
	 *         if charset is unknown or not specified in config file.
	 */
	public int getCharsetCharSize(String charsetName) {
		CharsetInfo csi = charsets.get(charsetName);
		return (csi != null) ? csi.getMinBytesPerChar() : 1;
	}

	/**
	 * Returns list of {@link Charset}s that encode with the number of bytes specified.
	 * @param size the number of bytes for the {@link Charset} encoding.
	 * @return Charsets that encode one byte characters.
	 */
	public List<String> getCharsetNamesWithCharSize(int size) {
		return charsets.values()
				.stream()
				.filter(csi -> csi.getMinBytesPerChar() == size)
				.map(csi -> csi.getName())
				.toList();
	}

	/**
	 * {@return charset info object that represents the specified charset}
	 * @param cs charset
	 */
	public CharsetInfo get(Charset cs) {
		return charsets.get(cs.name());
	}

	/**
	 * {@return charset info object that represents the specified charset}
	 * @param name charset name
	 */
	public CharsetInfo get(String name) {
		return charsets.get(name);
	}

	/**
	 * {@return charset info object that represents the specified charset, and if not found,
	 * returning the defaultCS value}
	 * 
	 * @param name charset name
	 * @param defaultCS default value to return if not found
	 */
	public CharsetInfo get(String name, Charset defaultCS) {
		CharsetInfo result = charsets.get(name);
		if (result == null && defaultCS != null) {
			result = charsets.get(defaultCS.name());
		}
		return result;
	}

	/**
	 * {@return a hopefully short list of non-LATIN UnicodeScripts that are supported by a 
	 * charset that is present in this jvm.  (ignoring any charsets that support all scripts).
	 * This list of scripts can be useful when presenting the user with a list of scripts or 
	 * things related to a script.  Typically the list will contain:
	 * ARABIC, BOPOMOFO, CYRILLIC, DEVANAGARI, HANGUL, HAN, HEBREW, HIRAGANA, KATAKANA, THAI }        
	 */
	public List<UnicodeScript> getMostImplementedScripts() {
		Set<UnicodeScript> scriptsToIgnore = EnumSet.of(COMMON, INHERITED, UNKNOWN, LATIN, GREEK);
		List<UnicodeScript> scripts = charsets.values()
				.stream()
				.filter(csi -> !csi.supportsAllScripts())
				.flatMap(csi -> csi.getScripts().stream())
				.filter(script -> !scriptsToIgnore.contains(script))
				.sorted((o1, o2) -> o1.name().compareTo(o2.name()))
				.distinct()
				.toList();
		return scripts;
	}

	//---------------------------------------------------------------------------------------------
	// static helper methods
	//---------------------------------------------------------------------------------------------

	public static List<String> getStandardCharsetNames() {
		return List.of(USASCII, UTF8, UTF16, UTF32);
	}

	private static List<CharsetInfo> getStandardCharsets() {
		//@formatter:off
		return List.of(
			new CharsetInfo(USASCII, null, 1, 1, 1, -1, true, true, EnumSet.of(COMMON, LATIN), Set.of()),
			new CharsetInfo(UTF8, null, 1, 4, 1, -1, true, true, CharsetInfo.ALL_SCRIPTS, Set.of()),
			
			new CharsetInfo(UTF16, null, 2, 4, 2, -1, true, true, CharsetInfo.ALL_SCRIPTS, Set.of()),
			new CharsetInfo(UTF_16BE.name(), null, 2, 4, 2, -1, true, true, CharsetInfo.ALL_SCRIPTS, Set.of()),
			new CharsetInfo(UTF_16LE.name(), null, 2, 4, 2, -1, true, true, CharsetInfo.ALL_SCRIPTS, Set.of()),
			
			new CharsetInfo(CharSetsSingleton.UTF_32.name(), null, 4, 4, 4, -1, true, true, CharsetInfo.ALL_SCRIPTS, Set.of()),
			new CharsetInfo(CharSetsSingleton.UTF_32BE.name(), null, 4, 4, 4, -1, true, true, CharsetInfo.ALL_SCRIPTS, Set.of()),
			new CharsetInfo(CharSetsSingleton.UTF_32LE.name(), null, 4, 4, 4, -1, true, true, CharsetInfo.ALL_SCRIPTS, Set.of()),
			
			new CharsetInfo(ISO_8859_1.name(), null, 1, 1, 1, -1, true, false, EnumSet.of(COMMON, LATIN), Set.of(USASCII))
		);
		//@formatter:on
	}

	/**
	 * Replaces the current singleton with a new singleton that has been initialized with the
	 * optional information found in the charset_info.json file.
	 */
	public static void reinitializeWithUserDefinedCharsets() {
		CharsetInfoConfigFile configFile = CharsetInfoConfigFile.read(getConfigFileLocation());
		if (!configFile.getCharsets().isEmpty()) {
			Singleton.INSTANCE = new CharsetInfoManager(configFile.getCharsets());
		}
	}

	/**
	 * {@return filename of the config file}
	 */
	public static ResourceFile getConfigFileLocation() {
		return Application.findDataFileInAnyModule("charset_info.json");
	}

	/**
	 * Class to represent the charsetinfo json configuration file.
	 */
	public static class CharsetInfoConfigFile {
		/**
		 * Read config info from the specified file
		 * 
		 * @param configFile {@link ResourceFile}
		 * @return new {@link CharsetInfoConfigFile}, never null, but maybe empty
		 */
		public static CharsetInfoConfigFile read(ResourceFile configFile) {
			if (configFile != null) {
				try (InputStream is = configFile.getInputStream();
						JsonReader reader = new JsonReader(new InputStreamReader(is))) {

					Gson gson = new GsonBuilder().create();
					CharsetInfoConfigFile configFileData =
						gson.fromJson(reader, CharsetInfoConfigFile.class);

					if (configFileData == null) {
						return new CharsetInfoConfigFile();
					}

					configFileData.validateData();
					return configFileData;
				}
				catch (JsonParseException | IOException e) {
					Msg.error(CharsetInfoManager.class, "Error reading charset_info.json", e);
					// fall thru, return default empty instance
				}
			}
			return new CharsetInfoConfigFile();
		}

		private List<String> comments; // broken up into a list so it looks good in the json
		private List<CharsetInfo> charsets;

		public CharsetInfoConfigFile() {
			this.comments = List.of();
			this.charsets = List.of();
		}

		public CharsetInfoConfigFile(String comment, List<CharsetInfo> charsets) {
			this.comments = comment.lines().toList();
			this.charsets = charsets;
		}

		public String getComment() {
			return String.join("\n", comments);
		}

		public List<CharsetInfo> getCharsets() {
			return charsets;
		}

		public void validateData() {
			Set<String> names = new HashSet<>();
			Set<String> dups = new HashSet<>();
			Set<String> unknowns = new HashSet<>();

			for (CharsetInfo csi : charsets) {
				if (!names.add(csi.getName())) {
					dups.add(csi.getName());
				}
				if (!Charset.isSupported(csi.getName())) {
					unknowns.add(csi.getName());
				}
			}
			if (!dups.isEmpty()) {
				Msg.warn(CharsetInfoManager.class,
					"Duplicate charset names found in charset_info.json: " + dups);
			}
			if (!unknowns.isEmpty()) {
				Msg.warn(CharsetInfoManager.class,
					"Unknown/unsupported charset names found in charset_info.json: " + unknowns);
			}
		}

		/**
		 * Writes this instance to a json file.
		 * 
		 * @param configFilename where to write to
		 * @throws IOException if error writing
		 */
		public void write(File configFilename) throws IOException {
			File configDir = configFilename.getParentFile();
			File tmpConfigFile = new File(configDir, configFilename.getName() + ".tmp");
			File prevConfigFile = new File(configDir, configFilename.getName() + ".prev");

			try (Writer fw = new FileWriter(tmpConfigFile)) {
				Gson gson = new GsonBuilder().setPrettyPrinting()
						.addSerializationExclusionStrategy(new ExclusionStrategy() {
							@Override
							public boolean shouldSkipField(FieldAttributes f) {
								return f.getDeclaringClass().equals(CharsetInfo.class) &&
									CharsetInfo.FIELDS_TO_EXCLUDE_FROM_JSON.contains(f.getName());
							}

							@Override
							public boolean shouldSkipClass(Class<?> clazz) {
								return false;
							}
						})
						.create();
				gson.toJson(this, fw);
			}
			prevConfigFile.delete();
			configFilename.renameTo(prevConfigFile);
			if (tmpConfigFile.renameTo(configFilename)) {
				prevConfigFile.delete();
			}
		}
	}

}
