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
package ghidra.features.bsim.query;

import java.io.*;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.TreeSet;

import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Class for modifying the PostgreSQL configuration files describing
 *   the main server settings (postgresql.conf)
 *   the connection settings  (pg_hba.conf)
 *   the identification map   (pg_ident.conf)
 */
public class ServerConfig {
	private TreeMap<String, String> keyValue = new TreeMap<>();			// Values we want set in the configuration file
	private TreeSet<ConnectLine> connectSet = new TreeSet<>();			// Entries we want in the connection file

	/**
	 * Class that holds a single configuration option from the PostgreSQL configuration file
	 */
	private static class ConfigLine {
		public String key;				// Configuration key
		public String value;			// Value assigned to the key
		public String comment;			// Any associate comment on the same line as the key/value
		public int status;
		// 0 if the line does not contain a controlled key
		// 1 if the line contains a controlled key that is uncommented
		// 2 if the line contains a controlled key that is commented

		private int sz;
		private int pos;
		private boolean commentedkey;

		public void parseUptoKey(String line) {
			key = null;
			value = null;
			comment = null;
			status = 0;
			sz = line.length();
			pos = 0;
			commentedkey = false;
			pos = skipWhiteSpace(line, pos);
			if (pos >= sz) {
				return;
			}
			if (line.charAt(pos) == '#') {
				pos += 1;
				commentedkey = true;
				pos = skipWhiteSpace(line, pos);
				if (pos >= sz) {
					return;
				}
			}
			int tokend = scanToken(line, pos);
			if (tokend == pos) {
				return;		// No characters in token
			}
			key = line.substring(pos, tokend);
			pos = tokend;

		}

		public void skipValueParseComment(String line) {
			pos = skipWhiteSpace(line, pos);
			if (pos >= sz) {
				return;
			}
			if (line.charAt(pos) != '=') {
				return;
			}
			pos += 1;
			comment = "";

			while (pos < sz) {
				if (line.charAt(pos) == '#') {
					comment = line.substring(pos);
					break;
				}
				pos += 1;
			}
			status = commentedkey ? 2 : 1;
		}

		public void parseValue(String line) {
			pos = skipWhiteSpace(line, pos);
			if (pos >= sz) {
				return;
			}
			if (line.charAt(pos) != '=') {
				return;
			}
			pos += 1;
			comment = "";
			int valstart = pos;
			while (pos < sz) {
				if (line.charAt(pos) == '#') {
					comment = line.substring(pos);
					break;
				}
				pos += 1;
			}
			value = line.substring(valstart, pos).trim();
			status = commentedkey ? 2 : 1;
		}

		private static int scanToken(String line, int pos) {
			int sz = line.length();
			while (pos < sz) {
				char c = line.charAt(pos);
				if (!Character.isJavaIdentifierPart(c)) {
					break;
				}
				pos += 1;
			}
			return pos;
		}

		private static int skipWhiteSpace(String line, int pos) {
			int sz = line.length();
			while (pos < sz) {
				char c = line.charAt(pos);
				if (!Character.isWhitespace(c)) {
					break;
				}
				pos += 1;
			}
			return pos;
		}
	}

	/**
	 * Class that holds an entry from the PostgreSQL connection configuration file
	 */
	private static class ConnectLine implements Comparable<ConnectLine> {
		public String type;				// Type of connection: local, host, hostssl, etc.
		public String database;			// Name of database associated with entry or the reserved word 'all'
		public String user;				// Name of user associated with entry (or 'all')
		public String address;			// IPv4 or IPv6 address
		public String method;			// authentication method to use:  trust, cert, ...
		public String options;			// Additional options
		public boolean isMatched;		// Set to true if we have seen this entry in the connection file

		@Override
		public int compareTo(ConnectLine op2) {
			int comp = database.compareTo(op2.database);
			if (comp != 0) {
				return comp;
			}
			comp = user.compareTo(op2.user);
			if (comp != 0) {
				return comp;
			}
			if (address == null) {
				if (op2.address != null) {
					return -1;
				}
			}
			else {
				if (op2.address == null) {
					return 1;
				}
				comp = address.compareTo(op2.address);
				if (comp != 0) {
					return comp;
				}
			}
			return 0;
		}

		/**
		 * Determine if the connection is coming either from UNIX socket or "localhost"
		 * @return true if the connection is local in this sense
		 */
		public boolean isLocal() {
			if (type.equals("local")) {		// UNIX socket
				return true;
			}
			if (address != null) {
				if (address.equals("127.0.0.1/32")) {	// IPv4 localhost
					return true;
				}
				if (address.equals("::1/128")) {		// IPv6 localhost
					return true;
				}
			}
			return false;
		}

		/**
		 * Parse the fields out of a line of the connection file
		 * @param line the text to parse
		 * @throws IOException if the text is not formatted properly to parse
		 */
		public void parse(String line) throws IOException {
			String[] split = line.split(" +");		// Split on whitespace
			if (split.length < 4) {
				throw new IOException("Parsing error");
			}
			type = split[0];
			database = split[1];
			user = split[2];
			int nextPos = 3;
			if (type.equals("local")) {		// "local" type has no address
				address = null;
			}
			else {
				address = split[3];
				nextPos = 4;
			}
			if (nextPos >= split.length) {
				throw new IOException("Parsing error");
			}
			method = split[nextPos];
			nextPos += 1;
			if (nextPos >= split.length) {
				options = null;
				return;
			}
			StringBuilder buffer = new StringBuilder();
			buffer.append(split[nextPos]);
			nextPos += 1;
			while (nextPos < split.length) {
				buffer.append(' ');
				buffer.append(split[nextPos]);
				nextPos += 1;
			}
			options = buffer.toString();
		}

		/**
		 * Restore a connection entry from an XML tag
		 * @param el the XML element to restore 
		 */
		public void restoreXml(XmlElement el) {
			type = el.getAttribute("type");
			database = el.getAttribute("db");
			user = el.getAttribute("user");
			address = el.getAttribute("addr");
			method = el.getAttribute("method");
			options = el.getAttribute("options");
		}

		/**
		 * Emit the line, formatted as it should appear in the connection file
		 * @param writer the stream writer
		 * @throws IOException if appending to the stream fails
		 */
		public void emit(Writer writer) throws IOException {
			writer.append(type);
			for (int i = type.length(); i < 8; ++i) {
				writer.append(' ');
			}
			writer.append(database);
			for (int i = database.length(); i < 16; ++i) {
				writer.append(' ');
			}
			writer.append(user);
			for (int i = user.length(); i < 16; ++i) {
				writer.append(' ');
			}
			int addrLen = 0;
			if (address != null) {
				addrLen = address.length();
				writer.append(address);
			}
			for (int i = addrLen; i < 24; ++i) {
				writer.append(' ');
			}
			writer.append(method);
			if (options != null) {
				writer.append(' ');
				writer.append(options);
			}
		}
	}

	private static class IdentLine {
		private String mapName;			// Map the entry belongs to		
		private String systemName;		// Name reported by the system
		private boolean systemNameIsQuoted;
		private String roleName;			// Database role to map to
		private boolean roleNameIsQuoted;

		private static int skipWhiteSpace(int pos, String line) {
			for (; pos < line.length(); ++pos) {
				char c = line.charAt(pos);
				if (c != ' ' && c != '\t') {
					break;
				}
			}
			return pos;
		}

		private static int parseField(int pos, String line) {
			for (; pos < line.length(); ++pos) {
				char c = line.charAt(pos);
				if (c == ' ' || c == '\t') {
					break;
				}
			}
			return pos;
		}

		private static int parseDoubleQuote(int pos, String line) {
			pos += 1;		// Skip the initial quote character
			for (; pos < line.length(); ++pos) {
				char c = line.charAt(pos);
				if (c == '"') {
					pos += 1;
					break;
				}
			}
			return pos;
		}

		public static boolean needsDoubleQuotes(String name) {
			for (int i = 0; i < name.length(); ++i) {
				char c = name.charAt(i);
				if (!Character.isLetterOrDigit(c)) {
					return true;
				}
			}
			return false;
		}

		public IdentLine() {
		}

		public IdentLine(String mName, String sysName, String rName) {
			mapName = mName;
			systemName = sysName;
			systemNameIsQuoted = needsDoubleQuotes(sysName);
			roleName = rName;
			roleNameIsQuoted = needsDoubleQuotes(rName);
		}

		public void setSystemName(String sysName) {
			systemName = sysName;
			systemNameIsQuoted = needsDoubleQuotes(sysName);
		}

		public boolean matchRole(String mName, String rName) {
			return mapName.equals(mName) && roleName.equals(rName);
		}

		/**
		 * Parse a single line from the pg_ident.conf file and recover the
		 * map name, system name, and role
		 * @param line is the incoming of text
		 * @return true if the line is an ident entry, false if it is a comment
		 * @throws IOException if the text cannot be parsed
		 */
		public boolean parse(String line) throws IOException {
			int pos = 0;
			pos = skipWhiteSpace(pos, line);
			if (pos >= line.length()) {
				return false;			// Blank line, treat as comment
			}
			if (line.charAt(pos) == '"') {
				throw new IOException("Bad map field in pg_ident.conf entry");
			}
			if (line.charAt(pos) == '#') {
				return false;			// Return false to indicate comment
			}
			int endpos = parseField(pos, line);
			mapName = line.substring(pos, endpos);

			pos = skipWhiteSpace(endpos, line);
			if (pos >= line.length()) {
				throw new IOException("Missing system-name in pg_ident.conf entry");
			}
			else if (line.charAt(pos) == '"') {
				systemNameIsQuoted = true;
				endpos = parseDoubleQuote(pos, line);
				if (line.charAt(endpos - 1) != '"') {
					throw new IOException("Entry missing ending quote in pg_ident.conf");
				}
				systemName = line.substring(pos + 1, endpos - 1);		// Strip quotes
			}
			else {
				systemNameIsQuoted = false;
				endpos = parseField(pos, line);
				systemName = line.substring(pos, endpos);
			}

			pos = skipWhiteSpace(endpos, line);
			if (pos >= line.length()) {
				throw new IOException("Missing role in pg_ident.conf entry");
			}
			else if (line.charAt(pos) == '"') {
				roleNameIsQuoted = true;
				endpos = parseDoubleQuote(pos, line);
				if (line.charAt(endpos - 1) != '"') {
					throw new IOException("Entry missing ending quote in pg_ident.conf");
				}
				roleName = line.substring(pos + 1, endpos - 1);		// Strip quotes
			}
			else {
				roleNameIsQuoted = false;
				endpos = parseField(pos, line);
				roleName = line.substring(pos, endpos);
			}
			return true;
		}

		public void emit(Writer writer) throws IOException {
			writer.write(mapName);
			for (int i = mapName.length(); i < 15; ++i) {
				writer.write(' ');
			}
			writer.write(' ');
			if (systemNameIsQuoted) {
				writer.write('"');
			}
			writer.write(systemName);
			if (systemNameIsQuoted) {
				writer.write('"');
			}
			for (int i = systemName.length() + (systemNameIsQuoted ? 2 : 0); i < 23; ++i) {
				writer.write(' ');
			}
			writer.write(' ');
			if (roleNameIsQuoted) {
				writer.write('"');
			}
			writer.write(roleName);
			if (roleNameIsQuoted) {
				writer.write('"');
			}
		}
	}

	/**
	 * Read a set of key/value pairs and connection entries to use for patching, from an XML file
	 * @param parser the XML parser
	 */
	public void restoreXml(XmlPullParser parser) {
		parser.start("serverconfig");
		while (parser.peek().isStart()) {
			XmlElement el = parser.start();
			if (el.getName().equals("config")) {
				String key = el.getAttribute("key");
				String val = parser.end().getText();
				keyValue.put(key, val);
			}
			else if (el.getName().equals("connect")) {
				ConnectLine connLine = new ConnectLine();
				connLine.isMatched = false;
				connLine.restoreXml(el);
				connectSet.add(connLine);
				parser.end(el);
			}
			else {
				parser.discardSubTree(el);
			}
		}
		parser.end();
	}

	private static String stripConnectComment(String line) {
		int pos = line.indexOf('#');			// Position of any comment character
		if (pos == -1) {
			pos = line.length();
		}
		for (int i = 0; i < pos; ++i) {
			char c = line.charAt(i);
			if (c != ' ' && c != '\t') {		// Is there meaning characters before the comment '#' character
				return line.substring(i, pos);	// Strip off comment
			}
		}
		return null;		// Indicate this line only contains spaces and/or comment
	}

	/**
	 * Given a set of key/value pairs, established via restoreXml or manually entered via addKey,
	 * read in an existing configuration file, and write out an altered form, where:
	 *   1) Keys matching something in the keyValue map have their value altered to match the map
	 *   2) Keys that don't match anything in the map, are output unaltered
	 *   3) Comments, both entire line and those coming after key/value pairs, are preserved
	 * @param inFile the file to read
	 * @param outFile the new file to write
	 * @throws IOException if the files cannot be read from or written to
	 */
	public void patchConfig(File inFile, File outFile) throws IOException {

		TreeSet<String> alreadyemitted = new TreeSet<>();
		String line;
		ConfigLine parse = new ConfigLine();

		BufferedReader reader = new BufferedReader(new FileReader(inFile));
		FileWriter writer = new FileWriter(outFile);
		try {
			for (;;) {
				line = reader.readLine();
				if (line == null) {
					break;		// End of file reached
				}
				if (line.length() != 0) {
					parse.parseUptoKey(line);
					if (parse.key != null) {
						parse.value = keyValue.get(parse.key);		// Check if this is a key we control
					}
					if (parse.value != null) {
						parse.skipValueParseComment(line);		// Discard the original value, but preserve any comment
					}
					if (parse.status > 0) {		// A controlled key
						if (!alreadyemitted.contains(parse.key)) {	// Have not emitted yet
							line = parse.key + " = " + parse.value;
							if (parse.comment.length() != 0) {
								line = line + "          " + parse.comment;
							}
							alreadyemitted.add(parse.key);
						}
						else {			// Have already emitted before
							if (parse.status == 1) {
								line = '#' + line;
							}
						}
					}
				}
				writer.write(line);
				writer.write('\n');
			}

			for (Entry<String, String> entry : keyValue.entrySet()) {
				if (!alreadyemitted.contains(entry.getKey())) {
					line = entry.getKey() + " = " + entry.getValue();
					writer.write(line);
					writer.write('\n');
				}
			}
		}
		finally {
			reader.close();
			writer.close();
		}
	}

	/**
	 * Read in a connection file and write out an altered version of the file where:
	 *   1) Any entry that matches something in connectSet, has its authentication method altered
	 *   2) Any entry that does not match into connectSet is commented out in the output
	 *   3) Entire line comments are preserved
	 * @param inFile the file to read
	 * @param outFile the new file to write
	 * @throws IOException if the files cannot be read from or written to
	 */
	public void patchConnect(File inFile, File outFile) throws IOException {
		BufferedReader reader = new BufferedReader(new FileReader(inFile));
		FileWriter writer = new FileWriter(outFile);
		try {
			for (;;) {
				String line = reader.readLine();
				if (line == null) {
					break;		// End of file reached
				}
				String stripLine = stripConnectComment(line);
				if (stripLine == null) {	// This line only contained a comment
					writer.write(line);		// Output the original line
				}
				else {
					ConnectLine connLine = new ConnectLine();
					connLine.parse(stripLine);
					ConnectLine matchLine = connectSet.ceiling(connLine);
					if (matchLine == null || 0 != matchLine.compareTo(connLine)) {
						writer.write('#');		// Comment out the line
						connLine.emit(writer);
					}
					else {
						matchLine.emit(writer);
						matchLine.isMatched = true;
					}
				}
				writer.write('\n');
			}

			// Append any entries we didn't match
			for (ConnectLine connLine : connectSet) {
				if (connLine.isMatched) {
					continue;
				}
				connLine.emit(writer);
				writer.write('\n');
			}
		}
		finally {
			reader.close();
			writer.close();
		}
	}

	/**
	 * Add/remove an identify entry to pg_ident.conf
	 * @param inFile is a copy of pg_ident.conf to modify
	 * @param outFile becomes the modified copy of pg_ident.conf
	 * @param mapName is the map being modified
	 * @param systemName is the system name (map from)
	 * @param roleName is the database role (map to)
	 * @param addUser is true if the map entry is to be added, false if the entry should be removed
	 * @throws IOException if the file cannot be read from or written to
	 */
	public static void patchIdent(File inFile, File outFile, String mapName, String systemName,
			String roleName, boolean addUser) throws IOException {
		BufferedReader reader = new BufferedReader(new FileReader(inFile));
		FileWriter writer = new FileWriter(outFile);

		try {
			boolean entryIsMatched = !addUser;
			for (;;) {
				String line = reader.readLine();
				if (line == null) {
					break;
				}
				IdentLine identLine = new IdentLine();
				if (identLine.parse(line)) {
					if (identLine.matchRole(mapName, roleName)) {	// Found old entry
						if (!addUser) {								// If we are supposed to drop the entry
							continue;								// Skip the emit method below
						}
						identLine.setSystemName(systemName);			// Update to new role
						entryIsMatched = true;
					}
					identLine.emit(writer);
					writer.write('\n');
				}
				else {	// Read a comment
					writer.write(line);			// Keep line as is
					writer.write('\n');
				}
			}
			if (!entryIsMatched) {
				IdentLine identLine = new IdentLine(mapName, systemName, roleName);
				identLine.emit(writer);
				writer.write('\n');
			}
		}
		finally {
			reader.close();
			writer.close();
		}
	}

	/**
	 * Add a key/value pair directly into the configuration file
	 * @param key the key to add/update
	 * @param value the value to insert
	 */
	public void addKey(String key, String value) {
		keyValue.put(key, value);
	}

	/**
	 * Retrieve the value associated with a particular key from a (parsed) configuration file
	 * @param key identifies the value to return
	 * @return the value
	 */
	public String getValue(String key) {
		return keyValue.get(key);
	}

	/**
	 * Parse a configuration file
	 * @param inFile is the path to the file
	 * @throws IOException if the file cannot be read
	 */
	public void scanConfig(File inFile) throws IOException {
		BufferedReader reader = new BufferedReader(new FileReader(inFile));

		String line;
		ConfigLine parse = new ConfigLine();

		try {
			for (;;) {
				line = reader.readLine();
				if (line == null) {
					break;		// End of file reached
				}
				if (line.length() != 0) {
					parse.parseUptoKey(line);
					if (parse.key == null) {
						continue;
					}
					String curval = keyValue.get(parse.key);		// Check if this is a key we want to find
					if (curval != null) {						// If this line is setting a value we control
						if (curval.length() != 0) {
							throw new IOException("Multiple settings for: " + parse.key);
						}
						parse.parseValue(line);		// Discard the original value, but preserve any comment
						if (parse.status == 1) {	// We have uncommented controlled key
							keyValue.put(parse.key, parse.value);
						}
					}
				}
			}
		}
		finally {
			reader.close();
		}
	}

	/**
	 * Read in all the entries of the connection file
	 * @param inFile the file to read in
	 * @throws IOException if the file cannot be read/parsed
	 */
	public void scanConnect(File inFile) throws IOException {
		BufferedReader reader = new BufferedReader(new FileReader(inFile));
		try {
			for (;;) {
				String line = reader.readLine();
				if (line == null) {
					break;		// End of file reached
				}
				String stripLine = stripConnectComment(line);
				if (stripLine == null) {	// This line only contained a comment
					continue;
				}
				ConnectLine connLine = new ConnectLine();
				connLine.parse(stripLine);
				connectSet.add(connLine);
			}
		}
		finally {
			reader.close();
		}
	}

	public String getLocalAuthentication() {
		for (ConnectLine connLine : connectSet) {
			if (connLine.isLocal()) {
				return connLine.method;
			}
		}
		return null;
	}

	public void setLocalAuthentication(String val, String options) {
		for (ConnectLine connLine : connectSet) {
			if (connLine.isLocal()) {
				connLine.method = val;
				connLine.options = options;
			}
		}
	}

	public String getHostAuthentication() {
		for (ConnectLine connLine : connectSet) {
			if (connLine.type.equals("hostssl") && !connLine.isLocal()) {
				return connLine.method;
			}
		}
		return null;
	}

	public void setHostAuthentication(String val, String options) {
		for (ConnectLine connLine : connectSet) {
			if (connLine.type.equals("hostssl") && !connLine.isLocal()) {
				connLine.method = val;
				connLine.options = options;
			}
		}
	}
}
