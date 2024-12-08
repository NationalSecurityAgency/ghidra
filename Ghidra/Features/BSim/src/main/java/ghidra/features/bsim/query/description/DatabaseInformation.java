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
package ghidra.features.bsim.query.description;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

import ghidra.util.exception.AssertException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class DatabaseInformation {
	public String databasename;			// Formal name of this database
	public String owner;				// Owner of this database
	public String description;			// Description of the database
	public short major;					// Signature strategy -- major version
	public short minor;					// Signature strategy -- minor version
	public int settings;				// Settings for signature generation
	public List<String> execats;	// Executable categories for this database
	public List<String> functionTags;	// Named boolean properties on functions
	public String dateColumnName;		// An override of the name "Ingest Date"
	public int layout_version;			// Version of the database layout
	public boolean readonly;			// -true- if database is readonly
	public boolean trackcallgraph;		// -true- if database tracks callgraph information of executables

	public DatabaseInformation() {
		databasename = "Example Database";
		owner = "Example Owner";
		description = "A collection of functions for testing purposes";
		major = 0;		// A zero major version indicates no data has been inserted yet
		minor = 0;
		settings = 0;
		execats = null;
		functionTags = null;
		dateColumnName = null;
		layout_version = 0;
		readonly = false;
		trackcallgraph = true;
	}

	public void saveXml(Writer write) throws IOException {
		write.append("<info>\n");
		if (databasename != null)
			write.append(" <name>").append(databasename).append("</name>\n");
		else
			write.append(" <name/>\n");
		if (owner != null)
			write.append(" <owner>").append(owner).append("</owner>\n");
		else
			write.append(" <owner/>\n");
		if (description != null)
			write.append(" <description>").append(description).append("</description>\n");
		else
			write.append(" <description/>\n");
		write.append(" <major>").append(Short.toString(major)).append("</major>\n");
		write.append(" <minor>").append(Short.toString(minor)).append("</minor>\n");
		write.append(" <settings>0x").append(Integer.toHexString(settings)).append("</settings>\n");
		if (execats != null) {
			for (String cat : execats)
				write.append(" <execategory>").append(cat).append("</execategory>\n");
		}
		if (functionTags != null) {
			for (String tag : functionTags)
				write.append(" <functiontag>").append(tag).append("</functiontag>\n");
		}
		if (dateColumnName != null) {
			write.append(" <datename>").append(dateColumnName).append("</datename>\n");
		}
		if (readonly)
			write.append(" <readonly>true</readonly>\n");
		if (!trackcallgraph)
			write.append(" <trackcallgraph>false</trackcallgraph>\n");
		write.append(" <layout>").append(Integer.toString(layout_version)).append("</layout>\n");
		write.append("</info>\n");
	}

	public void restoreXml(XmlPullParser parser) {
		parser.start("info");
		parser.start("name");
		databasename = parser.end().getText();
		if (databasename.length() == 0)
			databasename = null;
		parser.start("owner");
		owner = parser.end().getText();
		if (owner.length() == 0)
			owner = null;
		parser.start("description");
		description = parser.end().getText();
		if (description.length() == 0)
			description = null;
		parser.start("major");
		major = (short) SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("minor");
		minor = (short) SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("settings");
		settings = SpecXmlUtils.decodeInt(parser.end().getText());
		readonly = false;
		trackcallgraph = true;
		layout_version = 0;
		execats = null;
		functionTags = null;
		dateColumnName = null;
		while (parser.peek().isStart()) {
			XmlElement el = parser.start();
			if (el.getName().equals("readonly"))
				readonly = SpecXmlUtils.decodeBoolean(parser.end().getText());
			else if (el.getName().equals("trackcallgraph"))
				trackcallgraph = SpecXmlUtils.decodeBoolean(parser.end().getText());
			else if (el.getName().equals("layout"))
				layout_version = SpecXmlUtils.decodeInt(parser.end().getText());
			else if (el.getName().equals("execategory")) {
				if (execats == null)
					execats = new ArrayList<String>();
				String cat = parser.end().getText();
				execats.add(cat);
			}
			else if (el.getName().equals("functiontag")) {
				if (functionTags == null)
					functionTags = new ArrayList<String>();
				String tag = parser.end().getText();
				functionTags.add(tag);
			}
			else if (el.getName().equals("datename")) {
				dateColumnName = parser.end().getText();
			}
		}
		parser.end();
	}

	@Override
	public boolean equals(Object obj) {
		// FIXME - missing hashcode method - is equals really used?
		if (true) {
			throw new AssertException(
				"DatabaseInformation.equals is used - should add hashcode method");
		}
		DatabaseInformation op2 = (DatabaseInformation) obj;
		if (!op2.databasename.equals(databasename))
			return false;
		if (op2.major != major)
			return false;
		if (op2.minor != minor)
			return false;
		if (op2.settings != settings)
			return false;
		if (op2.execats == null) {
			if (execats != null)
				return false;
		}
		else {
			if (execats == null)
				return false;
			if (op2.execats.size() != execats.size())
				return false;
			for (int i = 0; i < execats.size(); ++i) {
				if (!op2.execats.get(i).equals(execats.get(i)))
					return false;
			}
		}
		if (op2.functionTags == null) {
			if (functionTags != null)
				return false;
		}
		else {
			if (functionTags == null)
				return false;
			if (op2.functionTags.size() != functionTags.size())
				return false;
			for (int i = 0; i < functionTags.size(); ++i) {
				if (!op2.functionTags.get(i).equals(functionTags.get(i)))
					return false;
			}
		}
		if (op2.dateColumnName == null) {
			if (dateColumnName != null)
				return false;
		}
		else {
			if (dateColumnName == null)
				return false;
			if (!op2.dateColumnName.equals(dateColumnName))
				return false;
		}
		if (op2.layout_version != layout_version)
			return false;
		if (op2.readonly != readonly)
			return false;
		if (op2.trackcallgraph != trackcallgraph)
			return false;
		return true;
	}

	public int checkSignatureSettings(short maj, short min, int set) {
		if ((maj == 0) || (set == 0))
			return 3;		// No setting information
		if ((major == 0) || (settings == 0))
			return 4;	// This has no setting information
		if ((major != maj) || (settings != set))
			return 2;	// There is a setting mismatch, major version and settings must match
		if (minor == min)
			return 0;				// There is a complete settings match
		if (minor > min) {
			if (minor - min > 1)
				return 2;		// Settings mismatch (minor versions differ too much)
		}
		else {
			if (min - minor > 1)
				return 2;		// Settings mismatch
		}
		return 1;			// Only a minor difference in version and settings
	}
}
