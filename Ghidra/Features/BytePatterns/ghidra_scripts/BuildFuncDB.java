/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
//@category CodeAnalysis

import ghidra.app.analyzers.LibHashDB;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;

import java.io.*;

import org.xml.sax.*;

public class BuildFuncDB extends GhidraScript {

	@Override
	protected void run() throws Exception {

		//If the file is already there, it adds more function records to it. If not, it creates and populates the file.
		File dbFile =
			Application.getModuleDataSubDirectory("BytePatterns", "lib/db.xml").getFile(true);
		LibHashDB db = new LibHashDB();
		if (dbFile.exists()) {
			db.restoreXml(getParser(dbFile));
		}

		LibHashDB dbCurrent = new LibHashDB(this.currentProgram);
		db.mergeWith(dbCurrent);
		FileWriter fwrite = new FileWriter(dbFile);
		db.saveXml(fwrite);
		fwrite.close();
		return;
	}

	private static XmlPullParser getParser(File xmlfile) throws SAXException, IOException {
		ErrorHandler handler = new ErrorHandler() {
			@Override
			public void warning(SAXParseException exception) throws SAXException {
				throw exception;
			}

			@Override
			public void error(SAXParseException exception) throws SAXException {
				throw exception;
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				throw exception;
			}
		};

		XmlPullParser parser;
		parser = new NonThreadedXmlPullParserImpl(xmlfile, handler, false);
		return parser;
	}
}
