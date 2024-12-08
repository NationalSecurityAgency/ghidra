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
package ghidra.features.bsim.query.protocol;

import java.io.*;
import java.util.Iterator;
import java.util.TreeSet;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.description.*;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlPullParser;

/**
 * Response to a request for specific executables and functions given by name.
 * Full ExecutableRecords and FunctionDescriptions are instantiated in this object's DescriptionManager
 *
 */
public class ResponseName extends QueryResponseRecord {

	public final DescriptionManager manage;		// Set of functions and executables matching the name request
	public boolean uniqueexecutable;		// True if query specified a unique executable
	public boolean printselfsig;
	public boolean printjustexe;

	public ResponseName() {
		super("responsename");
		manage = new DescriptionManager();
		uniqueexecutable = false;
		printselfsig = false;
		printjustexe = false;
	}

	@Override
	public DescriptionManager getDescriptionManager() {
		return manage;
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		if (uniqueexecutable)
			fwrite.append("<uniqueexe>true</uniqueexe>\n");
		else
			fwrite.append("<uniqueexe>false</uniqueexe>\n");
		if (printselfsig)
			fwrite.append("<printselfsig>true</printselfsig>\n");
		else
			fwrite.append("<printselfsig>false</printselfsig>\n");
		if (printjustexe)
			fwrite.append("<printjustexe>true</printjustexe>\n");
		else
			fwrite.append("<printjustexe>false</printjustexe>\n");
		manage.saveXml(fwrite);
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
			throws LSHException {
		uniqueexecutable = false;
		printselfsig = false;
		printjustexe = false;
		parser.start(name);
		if (parser.peek().getName().equals("uniqueexe")) {
			parser.start();
			uniqueexecutable = SpecXmlUtils.decodeBoolean(parser.end().getText());
		}
		if (parser.peek().getName().equals("printselfsig")) {
			parser.start();
			printselfsig = SpecXmlUtils.decodeBoolean(parser.end().getText());
		}
		if (parser.peek().getName().equals("printjustexe")) {
			parser.start();
			printjustexe = SpecXmlUtils.decodeBoolean(parser.end().getText());
		}
		manage.restoreXml(parser, vectorFactory);
		parser.end();
	}

	public void printRaw(PrintStream stream, LSHVectorFactory vectorFactory, int format) {
		if (!uniqueexecutable) {
			stream.println("Unable to resolve unique executable");
		}
		if ((!uniqueexecutable) || printjustexe) {
			TreeSet<ExecutableRecord> exeset = manage.getExecutableRecordSet();
			Iterator<ExecutableRecord> iter = exeset.iterator();
			while (iter.hasNext()) {
				String line = iter.next().printRaw();
				stream.println(line);
			}
			return;
		}
		ExecutableRecord lastexe = null;
		Iterator<FunctionDescription> iter = manage.listAllFunctions();
		while (iter.hasNext()) {
			FunctionDescription funcrec = iter.next();
			if (lastexe != funcrec.getExecutableRecord()) {
				lastexe = funcrec.getExecutableRecord();
				String line = lastexe.printRaw();
				stream.println(line);
			}
			stream.print("  ");
			if (printselfsig) {
				double val = 0.0;
				SignatureRecord srec = funcrec.getSignatureRecord();
				if (srec != null)
					val = vectorFactory.getSelfSignificance(srec.getLSHVector());
				stream.print(val);
				stream.print(' ');
			}
			String line = funcrec.printRaw();
			stream.println(line);
		}
	}

}
