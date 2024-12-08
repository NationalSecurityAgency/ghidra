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

import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.LSHException;
import ghidra.xml.XmlPullParser;

/**
 * Scan a description XML file and for each <fdesc> tag, parse it, build the FunctionDescription
 * object and call handleFunction
 *
 */
public abstract class FunctionDescriptionMapper {
	protected int recnum;					// Index of current FunctionDescription being processed
	
	public abstract void handleExecutable(ExecutableRecord erec) throws IOException, InterruptedException;
	
	public abstract void handleFunction(FunctionDescription fdesc,int rnum) throws IOException, InterruptedException;
	
	public void processFile(XmlPullParser parser,LSHVectorFactory vectorFactory) throws IOException,
			InterruptedException, LSHException {
		recnum = 0;
        
        DescriptionManager dmanage = null;
		parser.start("description");
		while(parser.peek().isStart()) {
			parser.start("execlist");
			dmanage = new DescriptionManager();		// Allocate per executable
			ExecutableRecord erec = ExecutableRecord.restoreXml(parser, dmanage);
			handleExecutable(erec);
			while(parser.peek().isStart()) {
				FunctionDescription fdesc = FunctionDescription.restoreXml(parser, vectorFactory, dmanage, erec);
				handleFunction(fdesc,recnum);
				dmanage.clearFunctions();		// Free up memory
				recnum += 1;					// Count the record
			}
			parser.end();
		}
		parser.end();
	}
}
