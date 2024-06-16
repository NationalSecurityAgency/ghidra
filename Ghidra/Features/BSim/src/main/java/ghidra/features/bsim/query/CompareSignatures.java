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

// Read in a set of precomputed signature files, generate a similarity score for each pair of functions
// listed in the files, if the similarity exceeds a threshold, print out a line to a file named "output"
import java.io.*;
import java.text.NumberFormat;
import java.util.Iterator;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;

import generic.lsh.vector.*;
import ghidra.features.bsim.query.description.*;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;

public class CompareSignatures {

	private DescriptionManager manager;
	private LSHVectorFactory vectorFactory;

	public CompareSignatures(LSHVectorFactory vFactory) {
		manager = new DescriptionManager();
		vectorFactory = vFactory;
	}

	private boolean isFileSignatures(File file) {
		if (file == null) return false;
		try {
			BufferedReader in = new BufferedReader(new FileReader(file));
			String line = in.readLine();
			in.close();
			if (line == null) return false;
			if (line.contains("<description>")) return true;
		}
		catch (FileNotFoundException e) {
			return false;
		}
		catch (IOException e) {
			return false;
		}
		return false;
	}
	
	private void readFiles(File directory) {
		ErrorHandler handler = SpecXmlUtils.getXmlHandler();
		File[] filelist = directory.listFiles();
		for (File element : filelist) {
			if (isFileSignatures(element)) {
				try {
					XmlPullParser parser = new NonThreadedXmlPullParserImpl(element,handler,false);
					manager.restoreXml(parser,vectorFactory);
				}
				catch (SAXException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (LSHException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		
	}
	
	private void printResultRow(PrintStream out,double sim,double signif,FunctionDescription func1,FunctionDescription func2) {
		NumberFormat nf = NumberFormat.getInstance();
		nf.setMaximumFractionDigits(2);
		nf.setMinimumFractionDigits(2);
		out.print(nf.format(sim));
		out.print("  ");
		out.print(nf.format(signif));
		out.print("  ");
		ExecutableRecord exerec = func1.getExecutableRecord();
		out.print(exerec.getNameExec());
		out.print(':');
		out.print(func1.getFunctionName());
		out.print("  ");
		exerec = func2.getExecutableRecord();
		out.print(exerec.getNameExec());
		out.print(':');
		out.println(func2.getFunctionName());
	}
	
	private void compareSignatures(PrintStream out,double simthresh,double signifthresh) {
		Iterator<FunctionDescription> iter1,iter2;
		VectorCompare veccompare = new VectorCompare();
		iter1 = manager.listAllFunctions();
		while(iter1.hasNext()) {
			FunctionDescription func1 = iter1.next();
			LSHVector vec1 = func1.getSignatureRecord().getLSHVector();
			iter2 = manager.listFunctionsAfter(func1);
			while(iter2.hasNext()) {
				FunctionDescription func2 = iter2.next();
				LSHVector vec2 = func2.getSignatureRecord().getLSHVector();
				double res = vec1.compare(vec2,veccompare);
				if (res > simthresh) {
					double signif = vectorFactory.calculateSignificance(veccompare);
					if (signif > signifthresh)
						printResultRow(out,res,signif,func1,func2);
				}
			}
		}
	}
	
	
	public void run(String[] args) {
		if ((args==null)||(args.length<1)) {
			System.out.println("Require signature directory path");
		}
		File directory = new File(args[0]);
		
		double simthresh = 0.7;				// Threshold for similarity
		double signifthresh = 4.0;			// Threshold for significance (close to size of function)
		
		readFiles(directory);
		try {
			PrintStream out;
			if (args.length > 1) {
				File outfile = new File(args[1]);
				out = new PrintStream(new FileOutputStream(outfile));
				compareSignatures(out,simthresh,signifthresh);
				out.close();
			}
			else {
				compareSignatures(System.out,simthresh,signifthresh);
			}
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		LSHVectorFactory vFactory = new WeightedLSHCosineVectorFactory();
		// TODO: We need to load a weight file here
		CompareSignatures comp = new CompareSignatures(vFactory);
		comp.run(args);
	}
}
