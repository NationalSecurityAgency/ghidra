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
package mdemangler;

import ghidra.app.util.demangler.DemangledObject;

/**
 * This class is a derivation of MDBaseTestConfiguration (see javadoc there).  This
 *  class must choose the appropriate truth from MDMangBaseTest (new truths might
 *  need to be added there) and override the appropriate helper methods of
 *  MDBaseTestConfiguration.  This specific test configuration is for the purpose
 *  of driving the tests of MDMangGhidraTest.
 */
public class MDGhidraTestConfiguration extends MDBaseTestConfiguration {

	protected DemangledObject demangledObject;
	protected String demangledGhidraObject;
	protected DemangledObject demangledObjectCheck;

	public MDGhidraTestConfiguration(boolean quiet) {
		super(quiet);
		mdm = new MDMangGhidra();
	}

	@Override
	protected void setTruth(String mdtruth, String mstruth, String ghtruth, String ms2013truth) {
		if (ghtruth != null) {
			truth = ghtruth;
		}
		else {
			truth = mdtruth;
		}
	}

	@Override
	protected void doDemangleSymbol() throws Exception {
		try {
			//Set true in operational mode.
			demangItem = ((MDMangGhidra) mdm).demangle(mangled, false); // "false" is different
			demangled = demangItem.toString();
			demangledObject = ((MDMangGhidra) mdm).getObject();
		}
		catch (MDException e) {
			demangItem = null;
			demangled = "";
		}
	}

	@Override
	protected void doBasicTestsAndOutput() throws Exception {
		super.doBasicTestsAndOutput();
		if (demangledObject != null) {
			demangledGhidraObject = demangledObject.toString();
			outputInfo.append("demangl: " + demangledGhidraObject + "\n");
		}
		else {
			demangledGhidraObject = "";
			outputInfo.append("demangled: NO RESULT\n");
		}
//		For checking the original results, for comparison purposes, this code should probably
//		be calling the MicrosoftWineDemangler.
//		try {
//			GenericDemangledObject genericWineObject = WineDemangler.demangle(mangled);
//			if (genericWineObject == null) {
//				demangledObjectCheck = null;
//			}
//			demangledObjectCheck = DemangledObjectFactory.convert(genericWineObject);
//			Msg.info(this, "    check: " + demangledObjectCheck.toString());
//		}
//		catch (Exception ex) {
//			Msg.info(this, "GH_failed: " + ex.getMessage());
//			demangledObjectCheck = null;
//		}
	}

	@Override
	protected void doExtraProcCheck() throws Exception {
		if ((demangledObjectCheck != null) && (demangledObject != null)) {
			if (demangledObjectCheck.getClass() != demangledObject.getClass()) {
				outputInfo.append("ObjComp: notequal NEW: " + demangledObject.getClass().getName() +
					", OLD: " + demangledObjectCheck.getClass().getName() + "\n");
			}
			else {
				outputInfo.append("ObjComp: equal NEW: " + demangledObject.getClass().getName() +
					", OLD: " + demangledObjectCheck.getClass().getName() + "\n");
			}
		}
		else {
			if ((demangledObjectCheck == null) && (demangledObject == null)) {
				outputInfo.append("ObjComp: Not possible -- both null\n");
			}
			else if (demangledObjectCheck == null) {
				outputInfo.append("ObjComp: Not possible -- OLD null; NEW: " +
					demangledObject.getClass().getName() + "\n");
			}
			else {
				outputInfo.append("ObjComp: Not possible -- NEW null; OLD: " +
					demangledObjectCheck.getClass().getName() + "\n");
			}
		}
		if (ghidraTestStringCompare(outputInfo, demangled, demangledGhidraObject)) {
			outputInfo.append("RESULTS MATCH------******\n");
		}
		else {
			outputInfo.append("RESULTS MISMATCH------*********************************\n");
		}
	}

	private boolean ghidraTestStringCompare(StringBuilder outputInfoArg, String truthString,
			String ghidraString) {
		int ti = 0;
		int gi = 0;
		boolean pass = true;
		while (pass) {
			if (ti < truthString.length()) {
				if (gi < ghidraString.length()) {
					if (truthString.charAt(ti) == ghidraString.charAt(gi)) {
						ti++;
						gi++;
					}
					else if ((truthString.charAt(ti) == ' ') && (ghidraString.charAt(gi) == '_')) {
						ti++;
						gi++;
//						int ti_1 = ti + 1;
//						int tc = 0;
//						//skip any more spaces.
//						while ((ti_1 < truthString.length()) &&
//							((truthString.charAt(ti_1) == ' '))) {
//							ti_1++;
//						}
//						//count any underscores.
//						while ((ti_1 < truthString.length()) &&
//							((truthString.charAt(ti_1) == '_'))) {
//							tc++;
//							ti_1++;
//						}
//						//count any underscores.
//						int gi_1 = gi;
//						int gc = 0;
//						while ((gi_1 < ghidraString.length()) &&
//							((ghidraString.charAt(gi_1) == '_'))) {
//							gc++;
//							gi_1++;
//						}
//						if (tc <= gc) {
//							ti = ti_1;
//							gi = gi_1;
//						}
//						else {
//							pass = false;
//							break;
//						}
//ONE ATTEMPT
//						if (((ti + 1) < truthString.length()) &&
//							(truthString.charAt(ti + 1) != '_')) {
//							ti++;
//							gi++;
//						}
//						else {
//							ti++;
//						}
					}
					else if ((truthString.charAt(ti) == ':') && (ghidraString.charAt(gi) == ' ')) {
						ti++;
					}
					else if ((truthString.charAt(ti) == ' ') && (ghidraString.charAt(gi) != ' ')) {
						ti++;
					}
					else if ((truthString.charAt(ti) != ' ') && (ghidraString.charAt(gi) == ' ')) {
						gi++;
					}
					else {
						pass = false;
						outputInfoArg.append("truth[" + ti + "]: " + truthString.charAt(ti) +
							" ghidra[" + gi + "]: " + ghidraString.charAt(gi) + "\n");
					}
				}
				else {
					while (ti < truthString.length()) {
						if (truthString.charAt(ti) != ' ') {
							pass = false;
							outputInfoArg.append("early truth termination\n");
							break;
						}
						ti++;
					}
					break;
				}
			}
			else if (gi < ghidraString.length()) {
				while (gi < ghidraString.length()) {
					if (ghidraString.charAt(gi) != ' ') {
						pass = false;
						outputInfoArg.append("early testoutput termination\n");
						break;
					}
					gi++;
				}
				break;
			}
			else {
				break; //both out of characters, but pass = true;
			}
		}
		return pass;
	}
}
