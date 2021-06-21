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
package help;

import static org.junit.Assert.*;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.help.HelpSet;

import org.junit.Test;

import help.validator.LinkDatabase;
import help.validator.location.*;
import help.validator.model.*;

public class OverlayHelpTreeTest {

	@Test
	public void testSourceTOCFileThatDependsUponPreBuiltHelp() {
		//
		// We want to make sure the overlay tree will properly resolve help TOC items being
		// built from TOC_Source.xml files when that file uses <TOCREF> items that are defined
		// in a help <TOCITEM> that lives inside of a pre-built jar file.
		//
		/*

		 	Example makeup we will create:

			  	PreBuild_TOC.xml

			  		<tocitem id="root" target="fake">
			  			<tocitem id="child_1" target="fake" />
			  		</tocitem>


			 	TOC_Source.xml

			 		<tocref id="root">
			 			<tocref="child_1">
			 				<tocdef id="child_2" target="fake" />
			 			</tocref>
			 		</tocref>

		 */

		TOCItemExternal root = externalItem("root");
		TOCItemExternal child_1 = externalItem(root, "child_1");

		Path tocSourceFile = Paths.get("/fake/path_2/TOC_Source.xml");
		String root_ID = root.getIDAttribute();
		TOCItemReference root_ref = tocref(root_ID, tocSourceFile);

		String child_1_ID = child_1.getIDAttribute();
		TOCItemReference child_1_ref = tocref(root_ref, child_1_ID, tocSourceFile);

		TOCItemDefinition child_2 = tocdef(child_1_ref, "child_2", tocSourceFile);

		TOCItemProviderTestStub tocProvider = new TOCItemProviderTestStub();
		tocProvider.addExternal(root);
		tocProvider.addExternal(child_1);
		tocProvider.addDefinition(child_2);

		TOCSpyWriter spy = printOverlayTree(tocProvider, tocSourceFile);

		assertNodeCount(spy, 3);
		assertOrder(spy, 1, root);
		assertOrder(spy, 2, child_1);
		assertOrder(spy, 3, child_2);
	}

	@Test
	public void testSourceTOCFileThatDependsAnotherTOCSourceFile() {

		/*

		 The first source file defines attributes that the second file references.

		 Example makeup we will create:

		  	TOC_Source.xml

		  		<tocdef id="root" target="fake">
		  			<tocdef id="child_1" target="fake" />
		  		</tocdef>


		 	Another TOC_Source.xml

		 		<tocref id="root">
		 			<tocref="child_1">
		 				<tocdef id="child_2" target="fake" />
		 			</tocref>
		 		</tocref>

		*/

		Path toc_1 = Paths.get("/fake/path_1/TOC_Source.xml");
		TOCItemDefinition root = tocdef("root", toc_1);
		TOCItemDefinition child_1 = tocdef(root, "child_1", toc_1);

		Path toc_2 = Paths.get("/fake/path_2/TOC_Source.xml");
		String root_ID = root.getIDAttribute();
		String child_1_ID = child_1.getIDAttribute();

		TOCItemReference root_ref = tocref(root_ID, toc_2);
		TOCItemReference child_1_ref = tocref(root_ref, child_1_ID, toc_2);
		TOCItemDefinition child_2 = tocdef(child_1_ref, "child_2", toc_2);

		TOCItemProviderTestStub tocProvider = new TOCItemProviderTestStub();
		tocProvider.addDefinition(root);
		tocProvider.addDefinition(child_1);
		tocProvider.addDefinition(child_2);// in the second TOC file

		TOCSpyWriter spy = printOverlayTree(tocProvider, toc_2);

		assertNodeCount(spy, 3);
		assertOrder(spy, 1, root);
		assertOrder(spy, 2, child_1);
		assertOrder(spy, 3, child_2);
	}

	@Test
	public void testSourceTOCFileThatDependsUponPreBuiltHelp_MultiplePreBuiltInputs() {
		//
		// We want to make sure the overlay tree will properly resolve help TOC items being
		// built from TOC_Source.xml files when that file uses <TOCREF> items that are defined
		// in a help <TOCITEM> that lives inside of multiple pre-built jar files.
		//
		/*

		 	Example makeup we will create:

			  	PreBuild_TOC.xml

			  		<tocitem id="root" target="fake">
			  			<tocitem id="child_1" target="fake">
			  				<tocitem="prebuilt_a_child" target="fake" />
			  			</tocitem>
			  		</tocitem>

				Another PreBuild_TOC.xml

			  		<tocitem id="root" target="fake">
			  			<tocitem id="child_1" target="fake">
			  				<tocitem="prebuilt_b_child" target="fake" />
			  			</tocitem>
			  		</tocitem>


			 	TOC_Source.xml

			 		<tocref id="root">
			 			<tocref="child_1">
			 				<tocdef id="child_2" target="fake" />
			 			</tocref>
			 		</tocref>

		 */

		TOCItemExternal root_a = externalItem("root");
		TOCItemExternal child_1_a = externalItem(root_a, "child_1");
		TOCItemExternal prebuilt_a_child = externalItem(child_1_a, "prebuilt_a_child");

		// note: same ID values, since they represent the same nodes, but from different TOC files
		TOCItemExternal root_b = externalItem(null, "root");
		TOCItemExternal child_1_b = externalItem(root_b, "child_1");
		TOCItemExternal prebuilt_b_child = externalItem(child_1_b, "prebuilt_b_child");

		Path tocSourceFile = Paths.get("/fake/path_2/TOC_Source.xml");
		String root_ID = root_a.getIDAttribute();
		TOCItemReference root_ref = tocref(root_ID, tocSourceFile);

		String child_1_ID = child_1_a.getIDAttribute();
		TOCItemReference child_1_ref = tocref(root_ref, child_1_ID, tocSourceFile);
		TOCItemDefinition child_2 = tocdef(child_1_ref, "child_2", tocSourceFile);

		TOCItemProviderTestStub tocProvider = new TOCItemProviderTestStub();
		tocProvider.addExternal(root_a);
		tocProvider.addExternal(root_b);
		tocProvider.addExternal(child_1_a);
		tocProvider.addExternal(child_1_b);
		tocProvider.addExternal(prebuilt_a_child);
		tocProvider.addExternal(prebuilt_b_child);
		tocProvider.addDefinition(child_2);

		TOCSpyWriter spy = printOverlayTree(tocProvider, tocSourceFile);

		assertNodeCount(spy, 3);
		assertOrder(spy, 1, root_a);// could also be root_b, same ID
		assertOrder(spy, 2, child_1_a);// could also be child_1_b, same ID
		assertOrder(spy, 3, child_2);

		// note: prebuilt_a_child and prebuilt_b_child don't get output, since they do not have
		//       the same TOC file ID as the help file being processed (in other words, they don't
		//       live in the TOC_Source.xml being processes, so they are not part of the output).
	}

	@Test
	public void testSourceTOCFileThatHasNodeWithSameTextAttributeAsOneOfItsExternalModluleDependencies() {

		/*

		 The first source file defines attributes that the second file references.   Both files
		 will have multiple nodes that coincidentally share 'text' attribute values.

		 Note: the 'id' attributes have to be unique; the 'text' attributes do not have to be unique

		 Example makeup we will create:

		  	PreBuild_TOC.xml

		  		<tocitem id="root" target="fake">
		  			<tocitem id="child_1_1" text="Child 1" target="fake" />
		  		</tocitem>

			Another PreBuild_TOC.xml

		  		<tocitem id="root" target="fake">
		  			<tocitem id="child_2_1" text=Child 1" target="fake" />
		  			<tocitem id="child_2_2" text=Child 2" target="fake" />
		  		</tocitem>


		 	Another TOC_Source.xml

		 		<tocref id="root">
		 			<tocref="child_1_1">
		 				<tocdef id="child_2_1a" text="Child 1a" target="fake" />
		 			</tocref>
		 			<tocdef id="child_3_2" text="Child 2" target="fake" />
		 		</tocref>

		*/

		TOCItemExternal root_a = externalItem("root");
		TOCItemExternal child_1_1 = externalItem(root_a, "child_1_1", "Child 1");

		// note: same ID values, since they represent the same nodes, but from different TOC files
		TOCItemExternal root_b = externalItem(null, "root");
		TOCItemExternal child_2_1 = externalItem(root_b, "child_2_1", "Child 1");
		TOCItemExternal child_2_2 = externalItem(root_b, "child_2_2", "Child 2");

		Path toc = Paths.get("/fake/path_2/TOC_Source.xml");
		String root_ID = root_a.getIDAttribute();
		String child_1_ID = child_1_1.getIDAttribute();

		TOCItemReference root_ref = tocref(root_ID, toc);
		TOCItemReference child_1_ref = tocref(root_ref, child_1_ID, toc);
		TOCItemDefinition child_2_1a = tocdef(child_1_ref, "child_2_1a", "Child 1a", toc);
		TOCItemDefinition child_3_2 = tocdef(root_ref, "child_3_2", "Child 2", toc);

		TOCItemProviderTestStub tocProvider = new TOCItemProviderTestStub();
		tocProvider.addExternal(root_a);
		tocProvider.addExternal(child_1_1);
		tocProvider.addExternal(root_b);
		tocProvider.addExternal(child_2_1);
		tocProvider.addExternal(child_2_2);
		tocProvider.addDefinition(child_2_1a); // in the first external TOC file
		tocProvider.addDefinition(child_3_2);

		TOCSpyWriter spy = printOverlayTree(tocProvider, toc);

		assertNodeCount(spy, 4);
		assertOrder(spy, 1, root_a);
		assertOrder(spy, 2, child_1_1);
		assertOrder(spy, 3, child_2_1a);
		assertOrder(spy, 4, child_3_2);

		// note: prebuilt_a_child and prebuilt_b_child don't get output, since they do not have
		//       the same TOC file ID as the help file being processed (in other words, they don't
		//       live in the TOC_Source.xml being processes, so they are not part of the output).
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private TOCSpyWriter printOverlayTree(TOCItemProviderTestStub tocItemProvider, Path tocFile) {

		//
		// Create a test version of the LinkDatabase for the overlay tree, with test versions of
		// it's required TOC input file and HelpModuleLocation
		//
		GhidraTOCFileDummy toc = new GhidraTOCFileDummy(tocFile);
		OverlayHelpModuleLocationTestStub location = new OverlayHelpModuleLocationTestStub(toc);
		LinkDatabaseTestStub db = new LinkDatabaseTestStub(location);

		// This is the class we are testing!!
		OverlayHelpTree overlayHelpTree = new OverlayHelpTree(tocItemProvider, db);

		TOCSpyWriter spy = new TOCSpyWriter();
		String TOCID = tocFile.toUri().toString();
		overlayHelpTree.printTreeForID(spy, TOCID);

		System.out.println(spy.toString());

		return spy;
	}

	private TOCItemDefinition tocdef(String ID, Path tocSourceFile) {
		return tocdef(null, ID, tocSourceFile);
	}

	private TOCItemDefinition tocdef(TOCItem parent, String ID, Path tocSourceFile) {
		return tocdef(parent, ID, ID, tocSourceFile);
	}

	private TOCItemDefinition tocdef(TOCItem parent, String ID, String text, Path tocSourceFile) {
		String target = "fake";
		String sort = "";
		int line = 1;
		return new TOCItemDefinition(parent, tocSourceFile, ID, text, target, sort, line);
	}

	private TOCItemReference tocref(String referenceID, Path tocSourceFile) {
		return tocref(null, referenceID, tocSourceFile);
	}

	private TOCItemReference tocref(TOCItem parent, String referenceID, Path tocSourceFile) {
		return new TOCItemReference(parent, tocSourceFile, referenceID, 1);
	}

	private TOCItemExternal externalItem(String ID) {
		return externalItem(null, ID);
	}

	private TOCItemExternal externalItem(TOCItem parent, String ID) {
		return externalItem(parent, ID, ID);
	}

	private TOCItemExternal externalItem(TOCItem parent, String ID, String text) {
		Path tocFile = Paths.get("/fake/path_1/PreBuild_TOC.xml");
		String target = "fake";
		String sort = "";
		int line = 1;
		return new TOCItemExternal(parent, tocFile, ID, text, target, sort, line);
	}

	private void assertOrder(TOCSpyWriter spy, int ordinal, TOCItem item) {
		String ID = spy.getItem(ordinal - 1 /* make an index */);
		assertEquals("Did not find TOC item at expected ordinal: " + ordinal, item.getIDAttribute(),
			ID);
	}

	private void assertNodeCount(TOCSpyWriter spy, int count) {
		assertEquals("Did not get exactly one node per TOC item input", count, spy.getItemCount());
	}

	private class TOCSpyWriter extends PrintWriter {

		private StringWriter stringWriter;

		private List<String> tocItems = new ArrayList<>();

		public TOCSpyWriter() {
			super(new StringWriter(), true);
			stringWriter = ((StringWriter) out);
		}

		String getItem(int position) {
			return tocItems.get(position);
		}

		int getItemCount() {
			return tocItems.size();
		}

		@Override
		public void println(String s) {
			super.println(s);

			s = s.trim();
			if (!s.startsWith("<tocitem")) {
				return;
			}

			storeDisplayAttribute(s);
		}

		private void storeDisplayAttribute(String s) {
			// create a pattern to pull out the display string
			Pattern p = Pattern.compile(".*toc_id=\"(.*)\".*");
			Matcher matcher = p.matcher(s.trim());

			if (!matcher.matches()) {
				return;// not a TOC item
			}

			String value = matcher.group(1);
			tocItems.add(value);
		}

		@Override
		public String toString() {
			return stringWriter.getBuffer().toString();
		}
	}

	private class TOCItemProviderTestStub implements TOCItemProvider {

		Map<String, TOCItemExternal> externals = new HashMap<>();
		Map<String, TOCItemDefinition> definitions = new HashMap<>();

		void addExternal(TOCItemExternal item) {
			String ID = item.getIDAttribute();
			externals.put(ID, item);
		}

		void addDefinition(TOCItemDefinition item) {
			String ID = item.getIDAttribute();
			definitions.put(ID, item);
		}

		@Override
		public Map<String, TOCItemExternal> getExternalTocItemsById() {
			return externals;
		}

		@Override
		public Map<String, TOCItemDefinition> getTocDefinitionsByID() {
			return definitions;
		}

	}

	private class LinkDatabaseTestStub extends LinkDatabase {

		public LinkDatabaseTestStub(HelpModuleLocation loc) {
			super(HelpModuleCollection.fromHelpLocations(Collections.singleton(loc)));
		}

		@Override
		public String getIDForLink(String target) {
			return "test_ID_" + target;
		}
	}

	private class OverlayHelpModuleLocationTestStub extends HelpModuleLocationTestDouble {

		OverlayHelpModuleLocationTestStub(GhidraTOCFileDummy toc) {
			super(Paths.get("/fake/help"));
			this.sourceTOCFile = toc;
		}

		@Override
		protected void loadHelpTopics() {
			// no! ...don't really go to the filesystem
		}

		@Override
		public GhidraTOCFile loadSourceTOCFile() {
			return null;// we set this in the constructor
		}

		@Override
		public HelpSet loadHelpSet() {
			return null;
		}

		@Override
		public boolean isHelpInputSource() {
			return true;
		}

	}

	private class GhidraTOCFileDummy extends GhidraTOCFileTestDouble {

		public GhidraTOCFileDummy(Path path) {
			super(path);
		}
	}
}
