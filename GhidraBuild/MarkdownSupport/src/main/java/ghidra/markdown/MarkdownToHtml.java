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
package ghidra.markdown;

import java.io.*;
import java.util.List;
import java.util.Map;

import org.commonmark.Extension;
import org.commonmark.ext.footnotes.FootnotesExtension;
import org.commonmark.ext.heading.anchor.HeadingAnchorExtension;
import org.commonmark.node.Link;
import org.commonmark.node.Node;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.*;

/**
 * Program to convert a Markdown file to an HTML file
 */
public class MarkdownToHtml {

	/**
	 * Converts a Markdown file to an HTML file
	 * 
	 * @param args An array of 2 arguments: The path of the markdown file to convert, and the path
	 *   to save the new HTML file to
	 * @throws Exception If invalid arguments are passed in, or if there is an issue writing the
	 *   new HTML file
	 */
	public static void main(String[] args) throws Exception {

		// Validate input
		if (args.length != 2) {
			throw new Exception("Expected 2 arguments, got " + args.length);
		}
		if (!args[0].toLowerCase().endsWith(".md")) {
			throw new Exception("First argument doesn't not end with .md");
		}

		// Setup the CommonMark Library with the needed extension libraries
		List<Extension> extensions =
			List.of(HeadingAnchorExtension.create(), FootnotesExtension.create());
		Parser parser = Parser.builder().extensions(extensions).build();
		HtmlRenderer renderer = HtmlRenderer.builder()
				.extensions(extensions)
				.attributeProviderFactory(new LinkAttributeProvider())
				.build();

		// Create output directory (if necessary)
		File inFile = new File(args[0]).getCanonicalFile();
		File outFile = new File(args[1]).getCanonicalFile();
		if (!outFile.getParentFile().isDirectory() && !outFile.getParentFile().mkdirs()) {
			throw new Exception("Failed to create: " + outFile.getParent());
		}

		// Generate and write the HTML
		String html = renderer.render(parser.parseReader(new FileReader(inFile)));
		try (PrintWriter out = new PrintWriter(outFile)) {
			out.write(html);
		}
	}

	/**
	 * Class to help adjust links to Markdown files to instead become links to HTML files
	 */
	private static class LinkAttributeProvider
			implements AttributeProvider, AttributeProviderFactory {

		@Override
		public AttributeProvider create(AttributeProviderContext attributeProviderContext) {
			return new LinkAttributeProvider();
		}

		@Override
		public void setAttributes(Node node, String tagName, Map<String, String> attributes) {
			if (node instanceof Link) {
				String href = attributes.get("href");
				if (href != null && !href.startsWith("#") && href.toLowerCase().endsWith(".md")) {
					attributes.put("href", href.substring(0, href.length() - 2) + "html");
				}
			}
		}
	}
}
