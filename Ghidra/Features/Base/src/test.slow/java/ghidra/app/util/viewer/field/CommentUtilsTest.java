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
package ghidra.app.util.viewer.field;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.WordLocation;

public class CommentUtilsTest extends AbstractGhidraHeadlessIntegrationTest {

	@Test
	public void testGetCommentAnnotations_NoAnnotation() {

		String comment = "This is a comment";
		List<WordLocation> annotations = CommentUtils.getCommentAnnotations(comment);
		assertTrue(annotations.isEmpty());
	}

	@Test
	public void testGetCommentAnnotations_PlainAnnotation() {

		String comment = "This is an {@symbol symbolName}";
		List<WordLocation> annotations = CommentUtils.getCommentAnnotations(comment);
		assertEquals(1, annotations.size());
		WordLocation word = annotations.get(0);
		assertEquals("{@symbol symbolName}", word.getWord());
	}

	@Test
	public void testGetCommentAnnotations_QuotedAnnotation() {

		String comment = "This is an {@symbol \"symbolName\"}";
		List<WordLocation> annotations = CommentUtils.getCommentAnnotations(comment);
		assertEquals(1, annotations.size());
		WordLocation word = annotations.get(0);
		assertEquals("{@symbol \"symbolName\"}", word.getWord());
	}

	@Test
	public void testGetCommentAnnotations_QuotedAnnotation_WithEscapedQuotes() {

		String comment = "This is an {@symbol \"symbol\\\"Name\\\"\"}";
		List<WordLocation> annotations = CommentUtils.getCommentAnnotations(comment);
		assertEquals(1, annotations.size());
		WordLocation word = annotations.get(0);
		assertEquals("{@symbol \"symbol\\\"Name\\\"\"}", word.getWord());
	}

	@Test
	public void testGetCommentAnnotations_QuotedAnnotationWithBraces() {

		String comment = "This is an {@symbol \"symbol{Name}\"}";
		List<WordLocation> annotations = CommentUtils.getCommentAnnotations(comment);
		assertEquals(1, annotations.size());
		WordLocation word = annotations.get(0);
		assertEquals("{@symbol \"symbol{Name}\"}", word.getWord());
	}

	@Test
	public void testGetCommentAnnotations_UnquotedAnnotation_WithBraces() {

		// the second brace is ignored (if the first brace is part of the symbol name, then it
		// needs to be escaped or quoted
		String comment = "This is an {@symbol symbol{Name}}";
		List<WordLocation> annotations = CommentUtils.getCommentAnnotations(comment);
		assertEquals(1, annotations.size());
		WordLocation word = annotations.get(0);
		assertEquals("{@symbol symbol{Name}", word.getWord());
	}

	@Test
	public void testGetCommentAnnotations_UnquotedAnnotation_WithUnbalancedBraces() {

		// the second brace is ignored
		String comment = "This is an {@symbol symbolName}}";
		List<WordLocation> annotations = CommentUtils.getCommentAnnotations(comment);
		assertEquals(1, annotations.size());
		WordLocation word = annotations.get(0);
		assertEquals("{@symbol symbolName}", word.getWord());
	}

	@Test
	public void testGetCommentAnnotations_UnquotedAnnotation_WithEscapedBraces() {

		// escaped braces get ignored
		String comment = "This is an {@symbol symbol\\{Name\\}}";
		List<WordLocation> annotations = CommentUtils.getCommentAnnotations(comment);
		assertEquals(1, annotations.size());
		WordLocation word = annotations.get(0);
		assertEquals("{@symbol symbol\\{Name\\}}", word.getWord());
	}
}
