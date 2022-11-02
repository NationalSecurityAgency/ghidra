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
/**
 * The Taint domain package
 * 
 * <p>
 * This package implements the domain of taint analysis. {@link TaintVec} models an array of bytes,
 * each having a {@link TaintSet}. A {@link TaintSet} is in turn made of several {@link TaintMarks}.
 * Each mark is a symbol with optional tags. We use the tags as a means of handling indirection, so
 * that we don't have to decide up front whether tainted offsets taint the values read and written
 * from memory. We allow them to be tainted, but add a tag to the mark, so they can be examined
 * and/or filtered by the user.
 * 
 * <p>
 * To facilitate storage and presentation of taint, we will need to implement some
 * (de)serialization. Rather than use Java's notion, we'll just implement toString and a static
 * parse method for sets and marks.
 * 
 * <p>
 * We recommend you read the documentation and source from the bottom up: {@link TaintMark},
 * {@link TaintSet}, {@link TaintVec}.
 */
package ghidra.taint.model;
