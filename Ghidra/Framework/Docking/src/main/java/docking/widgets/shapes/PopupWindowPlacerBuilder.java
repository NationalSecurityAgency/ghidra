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
package docking.widgets.shapes;

import docking.widgets.shapes.PopupWindowPlacer.*;

/**
 * This class builds a PopWindowPlacer that can have subsequent PopWindowPlacers.
 * <p>
 * General categories of placers available are <B>edge</B> placers, <B>overlapped-corner</B>
 * placers, and a clean-up <B>assert</B> placer.  Additionally, there are <B>rotational</B> placers
 * that are composed of edge placers.
 * <p>
 * <BR>
 * <BR> 
 * 
 * <H1>Edge Placers</H1>
 *  
 * <p>
 * The <B>edge</B> placers are the leftEdge, rightEdge, topEdge, and bottomEdge methods that take
 * Location arguments that one can think of as "cells" for optimal placement, but which have some
 * flexibility in making the placement.  One such cell is the TOP Location of the rightEdge,
 * specified by <code>rightEdge(Location.TOP)</code>.  If the placement does not quite fit this
 * cell because the optimal placement extend above the top of the screen, the placement may be
 * shifted down by a  allowed amount so that it still fits.  If more than the allowed amount is
 * needed, the placement fails.
 * <p>
 * Each edge placer takes a variable number of Location arguments.  These arguments work in the
 * same way for each method, though some arguments are not valid for some edges; for instance,
 * <code>Location.TOP</code> is only valid for left and right edges.
 * <p>
 * 
 * <H2>Two or More Location Arguments</H2>
 * 
 * <p>
 * When two or more arguments are used, the first argument specifies the nominal placement cell
 * and the second argument specifies how far the solution is allowed to shift.  If a solution is
 * not found and if there are more than two arguments, another placement attempt is made where
 * the second argument specifies the nominal placement cell and the third argument specifies how
 * far the solution is allowed to shift. To specify a "no-shift" solution, one specifies the same
 * placement cell twice (e.g., <code>rightEdge(Location.TOP, Location.TOP)</code>).
 * <p>
 * 
 * <H2>One Location Argument</H2>
 * 
 * <p>
 * When one argument is used, the solution is the same as when two arguments are specified except
 * that the second argument is automatically set to the nearest neighboring cell.  Thus,
 * <code>rightEdge(Location.TOP)</code> is the same as
 * <code>rightEdge(Location.TOP, Location.CENTER)</code>.  When the single argument is
 * <code>Location.CENTER</code>, two attempts are built, the first being the BOTTOM or RIGHT cell
 * and the second being the TOP or LEFT cell.
 * <p>
 * 
 * <H2>No Arguments</H2>
 * 
 * <p>
 * When no arguments are specified, two arguments to the underlying placer are automatically set
 * to BOTTOM or RIGHT for the first and TOP or LEFT for the second.
 * <p>
 * 
 * <H2>Examples</H2>
 * 
 * <p>
 * Builds a placer that first attempts a placement at the bottom of the right edge with no
 * shift, then tries the top of the right edge with no shift, then top center with no shift:
 * <pre>
 *    PopupWindowPlacer placer =
 *        new PopupWindowPlacerBuilder()
 *            .rightEdge(Location.BOTTOM,Location.BOTTOM)
 *            .rightEdge(Location.TOP, Location.TOP)
 *            .topEdge(Location.CENTER, Location.CENTER)
 *            .build();</pre>
 * Builds a placer that attempts a placement on the right edge from bottom to top, followed by
 * the top edge from center to right, then center to left:
 * <pre>
 *    PopupWindowPlacer placer =
 *        new PopupWindowPlacerBuilder()
 *            .rightEdge()
 *            .topEdge(Location.CENTER);
 *            .build();</pre>
 * <p>
 * <BR>
 * <BR>
 * 
 * <H1>Rotational Placers</H1>
 * 
 * <p>
 * There are clockwise and counter-clockwise rotational placers that built up from edge placers.
 * These are:
 * <pre>
 *    rotateClockwise(Location major, Location minor)
 *    rotateCounterClockwise(Location major, Location minor)
 *    thenRotateClockwise()
 *    thenRotateCounterClockwise()</pre>
 * The first two of these take two Location arguments the specify the starting cell.  For instance,
 * <code>rotateClockwise(Location.BOTTOM, Location.RIGHT)</code>.  This specifies a set of edge
 * placers that attempt placement starting from the specified cell, and making attempt in a
 * clockwise fashion until the starting cell is revisited, at which time the attempt fails if a
 * viable placement has not been found.  The <code>rotateCounterClockwise</code> placer works the
 * same, but in a counter-clockwise fashion.  The <code>thenRotateClockwise</code> and
 * <code>thenRotateCounterClockwise</code> placers are the same as the previous two placers
 * except that they start at the "beginning" cell where the most previous placer had left off.  If
 * there was not a previous placer, then the BOTTOM RIGHT cell is chosen as the starting cell.
 * <p>
 * <BR>
 * <BR>
 * 
 * <H1>Overlapping Corner Placer</H1>
 * 
 * <p>
 * There is one corner placer, <code>leastOverlapCorner()</code>.  This placer tries to make a
 * placement at each of the corners of the context area and shifts into the context region as much
 * as necessary to fit the screen bounds.  The corner that overlaps the context area the least is
 * chosen as the solution placement corner.  In case of a tie (e.g., no overlap on some corners),
 * the placement order chosen in this preference order: bottom right, bottom left, top right, and
 * top left.  Unless ill-constructed (sized of context area, screen, and pop-up dimension), this
 * placer should always find a solution.
 * <p>
 * <BR>
 * <BR>
 * 
 * <H1>Assert Placer</H1>
 * 
 * <p>
 * The <code>throwsAssertException()</code> placer is available, which automatically throws an
 * AssertException.  This placer is only intended to be used by the client in such as case when
 * it is believed that a placement should have already been found, such as after the
 * <code>leastOverlapCorner()</code> placer.  This just throws an exception instead of returning
 * the <code>null</code> return value that would be returned from previous placement attempts.
 * <p>
 * <BR>
 * <BR>
 * 
 * <H1>Composite Placer</H1>
 * 
 * <p>
 * Builds a placer that first attempts a placement at the right edge from bottom to top, then
 * left edge from bottom to top, then top edge from right to left, then bottom edge from right to
 * left, followed by a least-overlap-corner solution, followed by a failure assert:
 * <pre>
 *    PopupWindowPlacer placer =
 *        new PopupWindowPlacerBuilder()
 *            .rightEdge()
 *            .leftEdge()
 *            .topEdge()
 *            .bottomEdge()
 *            .leastOverlapCorner()
 *            .throwsAssertException()
 *            .build();</pre>
 * <p>
 * Builds a placer that first attempts each of the four major corners in a specific order, with no
 * shifting, followed by an assertion failure:
 * <pre>
 *    PopupWindowPlacer placer =
 *        new PopupWindowPlacerBuilder()
 *            .rightEdge(Location.BOTTOM, Location.BOTTOM)
 *            .leftEdge(Location.TOP, Location.TOP)
 *            .rightEdge(Location.TOP, Location.TOP)
 *            .leftEdge(Location.BOTTOM, Location.BOTTOM)
 *            .throwsAssertException()
 *            .build();</pre>
 * <p>
 * Builds a placer that attempt to make a placement at the bottom right corner, first shifting up
 * to the center location then shifting left to the center location, then failing only with a
 * null return:
 * <pre>
 *    PopupWindowPlacer placer =
 *        new PopupWindowPlacerBuilder()
 *            .rightEdge(Location.BOTTOM)
 *            .bottomEdge(Location.RIGHT)
 *            .build();</pre>
 * <p>
 * Builds a placer that attempts a placement at the top, left corner, the tries to make a placement
 * in a clockwise fashion, followed by a failure assert:
 * <pre>
 *    PopupWindowPlacer placer =
 *        new PopupWindowPlacerBuilder()
 *            .topEdge(Location.LEFT, Location.LEFT)
 *            .thenRotateClockwise()
 *            .throwsAssertException()
 *            .build();</pre>
 *
 * @see PopupWindowPlacer
 */
public class PopupWindowPlacerBuilder {

	private PopupWindowPlacer head = null;
	private PopupWindowPlacer current = null;

	/**
	 * Builds the final PopupWindowPlacer.
	 * @return the PopupWindowPlacer
	 */
	public PopupWindowPlacer build() {
		return head;
	}

	private void add(PopupWindowPlacer next) {
		if (current == null) {
			current = next;
			head = current;
		}
		else {
			current.setNext(next);
			current = next;
		}
	}

	/**
	 * Set the next PopupWindowPlacer to be one that tries to make the placement at the right
	 * edge of the inner bounds (context) without exceeding outer bounds (screen), using
	 * an ordered, preferred placements on that edge.  Invalid values will error.
	 * @param minors the ordered, preferred placements on the edge. If not specified, goes from
	 * greater-valued end of the edge to the lesser-valued end of the edge.
	 * @return this builder
	 */
	public PopupWindowPlacerBuilder rightEdge(Location... minors) {
		return edge(Location.RIGHT, minors);
	}

	/**
	 * Set the next PopupWindowPlacer to be one that tries to make the placement at the left
	 * edge of the inner bounds (context) without exceeding outer bounds (screen), using
	 * an ordered, preferred placements on that edge.  Invalid values will error.
	 * @param minors the ordered, preferred placements on the edge. If not specified, goes from
	 * greater-valued end of the edge to the lesser-valued end of the edge.
	 * @return this builder
	 */
	public PopupWindowPlacerBuilder leftEdge(Location... minors) {
		return edge(Location.LEFT, minors);
	}

	/**
	 * Set the next PopupWindowPlacer to be one that tries to make the placement at the bottom
	 * edge of the inner bounds (context) without exceeding outer bounds (screen), using
	 * an ordered, preferred placements on that edge.  Invalid values will error.
	 * @param minors the ordered, preferred placements on the edge. If not specified, goes from
	 * greater-valued end of the edge to the lesser-valued end of the edge.
	 * @return this builder
	 */
	public PopupWindowPlacerBuilder bottomEdge(Location... minors) {
		return edge(Location.BOTTOM, minors);
	}

	/**
	 * Set the next PopupWindowPlacer to be one that tries to make the placement at the top
	 * edge of the inner bounds (context) without exceeding outer bounds (screen), using
	 * an ordered, preferred placements on that edge.  Invalid values will error.
	 * @param minors the ordered, preferred placements on the edge. If not specified, goes from
	 * greater-valued end of the edge to the lesser-valued end of the edge.
	 * @return this builder
	 */
	public PopupWindowPlacerBuilder topEdge(Location... minors) {
		return edge(Location.TOP, minors);
	}

	/**
	 * Set the next PopupWindowPlacer to be one that tries to make the placement on the major
	 * edge of the inner bounds (context) without exceeding outer bounds (screen), using
	 * an ordered, preferred placements on that edge.  Invalid values will error.
	 * @param major the major edge of the context area
	 * @param minors the ordered, preferred placements on the edge. If not specified, goes from
	 * greater-valued end of the edge to the lesser-valued end of the edge.
	 * @return this builder
	 */
	public PopupWindowPlacerBuilder edge(Location major, Location... minors) {
		if (minors.length > 3) {
			throw new IllegalArgumentException("Too many preferred Locations: " + minors);
		}
		for (Location minor : minors) {
			if (!major.validMinor(minor)) {
				throw new IllegalArgumentException(
					"Preferred Location " + minor + " is not valid for " + major + " edge.");
			}
		}

		if (minors.length == 0) {
			// We are defaulting this as greater to lesser
			if (major.isHorizontal()) {
				add(new EdgePopupPlacer(major, Location.BOTTOM, Location.TOP));
			}
			else {
				add(new EdgePopupPlacer(major, Location.RIGHT, Location.LEFT));
			}
		}
		else if (minors.length == 1) {
			if (minors[0] == Location.CENTER) {
				// Trying center to greater and then center to lesser.
				if (major.isHorizontal()) {
					add(new EdgePopupPlacer(major, minors[0], Location.BOTTOM));
					add(new EdgePopupPlacer(major, minors[0], Location.TOP));
				}
				else {
					add(new EdgePopupPlacer(major, minors[0], Location.RIGHT));
					add(new EdgePopupPlacer(major, minors[0], Location.LEFT));
				}
			}
			else {
				// Only looking from greater/lesser to the the center.
				add(new EdgePopupPlacer(major, minors[0], Location.CENTER));
			}
		}
		else { // Since we tested minors.length > 3 above, then we know we must have 2 or 3
			for (int i = 0; i < minors.length - 1; i++) {
				add(new EdgePopupPlacer(major, minors[i], minors[i + 1]));
			}
		}

		return this;
	}

	/**
	 * Set the next PopupWindowPlacer to be one that tries to make the placement by starting at
	 * the last-used {@code majorBegin} and {@code minorBegin} and continues clockwise
	 * to find a solution.  If there was no last-used location set, then BOTTOM, RIGHT is used.
	 * @return this builder
	 */
	public PopupWindowPlacerBuilder thenRotateClockwise() {
		if (current == null) {
			return rotateClockwise(Location.BOTTOM, Location.RIGHT);
		}
		return rotateClockwise(current.major, current.minorBegin);
	}

	/**
	 * Set the next PopupWindowPlacer to be one that tries to make the placement by starting at
	 * a point specified by {@code majorBegin} and {@code minorBegin} and continues
	 * clockwise to find a solution.
	 * @param majorBegin the major coordinate location of the starting point
	 * @param minorBegin the minor coordinate location of the starting point
	 * @return this builder
	 */
	public PopupWindowPlacerBuilder rotateClockwise(Location majorBegin, Location minorBegin) {
		Location major = majorBegin;
		Location minor = minorBegin;
		do {
			add(new EdgePopupPlacer(major, minor, major.clockwise()));
			minor = major;
			major = major.clockwise();
		}
		while (major != majorBegin);
		if (minor != minorBegin) {
			// Does remaining portion of initial edge, but repeats first location.
			// So if starting at BOTTOM CENTER, will repeat that location in the last partial edge
			add(new EdgePopupPlacer(major, minor, minorBegin));
		}
		return this;
	}

	/**
	 * Set the next PopupWindowPlacer to be one that tries to make the placement by starting at
	 * the last-used {@code majorBegin} and {@code minorBegin} and continues counter-clockwise
	 * to find a solution.  If there was no last-used location set, then RIGHT, BOTTOM is used.
	 * @return this builder
	 */
	public PopupWindowPlacerBuilder thenRotateCounterClockwise() {
		if (current == null) {
			return rotateCounterClockwise(Location.RIGHT, Location.BOTTOM);
		}
		return rotateCounterClockwise(current.major, current.minorBegin);
	}

	/**
	 * Set the next PopupWindowPlacer to be one that tries to make the placement by starting at
	 * a point specified by {@code majorBegin} and {@code minorBegin} and continues
	 * counter-clockwise to find a solution.
	 * @param majorBegin the major coordinate location of the starting point
	 * @param minorBegin the minor coordinate location of the starting point
	 * @return this builder
	 */
	public PopupWindowPlacerBuilder rotateCounterClockwise(Location majorBegin,
			Location minorBegin) {
		Location major = majorBegin;
		Location minor = minorBegin;
		do {
			add(new EdgePopupPlacer(major, minor, major.counterClockwise()));
			minor = major;
			major = major.counterClockwise();
		}
		while (major != majorBegin);
		if (minor != minorBegin) {
			// Does remaining portion of initial edge, but repeats first location.
			// So if starting at BOTTOM CENTER, will repeat that location in the last partial edge
			add(new EdgePopupPlacer(major, minor, minorBegin));
		}
		return this;
	}

	/**
	 * Set the next PopupWindowPlacer to be one that tries to make the placement that is
	 * allowed to overlap the inner bounds, but with the least overlap area.  Tie-breaker
	 * order is first in this order: Bottom Right, Bottom Left, Top Right, Top  Left.
	 * <p>
	 * Should never return null, except if using impractical parameters, such as using
	 * outer bounds that are smaller than inner bounds.
	 * @return this builder
	 */
	public PopupWindowPlacerBuilder leastOverlapCorner() {
		add(new LeastOverlapCornerPopupWindowPlacer());
		return this;
	}

	/**
	 * Set the next PopupWindowPlacer that throws an AssertException because no solution has
	 * been found by the time this placer is tried.  This is intended to be used when the coder
	 * has already guaranteed that there is a solution (i.e., the {@link #leastOverlapCorner()}
	 * placer has been used and the pop-up area will fit within the outer bounds).
	 * @return this builder
	 */
	public PopupWindowPlacerBuilder throwsAssertException() {
		add(new ThrowsAssertExceptionPlacer());
		return this;
	}

}
