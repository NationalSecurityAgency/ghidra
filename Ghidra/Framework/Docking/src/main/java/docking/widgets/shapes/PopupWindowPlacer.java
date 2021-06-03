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

import java.awt.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.util.exception.AssertException;

/**
 * This class places a rectangle on the boundary of an inner bounds area, such that it is not
 * placed outside of an outer boundary.  It takes the concept of trying to make the placement at
 * the closest distance, but preferring certain sides or angles of approach in iterating a
 * solution. However, we reduce this concept down to a very simple form where iteration is not
 * needed because we are basing the algorithm on a geometric model that has explicit solutions
 * (for example, instead of picking a starting point around the perimeter and rotating
 * counter-clockwise to find a fit, or, for example, creating a grid of placements and choosing
 * the one that is closest but yet has preferences on one side or another).  From the geometric
 * model, we can, instead, calculate the first location that will fit with a preferred boundary
 * location, such as fit on the right side of the context area, near the bottom.  We could have
 * chosen to iterate through the areas in a counter-clockwise fashion, but by using a builder
 * model, we give the user more control of the order of choice.
 * For example, the user might first prefer the right side near the bottom, then the left side near
 * the bottom, followed by the top near the right, and then the bottom near the right.
 * <p>
 * This first drawing shows the overall context of the inner bounds within an outer bounds along
 * with a good placement and a bad placement that violates the outer bounds.
 * <pre>
 *
 *        +-----------------------------------------------+
 *        |                                        outer  |
 *        |                                               |
 *        |                                               |
 *        |      +------------------+                     |
 *        |      |       good       |                     |
 *        |      |     placement    |                     |
 *        |      |                  |                     |
 *        |      +------------------+---------+           |
 *        |                         |         |           |
 *        |                         |  inner  |           |
 *        |                         |         |           |
 *        |                         +---------+------------------+
 *        |                                   |       bad |      |
 *        |                                   |     placement    |
 *        +-----------------------------------+-----------+      |
 *                                            +------------------+
 *
 * </pre>
 *
 * The next two drawings show the LEFT and RIGHT edges with nominal locations of TOP, CENTER, and
 * BOTTOM placements and the TOP and BOTTOM edges with nominal location of LEFT, CENTER, and
 * RIGHT placements.  There are a total of eight of these locations ("cells") around the inner
 * bounds.
 * <pre>
 *
 *              LEFT                            RIGHT
 *        +---------------+               +---------------+
 *        |               |               |               |
 *        |      TOP      |               |      TOP      |
 *        |               |               |               |
 *        +---------------X---------------X---------------+
 *        |               |               |               |
 *        |    CENTER     X     inner     X    CENTER     |
 *        |               |               |               |
 *        +---------------X---------------X---------------+
 *        |               |               |               |
 *        |    BOTTOM     |               |    BOTTOM     |
 *        |               |               |               |
 *        +---------------+               +---------------+
 *
 *
 *        +---------------+---------------+---------------+
 *        |               |               |               |
 *        |     LEFT      |    CENTER     |     RIGHT     | TOP
 *        |               |               |               |
 *        +---------------X-------X-------X---------------+
 *                        |               |
 *                        |     inner     |
 *                        |               |
 *        +---------------X-------X-------X---------------+
 *        |               |               |               |
 *        |     LEFT      |    CENTER     |     RIGHT     | BOTTOM
 *        |               |               |               |
 *        +---------------+---------------+---------------+
 *
 * </pre>
 * <p>
 *
 * These cells are shown in their nominal placement locations (where they touch the inner bounds,
 * marked with an X).  However we will shift these locations by particular amounts so that these
 * locations still fit within the outer bounds.  For instance, if we allow the BOTTOM cell
 * on the LEFT edge to be shifted up far enough such that it fits the lower edge of the outer
 * bounds, we limit this shift if it reaches the nominal placement of another specified cell
 * (CENTER or TOP) on that edge.  If a solution is not found before the limit is reached, the
 * placement fails.
 * <p>
 * If the chosen cell is a CENTER cell, then it could shift up or down, depending on the
 * circumstances and the parameters applied.
 * <p>
 * These placements and shifts are controlled by specifying the <B>major</B> and <B>minorBegin</B>
 * and <B>minorEnd</B> {@link Location Locations}.  The major Location specifies the <B>edge</B>
 * for an {@link EdgePopupPlacer} and the minorBegin Location specifies the placement <B>cell</B>
 * on this edge and the minorEnds specifies the last cell (amount of shift allowed), starting
 * from the minorBegin Location.  For a CENTER minorBeing Location, the minorEnd cell may be
 * any of the three allowed Locations on that major edge as well as null, representing that a
 * shift is allowed in either direction.  When the minorEnd Location is set to the minorBegin
 * Location, then no shift is permitted.
 * <p>
 * Combinations of these placement attempts can be put together to create more complex strategies.
 * See {@link PopupWindowPlacerBuilder} for examples of these.
 * <p>
 * There are also {@link LeastOverlapCornerPopupWindowPlacer} and
 * {@link ThrowsAssertExceptionPlacer}, for instance, that do not follow the same cell scheme.
 * The first of these tries to make the placement at each of the corners of the inner
 * bounds, but shifts these placements to fit the outer bounds in such a way that the inner
 * bounds area may be occluded.  The placement on the corner which overlaps the least amount of
 * the inner bounds area is chosen.  The second of these placers automatically throws an
 * {@link AssertException}.  It is intended to be used in a builder model in which a sequence of
 * placement attempts are made until good solution is found or until a null value is returned.
 * This last placer, when chosen, serves as an assert condition, which is helpful
 * in circumstances where the developer believes such an assertion is not possible,
 * such as when allowing an overlapping placement solution.
 * 
 * @see PopupWindowPlacerBuilder
 */
public abstract class PopupWindowPlacer {

	protected Location major;
	protected Location minorBegin;
	protected Location minorEnd;

	private PopupWindowPlacer next = null;

	/**
	 * Constructor only for classes that do not use placement preferences
	 */
	public PopupWindowPlacer() {
		// Only for implementations that do not use placement preferences
	}

	/**
	 * Constructor only for classes that specify major edge and minor begin and end location
	 * on that edge.
	 * @param major edge
	 * @param minorBegin start location on edge
	 * @param minorEnd end location on edge
	 * 
	 * @see PopupWindowPlacerBuilder
	 */
	public PopupWindowPlacer(Location major, Location minorBegin, Location minorEnd) {
		if (major == Location.CENTER) {
			throw new IllegalArgumentException("Cannot use " + major + " for major edge.");
		}
		if (!major.validMinor(minorBegin)) {
			throw new IllegalArgumentException(
				"Invalid minor location for " + major + " edge: " + minorBegin);
		}
		if (!major.validMinor(minorEnd)) {
			throw new IllegalArgumentException(
				"Invalid minor location for " + major + " edge: " + minorEnd);
		}
		this.major = major;
		this.minorBegin = minorBegin;
		this.minorEnd = minorEnd;
	}

	void setNext(PopupWindowPlacer next) {
		this.next = next;
	}

	/**
	 * Returns the placement Rectangle of toBePlaced Dimension for this PopupWindowPlacer. If it
	 * cannot find a solution, it tries the  {@link #next} PopupWindowPlacer and so forth until
	 * there are no others available, upon which null is returned if there is no solution.
	 * @param toBePlaced the Dimension
	 * @param innerBounds the inner bounds Rectangle
	 * @param outerBounds the out bounds in which the final result must fit
	 * @return the placement Rectangle or null if extends outside the outerBounds
	 */
	public Rectangle getPlacement(Dimension toBePlaced, Rectangle innerBounds,
			Rectangle outerBounds) {
		Rectangle myPlacement = getMyPlacement(toBePlaced, innerBounds, outerBounds);
		//Msg.info(this, debugDump(myPlacement));
		if (myPlacement != null) {
			return myPlacement;
		}
		if (next != null) {
			return next.getPlacement(toBePlaced, innerBounds, outerBounds);
		}
		return null;
	}

	protected abstract Rectangle getMyPlacement(Dimension toBePlaced, Rectangle innerBounds,
			Rectangle outerBounds);

	/**
	 * Returns a Rectangle solution for the placement of a toBePlaced Dimension.
	 * <p>
	 * When dealing with solutions for the top or bottom edge, we are considering <B>vertical</B>
	 * to be the major axis with y/height values representing that axis, and <B>horizontal</B>
	 * to be the minor axis with x/width values representing that axis.  When dealing with
	 * solutions for the left and right edge, these major and minor axes are switched.
	 *
	 * @param result the new instance of the resulting class type to be returned
	 * @param toBePlaced the wrapped toBePlaced Dimension
	 * @param context the wrapped context Rectangle
	 * @param outer the wrapped outer boundsRectangle
	 * @return the resultant wrapped Rectangle
	 */
	protected PositionableRectangle getPlacement(PositionableRectangle result,
			PositionableDimension toBePlaced, PositionableRectangle context,
			PositionableRectangle outer) {

		// Test major axis edge
		int placementMajorCoordinate;
		if (major.isLesser()) {
			placementMajorCoordinate = getLesserLocation(context.getMajorCoordinate(),
				context.getMajorLength(), toBePlaced.getMajorLength());
			int shiftedPlacement =
				getLesserBoundedLocation(placementMajorCoordinate, outer.getMajorCoordinate());
			if (placementMajorCoordinate < shiftedPlacement) {
				return null; // no solution on edge
			}
		}
		else if (major.isGreater()) {
			placementMajorCoordinate = getGreaterLocation(context.getMajorCoordinate(),
				context.getMajorLength(), toBePlaced.getMajorLength());
			int shiftedPlacement = getGreaterBoundedLocation(placementMajorCoordinate,
				toBePlaced.getMajorLength(), outer.getMajorCoordinate(), outer.getMajorLength());
			if (placementMajorCoordinate > shiftedPlacement) {
				return null; // no solution on edge
			}
		}
		else {
			throw new AssertException("Should not get here.");
		}

		// Find placement on the edge using minor axis
		Integer placementMinorCoordinate =
			getPlacement(toBePlaced.getMinorLength(), context.getMinorCoordinate(),
				context.getMinorLength(), outer.getMinorCoordinate(), outer.getMinorLength());
		if (placementMinorCoordinate == null) {
			return null; // no solution on edge
		}

		result.set(placementMajorCoordinate, placementMinorCoordinate, toBePlaced);
		return result;
	}

	/**
	 * With all inputs on a line (one-dimensional), returns the placement for the minor axis.
	 * In other words, this algorithm is used for both conditions: the major axis being horizontal
	 * and the minor axis being vertical; the major axis being vertical, and the minor axis being
	 * horizontal.  These two situations are independent, but the same algorithm is used.
	 * <p>
	 * <B>Algorithm Design</B><p>
	 * Note: smaller values are up and bigger values are down, in the presentation below.
	 * <p>
	 * In trying to allay some confusion (yes it can be confusing), note that for any given major
	 * axis (say horizontal), this axis can portray values that are further right or further left.
	 * This is why the left edge and right edge are noted by horizontal axes values... one
	 * intersects the horizontal axis further to the left and the other intersects the axis
	 * further to the right.
	 * <p>
	 * The location of placements on the left or right edges, however are noted by vertical axis
	 * values, with TOP having a lesser value and bottom having a greater value.  These locations
	 * specified by the minor dimension, and are the "one dimension" that is the subject of this
	 * placement algorithm.
	 * <p>
	 * The scenario with top and bottom edge reverses the major dimension to be vertical and the
	 * minor dimension to be horizontal.
	 * <p>
	 * Keeping with the original right edge scenario begun above, we are trying to find a minor
	 * axis placement on the right (major) edge.  For this placement, one can refer to
	 * documentation elsewhere in this class, but essentially, we are trying to place a popup
	 * area against a context rectangle without exceeding the outer bounds (screen) rectangle.  But,
	 * again, we are only considering the placement against the right edge already chosen and only
	 * trying to fit in the vertical dimension against this edge.  Thus, this algorithm only needs
	 * values for this one dimension.  These are the length of the placement area in this one
	 * dimension, and both the location and lengths of the context and outer bounds rectangles
	 * for this one dimension.
	 * <p>
	 * The algorithm considers three main locations (cells) on this minor axis.  When the minor
	 * axis is vertical (which is our current scenario), they are TOP, CENTER, and BOTTOM.  When
	 * the minor axis is horizontal, they are LEFT, CENTER, and RIGHT.  These locations are
	 * nominal, but are also allowed to be shifted so that the placement fits within the outer
	 * bounds.  Thus, we have five key values, in which three have fixed relative placements
	 * (when using <B>positive</B> lengths):
	 * <pre>
	 *         <B>lesserLocation</B> (nominal placement on TOP or LEFT)
	 *               &le;
	 *         <B>centerLocation</B> (nominal placement such that the center of the context rectangle
	 *                          and the center of the popup area align with each other)
	 *               &le;
	 *         <B>greaterLocation</B> (nominal placement on BOTTOM or RIGHT)
	 * </pre>
	 * and these two can be found at various placements amongst the other three:
	 * <pre>
	 *         <B>lesserBoundedLocation &ge; lesserLocation</B> (lesserLocation shifted so TOP or
	 *             LEFT fits outer bounds)
	 *         <B>greaterBoundedLocation &le; greaterLocation</B> (lesserLocation shifted BOTTOM or
	 *             RIGHT fits outer bounds)
	 * </pre>
	 * Note that with an ill-constructed scenario, as shown here, we return <B>no solution</B>:
	 * <pre>
	 *         <B>greaterBoundedLocation</B>
	 *                   &lt;
	 *         <B>lesserBoundedLocation</B>
	 * </pre>
	 * Given a better-constructed scenario, the <B>lesserBoundedLocation</B> and
	 * <B>greaterBoundedLocation</B> values can fall between the other three values at the following
	 * possible locations:
	 * <pre>
	 *         <B>lesserLocation</B>
	 *             <B>&rarr;</B> <B>lesserBoundedLocation</B> (&ge; <B>lesserLocation</B>)
	 *             <B>&rarr;</B> <B>greaterBoundedLocation</B> (&le; <B>greaterLocation</B>)
	 *         <B>centerLocation</B>
	 *             <B>&rarr;</B> <B>lesserBoundedLocation</B> (&ge; <B>lesserLocation</B>)
	 *             <B>&rarr;</B> <B>greaterBoundedLocation</B> (&le; <B>greaterLocation</B>)
	 *         <B>greaterLocation</B>
	 * </pre>
	 * These layout possibilities can be broken down into three possibilities...
	 * <pre>
	 *         <B>lesserLocation</B>
	 *             <B>&rarr;</B> <B>lesserBoundedLocation</B> (&ge; <B>lesserLocation</B>)
	 *             <B>&rarr;</B> <B>greaterBoundedLocation</B>
	 *         <B>centerLocation</B>
	 *         <B>greaterLocation</B>
	 *         ----------
	 *         if start is LESSER
	 *             if end is LESSER and lesserBoundedLocation != lesserLocation
	 *                 no solution
	 *             else
	 *                 solution is lesserBoundedLocation
	 *         else
	 *             if end is LESSER
	 *                 solution is greaterBoundedLocation
	 *             else
	 *                 no solution
	 * </pre>
	 *  or
	 * <pre>
	 *         <B>lesserLocation</B>
	 *             <B>&rarr;</B> <B>lesserBoundedLocation</B> (&ge; <B>lesserLocation</B>)
	 *         <B>centerLocation</B>
	 *             <B>&rarr;</B> <B>greaterBoundedLocation</B> (&le; <B>greaterLocation</B>)
	 *         <B>greaterLocation</B>
	 *         ----------
	 *         if start is GREATER
	 *             if end is GREATER and greaterBoundedLocation != greaterLocation
	 *                 no solution
	 *             else
	 *                 solution is greaterBoundedLocation
	 *         else if start is LESSER
	 *             if end is LESSER and lesserBoundedLocation != lesserLocation
	 *                 no solution
	 *             else
	 *                 solution is lesserBoundedLocation
	 *         else
	 *             solution is centerLocation
	 * </pre>
	 *  or
	 * <pre>
	 *         <B>lesserLocation</B>
	 *         <B>centerLocation</B>
	 *             <B>&rarr;</B> <B>lesserBoundedLocation</B>
	 *             <B>&rarr;</B> <B>greaterBoundedLocation</B> (&le; <B>greaterLocation</B>)
	 *         <B>greaterLocation</B>
	 *         ----------
	 *         if start is GREATER
	 *             if end is GREATER and greaterBoundedLocation != greaterLocation
	 *                 no solution
	 *             else
	 *                 solution is greaterBoundedLocation
	 *         else
	 *             if end is GREATER
	 *                 solution is lesserBoundedLocation
	 *             else
	 *                 no solution
	 * </pre>
	 * The algorithm breaks down into these scenarios and presents the solution as required.
	 * @param placementLength the length of the placement Dimension on the line
	 * @param contextLocation location of the context Rectangle on the line
	 * @param contextLength the length of the context Rectangle Dimension on the line
	 * @param boundLocation location of the outer bounds Rectangle on the line
	 * @param boundLength  the length of the outer bounds Rectangle Dimension on the line
	 * @return the resultant location on the line
	 */
	private Integer getPlacement(int placementLength, int contextLocation, int contextLength,
			int boundLocation, int boundLength) {
		int lesserLocation = getLesserLocation(contextLocation, contextLength, placementLength);
		int lesserBoundedLocation = getLesserBoundedLocation(lesserLocation, boundLocation);
		int greaterLocation = getGreaterLocation(contextLocation, contextLength, placementLength);
		int greaterBoundedLocation =
			getGreaterBoundedLocation(greaterLocation, placementLength, boundLocation, boundLength);

		if (greaterBoundedLocation < lesserBoundedLocation) {
			return null; // no solution
		}

		int centerLocation = getCenterLocation(contextLocation, contextLength, placementLength);

		if (greaterBoundedLocation < centerLocation) {
			return getSolutionWhenGreaterBoundedLessThanCenter(lesserLocation,
				lesserBoundedLocation, greaterBoundedLocation);
		}

		if (lesserBoundedLocation > centerLocation) {
			return getSolutionWhenLesserBoundedGreaterThanCenter(lesserBoundedLocation,
				greaterBoundedLocation, greaterLocation);
		}

		return getSolutionWhenCenterBounded(lesserLocation, lesserBoundedLocation, centerLocation,
			greaterBoundedLocation, greaterLocation);
	}

	private Integer getSolutionWhenGreaterBoundedLessThanCenter(int lesserLocation,
			int lesserBoundedLocation, int greaterBoundedLocation) {
		if (minorBegin.isLesser()) {
			if (minorEnd.isLesser() && lesserLocation != lesserBoundedLocation) {
				return null; // no solution
			}
			return lesserBoundedLocation;
		}
		if (minorEnd.isLesser()) {
			return greaterBoundedLocation;
		}
		return null; // no solution
	}

	private Integer getSolutionWhenLesserBoundedGreaterThanCenter(int lesserBoundedLocation,
			int greaterBoundedLocation, int greaterLocation) {
		if (minorBegin.isGreater()) {
			if (minorEnd.isGreater() && greaterLocation != greaterBoundedLocation) {
				return null; // no solution
			}
			return greaterBoundedLocation;
		}
		if (minorEnd.isGreater()) {
			return lesserBoundedLocation;
		}
		return null; // no solution
	}

	private Integer getSolutionWhenCenterBounded(int lesserLocation, int lesserBoundedLocation,
			int centerLocation, int greaterBoundedLocation, int greaterLocation) {
		if (minorBegin.isGreater()) {
			if (minorEnd.isGreater() && greaterLocation != greaterBoundedLocation) {
				return null; // no solution
			}
			return greaterBoundedLocation;
		}
		else if (minorBegin.isLesser()) {
			if (minorEnd.isLesser() && lesserLocation != lesserBoundedLocation) {
				return null; // no solution
			}
			return lesserBoundedLocation;
		}
		return centerLocation;
	}

	/**
	 * With all inputs on a line (one-dimensional), returns a location that is shifted enough from
	 * the placementLocation such that the greater end of bounds specified by boundLocation
	 * is not exceeded (i.e., the new location is not bigger than {@code #boundLocation}).
	 *
	 * @param placementLocation starting location that gets shifted
	 * @param placementLength the length of the to-be-placed dimension on the (one-dimensional)
	 *        line
	 * @param boundLocation the bounds on the line that must not be exceeded to the greater side
	 * @param boundLength the length of the outer bounds dimension on the (one-dimensional) line
	 * @return the shifted result
	 */
	protected int getGreaterBoundedLocation(int placementLocation, int placementLength,
			int boundLocation, int boundLength) {
		return Integer.min(placementLocation, boundLocation + boundLength - placementLength);
	}

	/**
	 * With all inputs on a line (one-dimensional), returns a location that is shifted enough from
	 * the placementLocation such that the lesser end of bounds specified by boundLocation
	 * is not exceeded (i.e., the new location is not smaller than boundLocation).
	 *
	 * @param placementLocation starting location that gets shifted
	 * @param boundLocation the bounds on the line that must not be exceeded to the lesser side
	 * @return the shifted result
	 */
	protected int getLesserBoundedLocation(int placementLocation, int boundLocation) {
		return Integer.max(placementLocation, boundLocation);
	}

	/**
	 * Returns the placement on a line (one-dimensional) on the greater end of the context area.
	 *
	 * @param contextLocation the context location on the line
	 * @param contextLength the context length on the line
	 * @param placementLength the length of the to-be-place dimension on that line
	 * @return the resultant placement on the line
	 */
	protected int getGreaterLocation(int contextLocation, int contextLength, int placementLength) {
		return contextLocation + contextLength;
	}

	/**
	 * Returns the placement on a line (one-dimensional) on the lesser end of the context area.
	 *
	 * @param contextLocation the context location on the line
	 * @param contextLength the context length on the line
	 * @param placementLength the length of the to-be-place dimension on that line
	 * @return the resultant placement on the line
	 */
	protected int getLesserLocation(int contextLocation, int contextLength, int placementLength) {
		return contextLocation - placementLength;
	}

	/**
	 * Determines the placementLocation such that the midpoint of the context and the midpoint
	 * of the placement are at the same point.  Location and Length can either be an x value and
	 * width or a y value and height.
	 *
	 * @param contextLocation the x or y value of the context, depending on if we are doing the
	 *        horizontal or vertical midpoint
	 * @param contextLength the corresponding width (if dealing with x/horizontal midpoint) or
	 *        height (if dealing with y/vertical midpoint)
	 * @param placementLength the corresponding height or width of the placement
	 * @return the placement location (again x or y value)
	 */
	protected int getCenterLocation(int contextLocation, int contextLength, int placementLength) {
		return contextLocation + (contextLength - placementLength) / 2;
	}

	/** Dumps some debug output about the current class and its placement result*/
	@SuppressWarnings("unused")
	private String debugDump(Rectangle placement) {
		return String.format("%s: %s(%s,%s)... placement %s", getClass().getSimpleName(), major,
			minorBegin, minorEnd, dumpRectangle(placement));
	}

	/** Dumps a simple Rectangle output */
	private String dumpRectangle(Rectangle r) {
		if (r == null) {
			return "null";
		}
		return String.format("[x=%d,y=%d,width=%d,height=%d]", r.x, r.y, r.width, r.height);
	}

	@Override
	public String toString() {
		String name = getClass().getSimpleName();
		String specificName = name.replace(PopupWindowPlacer.class.getSimpleName(), "");
		String[] words = StringUtils.splitByCharacterTypeCamelCase(specificName);
		return StringUtils.join(words, ' ');
	}

//==================================================================================================
// Placer Classes
//==================================================================================================

	/**
	 * Placer that attempts a placement on the <code>major</code> edge of the inner bounds, with
	 * <code>minorBegin</code> specifying the preferred cell location at which to start the
	 * placement attempt and <code>minorEnd</code> specifying that limit on the amount of shift
	 * that is made in an attempt to make the placement fit within the outer bounds.  The inner
	 * bounds is not allowed to be violated.
	 */
	static class EdgePopupPlacer extends PopupWindowPlacer {
		public EdgePopupPlacer(Location major, Location minorBegin, Location minorEnd) {
			super(major, minorBegin, minorEnd);
		}

		@Override
		public Rectangle getMyPlacement(Dimension toBePlaced, Rectangle context, Rectangle outer) {
			if (major.isHorizontal()) {
				return getPlacement(new HorizontalMajorRectangle(),
					new HorizontalMajorDimension(toBePlaced), new HorizontalMajorRectangle(context),
					new HorizontalMajorRectangle(outer));
			}
			return getPlacement(new VerticalMajorRectangle(),
				new VerticalMajorDimension(toBePlaced), new VerticalMajorRectangle(context),
				new VerticalMajorRectangle(outer));
		}
	}

	/**
	 * Placer picks corner with toBePlaced as the least overlap with innerBounds. In the case of a
	 * tie, the tie-breaker is first in this order: Bottom Right, Bottom Left, Top Right, Top  Left.
	 */
	static class LeastOverlapCornerPopupWindowPlacer extends PopupWindowPlacer {
		public LeastOverlapCornerPopupWindowPlacer() {
			super();
		}

		@Override
		public Rectangle getMyPlacement(Dimension toBePlaced, Rectangle context, Rectangle outer) {

			Rectangle bestRectangle = null;
			int bestArea = Integer.MAX_VALUE;

			Rectangle rectangle;
			Rectangle intersection;
			int area;

			int top = getLesserLocation(context.y, context.height, toBePlaced.height);
			int bottom = getGreaterLocation(context.y, context.height, toBePlaced.height);
			int left = getLesserLocation(context.x, context.width, toBePlaced.width);
			int right = getGreaterLocation(context.x, context.width, toBePlaced.width);

			int topShifted = getLesserBoundedLocation(top, outer.y);
			int bottomShifted =
				getGreaterBoundedLocation(bottom, toBePlaced.height, outer.y, outer.height);
			int leftShifted = getLesserBoundedLocation(left, outer.x);
			int rightShifted =
				getGreaterBoundedLocation(right, toBePlaced.width, outer.x, outer.width);

			if (bottomShifted < topShifted || rightShifted < leftShifted) {
				return null; // no solution fits within outer bounds
			}

			// Bottom Right
			rectangle = new Rectangle(new Point(rightShifted, bottomShifted), toBePlaced);
			intersection = rectangle.intersection(context);
			area = intersection.width * intersection.height;
			if (area < bestArea) {
				bestArea = area;
				bestRectangle = rectangle;
			}

			// Bottom Left
			rectangle = new Rectangle(new Point(leftShifted, bottomShifted), toBePlaced);
			intersection = rectangle.intersection(context);
			area = intersection.width * intersection.height;
			if (area < bestArea) {
				bestArea = area;
				bestRectangle = rectangle;
			}

			// Top Right
			rectangle = new Rectangle(new Point(rightShifted, topShifted), toBePlaced);
			intersection = rectangle.intersection(context);
			area = intersection.width * intersection.height;
			if (area < bestArea) {
				bestArea = area;
				bestRectangle = rectangle;
			}

			// Top Left
			rectangle = new Rectangle(new Point(leftShifted, topShifted), toBePlaced);
			intersection = rectangle.intersection(context);
			area = intersection.width * intersection.height;
			if (area < bestArea) {
				bestArea = area;
				bestRectangle = rectangle;
			}

			return bestRectangle;
		}
	}

	/**
	 * Set the next PopupWindowPlacer that throws an AssertException because no solution has
	 * been found by the time this placer is tried.  This is intended to be used when the client
	 * has already guaranteed that there is a solution (i.e., this placer is been used and the
	 * pop-up area will fit within the outer bounds).
	 */
	static class ThrowsAssertExceptionPlacer extends PopupWindowPlacer {
		@Override
		public Rectangle getMyPlacement(Dimension toBePlaced, Rectangle innerBounds,
				Rectangle outerBounds) {
			throw new AssertException("Unexpected popup placement error.");
		}
	}

//==================================================================================================
// Size and Shape Classes
//==================================================================================================

	private static abstract class PositionableDimension extends Dimension {

		public PositionableDimension(Dimension dimension) {
			super(dimension);
		}

		abstract int getMajorLength();

		abstract void setMajorLength(int length);

		abstract int getMinorLength();

		abstract void setMinorLength(int length);
	}

	private static class HorizontalMajorDimension extends PositionableDimension {

		public HorizontalMajorDimension(Dimension dimension) {
			super(dimension);
		}

		@Override
		int getMajorLength() {
			return this.width;
		}

		@Override
		void setMajorLength(int length) {
			this.width = length;
		}

		@Override
		int getMinorLength() {
			return this.height;
		}

		@Override
		void setMinorLength(int length) {
			this.height = length;
		}
	}

	private static class VerticalMajorDimension extends PositionableDimension {

		public VerticalMajorDimension(Dimension dimension) {
			super(dimension);
		}

		@Override
		int getMajorLength() {
			return this.height;
		}

		@Override
		void setMajorLength(int length) {
			this.height = length;
		}

		@Override
		int getMinorLength() {
			return this.width;
		}

		@Override
		void setMinorLength(int length) {
			this.width = length;
		}
	}

	private static abstract class PositionableRectangle extends Rectangle {

		PositionableRectangle() {
			super();
		}

		public PositionableRectangle(Rectangle rectangle) {
			super(rectangle);
		}

		public void set(int majorCoordinate, int minorCoordinate, PositionableDimension dimension) {
			setMajorCoordinate(majorCoordinate);
			setMinorCoordinate(minorCoordinate);
			setSize(dimension);
		}

		abstract int getMajorCoordinate();

		abstract void setMajorCoordinate(int coordinate);

		abstract int getMinorCoordinate();

		abstract void setMinorCoordinate(int coordinate);

		abstract int getMajorLength();

		abstract void setMajorLength(int length);

		abstract int getMinorLength();

		abstract void setMinorLength(int length);
	}

	private static class HorizontalMajorRectangle extends PositionableRectangle {

		HorizontalMajorRectangle() {
			super();
		}

		public HorizontalMajorRectangle(Rectangle rectangle) {
			super(rectangle);
		}

		@Override
		int getMajorCoordinate() {
			return this.x;
		}

		@Override
		void setMajorCoordinate(int coordinate) {
			this.x = coordinate;
		}

		@Override
		int getMinorCoordinate() {
			return this.y;
		}

		@Override
		void setMinorCoordinate(int coordinate) {
			this.y = coordinate;
		}

		@Override
		int getMajorLength() {
			return this.width;
		}

		@Override
		void setMajorLength(int length) {
			this.width = length;
		}

		@Override
		int getMinorLength() {
			return this.height;
		}

		@Override
		void setMinorLength(int length) {
			this.height = length;
		}
	}

	private static class VerticalMajorRectangle extends PositionableRectangle {

		VerticalMajorRectangle() {
			super();
		}

		public VerticalMajorRectangle(Rectangle rectangle) {
			super(rectangle);
		}

		@Override
		int getMajorCoordinate() {
			return this.y;
		}

		@Override
		void setMajorCoordinate(int coordinate) {
			this.y = coordinate;
		}

		@Override
		int getMinorCoordinate() {
			return this.x;
		}

		@Override
		void setMinorCoordinate(int coordinate) {
			this.x = coordinate;
		}

		@Override
		int getMajorLength() {
			return this.height;
		}

		@Override
		void setMajorLength(int length) {
			this.height = length;
		}

		@Override
		int getMinorLength() {
			return this.width;
		}

		@Override
		void setMinorLength(int length) {
			this.width = length;
		}
	}

}
