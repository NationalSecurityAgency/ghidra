# Ghidra's Coding Standards
Ver 2.0 - 20261104

## Introduction
The purpose of this document is to record the Ghidra team's accepted rules for code formatting,
naming conventions, code complexity, and other best practices. Many of the rules listed in this
document are not universal absolutes and many blur into areas of personal preferences. The purpose
of these types of rules is not to definitely state that one way is better than another, but that we
are consistent throughout the team.

Most of these rules came from one or more of the listed references at the end of this document. Many
of these rules were listed in just about every guide. Where they disagreed, we generally went with
the majority. Some rules seem arbitrary as to the actual value used, but that a value was needed
seemed universal. For example, just about every reference stated a maximum character line length. We
think all were either 80 or 100. So everyone seems to think it is important to have some limit, but
they don't agree to the actual number.

### Most Important Rules of All
* Any of the rules or suggestions in this document can be broken, but you must document why breaking
  the rule makes the code better.
* Program for people, not machines. The primary goal of your development efforts should be that your
  code is easy for other people to understand.

## Naming Conventions

### General Naming Rules
* Names for classes, interfaces, methods, parameters, instance variables and long-lived local
  variables should not contain abbreviations or acronyms except for well known ones (the
  abbreviation is more commonly used than the full name) like URL and HTML.

  The following exceptions are allowed (The list can be expanded with majority approval):

  * Utils - can be used as a suffix for the name of a class of static utility methods (e.g.,
    `StringUtils`)

* If an abbreviation or acronym is used, only the first letter should be capitalized. (Unless it is
  the beginning of a method or variable name, in which case the first letter is also lower case.)

  For example, use `fooUrl`, not `fooURL`.

### Package Naming
* Package names should start with `ghidra.<module group>.<module name>`. (e.g.,
  `ghidra.framework.docking`.)
* Package names should be all lower case, preferably one word and no abbreviations.

### Class Naming
* Class names should be nouns.
* Class names should use upper CamelCase where the first letter of each word is capitalized.

  Examples: `Table`, `FoldingTable`, `WoodTable`

* Classes that extend other classes should use the base class name as a base and prepend it with
  what is more specific about the extended class.

  For example, if the base class is `Truck`, the subclasses would have names like `DumpTruck`,
  `DeliveryTruck`, or `FlyingTruck`.

* The design pattern of an interface with one or more implementations should use the following
  naming conventions:
  * `Foo` - The interface should be named the fundamental thing.
  * `AbstractFoo` - An abstract implementation intended to be used as the base of a hierarchy of
    classes.
  * `DefaultFoo` - A "default" implementation that would be appropriate for the majority of use 
    cases.
  * `{descriptive}Foo` - Other implementations should describe what makes them unique.
* The design pattern for using an *abstract base class* without a corresponding interface should use
  the following naming conventions:
  * `Foo` - The abstract base class should be named the fundamental thing. EXCEPTION: if the 
    abstract base class does not represent a "fundamental thing" whose type will be referred to in 
    other code as parameters, return types, etc., then the class should be named `AbstractFoo`.
  * `{descriptive}Foo` - subclasses that provide different flavors of `Foo`.
* Test class names should end with "Test" (e.g., `FooTest`).
* Test doubles or stub objects should use the following naming rules:
  * `DummyFoo` - a stub that returns empty or null values because they are irrelevant to the test.
  * `SpyFoo` - may provide values to the environment, but also records statistics.
  * `MockFoo` - provides values to the environment and usually has some form of expectations.
  * `FakeFoo` - replaces real functionality with a simplified version (like replacing database 
    access with in-memory data).

### Interface Naming
* Interface names should be nouns, or adjectives ending with "able" such as `Runnable` or
  `Serializable`.
* Interface names should use upper CamelCase where the first letter of each word is capitalized.

### Method Naming
* Method names should use lower CamelCase where the first letter of each word is capitalized except
  for the first word.
* Method names should generally be verbs or other descriptions of actions.
* Specific naming conventions:
  * Methods that access a class's attributes should start with "get" or "set".
  * Methods that return a boolean should start with "is". Sometimes "has", "can", or "should" are
    more appropriate.
  * Methods that look something up should start with "find".
* Methods that return a value should be named based on what they return. Void methods should be
  named based on what they do.

  ```java
  public Foo buildFoo() {     // returns a Foo so method name is based on Foo
      ...
  }
  public int getSize() {      // returns a primitive, which is the size, so name is based on "size"
      ...
  }
  public void startServer() { // doesn't return anything so name it based on what it does
      ...
  }
  public boolean installHandler(Handler handler) { // even though it returns a boolean, it's not about returning
      ...                                          // a boolean, so name it based on what it does
  }
  ```

### Instance Variable Naming
* Instance Variable names should use lower CamelCase where the first letter of each word is
  capitalized except for the first word.

### Local Variable and Parameter Naming
* Local Variable names should use lower CamelCase where the first letter of each word is capitalized
  except for the first word.
* Variable names should be proportional in length to their scope.
  * Names that live throughout large blocks or methods should have very descriptive names and avoid
    abbreviations.
  * Names that exist in small blocks can use short or abbreviated names.
  * Names that exist in tiny blocks can use one letter names (e.g., lambdas).
* Variable names should generally have the same name as their class (e.g., `Person person` or 
  `Button button`).
  * If for some reason, this rule doesn't seem to fit, then that is a strong indication that the
    type is badly named.
  * Some variables have a role. These variables can often be named "{role}Type". For example, 
    `Button openButton` or `Point startPoint, endPoint`.
* Collections should be named the plural form of the type without the collection type name. For
  example, use `List<Dog> dogs`, not `List<Dog> dogList`.

### Enum Naming
* Enum class names should be like any other class (UpperCamelCase).
* Enum value names should be all upper case.

  ```java
  public enum AnalyzerStatus {
  	ENABLED, DELAYED, DISABLED
  }
  ```

### Loop Counters
* Use of `i`, `j`, `k`, etc. is acceptable as generic loop counters, unless a more descriptive name
  would greatly enhance the readability.

### Constants (static final fields)
* Constants should be all upper case with words separated by "_" (underscore char).

  Examples: `MAXIMUM_VELOCITY` or `DEFAULT_COLOR`

### Generic Types
* Generic type names should be named in one of two styles:
  * A single Capital Letter, optionally followed by a single number (e.g., `T`, `X`, `V`, `T2`)
    * `T` is used most often for single parameter types.
    * `R` is commonly used for return type.
    * `K,V` is commonly used for key,value types.
  * A name in the form used for classes followed by the capital letter T (e.g., `ActionT`, `RowT`,
    `ColumnT`). Try to avoid using this full name form unless it greatly enhances readability.

### Utility Classes
* Utility class names should end in "Utils".

## Source File Structure

### File Organization
* A Java File should be organized in the following order:
  * Header
  * Package statement
  * Import statements
  * Class Javadocs
  * Class declaration
  * Static variables
  * Instance variables
  * Static factory methods
  * Constructors
  * Methods
  * Private classes
* Local variables should be declared when first needed and not at the top of the method and should
  be initialized as close to the declaration as possible (preferably at the same time).
* Overloaded methods should be next to each other.
* Modifiers should appear in the following order:
  * access modifier (public/private/protected)
  * abstract
  * static
  * final
  * transient
  * volatile
  * default
  * synchronized
  * native
  * strictfp

## Formatting
Most of these are handled by the Eclipse formatter and are here to document the Ghidra formatting
style. The Eclipse formatter can be found in the `eclipse/` directory of a Ghidr release or source 
repository.

### Line Length
* Java code will have a character limit of 100 characters per line.

### Indenting
* New blocks are indented using a tab character (the tab should be 4 spaces wide).
* Line continuation should be indented the same as a new block.

### Special Formatting
* If special formatting is required to make code readable, you may surround the statement or code
  block with the Eclipse formatter tags. For example,

  ```java
  public String toString() {
  	//@formatter:off
  	return "{\n" +
  		"\tname: " + name + ",\n" +
  		"\tmodelColumn" + modelIndex + ",\n" +
  		"\tviewColumn: " + viewIndex + ",\n" +
  		"\tconstraints: " +
  			CollectionUtils.collect(applicableConstraints, c -> c.asString()) +"\n" +
  	"}";
  	//@formatter:on
  }
  ```

* Do not use empty end-of-line comments "//" to trick Eclipse into not formatting the line.

### Braces
* Braces should always be used where optional.
* Braces should follow the Kernighan and Ritchie style for nonempty blocks and block-like
  structures.
  * No line break before the opening brace.
  * Line break after the opening brace.
  * Line break before the closing brace.
  * Line break after the closing brace.
* Empty blocks should look as follows.

  ```java
  void doNothing() {
  	// comment as to why we are doing nothing
  }
  ```

### White Space
* A single blank line should be used to separate the following sections:
  * Copyright notice
  * Package statement
  * Import section
  * Class declarations
  * Methods
  * Constructors
* A single blank line should be used:
  * Between statements as needed to break code into logical sections.
  * Between import statements as needed to break into logical groups.
  * Between fields as needed to break into logical groups.
  * Between the Javadoc description and the Javadoc tag section.
* A single space should be used:
  * To separate keywords from neighboring opening or closing brackets and braces.
  * Before and after all binary operators.
  * After a // that starts a comment.
  * Before a // that starts an end of line comment.
  * After semicolons separating parts of a "for" loop.

### Variable Assignment
* Each variable should be declared on its own line.

  ```java
  Bad:
  	int i,j;

  Good:
  	int i;
  	int j;
  ```

## Comments

### Javadoc
* Javadoc blocks are normally of the form

  ```java
  /**
   * Some description with normal
   * wrapping.
   */
  ```

* Javadoc paragraphs should be separated by a single line containing only `<p>` line (starting with 
  an aligned *)
* When referencing other methods, use links (e.g., `{@link #method(type1, type2, ...)}` or 
  `{@link Classname#method(type1, type2, ...)}`).
* Block tags should never appear without a description.
* Descriptions in block tags should not end in a period, unless followed by another sentence.
* Block tags that are used should appear in the following order:
  * `@param`
  * `@return`
  * `@throws`
  * `@see`
  * `@deprecated`
* The Javadoc block should begin with a brief summary fragment. This fragment should be a noun
  phrase or a verb phrase and not a complete sentence. However, the fragment is capitalized and
  punctuated as if it were a complete sentence.

  For example, do

  ```java
  /**
   * Sets the warning level for the messaging system.
   */
  ```

  not

  ```java
  /**
   * This method sets the warning level for the messaging system.
   */
  ```

* Javadoc should be present for every non-private class/interface/record/method with the following
  exceptions:
  * Methods that override a super method and declare `@Override`.
  * JUnit test methods (although inline comments within the method body may be helpful)

### Code Comments
* Block comments are indented at the same level as the surrounding code.
* Block comments should be preceded by a blank line unless it is the first line of the block.
* Block comments should be one of the following forms:

  ```java
  /*
   * This is
   * nice.
   */

  // I like this
  // also.
  ```

* Any empty code block should have a comment so that the reader will know it was intentional. Also,
  the comment should not be something like "// empty" or "don't care", but instead should state why
  it is empty or why you don't care.
* Comments should indicate the 'why' you are doing something, not just 'what' you are doing. The
  code tells us what it is doing. Comments should not be pseudo code.
* Prefer creating a descriptive method to using a block comment. So if you feel that a block comment
  is needed to explain the next block of code, then it probably would be better off moved to a
  method with a name that says what the code does.
* Use of comments in code should be minimized by making the code self-documenting by appropriate
  name choices and an explicit logical structure.
* Tricky code should not be commented. Instead, it should be rewritten.

## Complexity

### Method Size
* Avoid long methods.
  * Methods should perform one clearly defined task.
  * Methods should generally fit on one page (approximately 30 lines).

### Method Complexity
* A method should be completely understandable (what, how, why) in about 30 seconds.
* Method Complexity should be kept low, according to the following scale:
  * 0-5: The method is *probably* fine
  * 6-10: The method is questionable; seek to simplify
  * 11+: OMG! Unacceptable!

  Calculating Complexity:

  * Start with one.
  * Add one for each of the following.
    * Returns: Each return other than a simple early guard condition or the last statement in the
      method.
    * Selection: if, else if, case, default.
    * Loops: for, while, do-while, break, and continue.
    * Operators: `&&`, `||`, `?`
    * Exceptions: catch, finally, throw.
* Methods should avoid deep nesting.
  * 2 or less - good
  * 3 or 4 - questionable
  * 5 or more - unacceptable
* Methods and constructors should avoid large numbers of parameters.
  * 3 or less - good
  * 4 or 5 - questionable
  * 6 or 7 - bad, should consider redesign
  * 8 or more - unacceptable
* All blocks of code in a method should be at the same level of abstraction:

  ```java
  // example of mixed levels:
  void doDailyChores() {
  	dust();
  	vacuum();
  	mopFloor();
  	addDirtyClothesToWashingMachine();
  	placeDetergentInWashingMachine();
  	closeWashingMachineDoor();
  	startWashingMachine();
  	cleanToilet();
  }

  // fixed
  void doDailyChores() {
  	dust();
  	vacuum();
  	mopFloor();
  	washClothes();
  	cleanToilet();
  }
  ```

* Methods and constructors should generally avoid multiple parameters of the same type, unless the
  method's purpose is to process multiple instances of the same type (e.g., comparator, math
  functions). This is especially egregious for boolean parameters.
* Tips for lowering complexity
  * Keep the number of nesting levels low
  * Keep the number of variables used low
  * Keep the lines of code low
  * Keep 'span' low (the number of lines between successive references to variables)
  * Keep 'live time' low (the number of lines that a variable is in use)

## Testing

### Unit Testing
* A single test case should only test one result. If there are more than 2 or 3 asserts in a single
  test, consider breaking into multiple tests.
* Unit tests should run fast (a single test case (method) should be less than a second).

## Miscellaneous

### @Override
* Methods that override a method in a parent class should use the `@Override` tag.
* Methods that implement an interface method should use the `@Override` tag.
* Methods that use the `@Override` tag do not need a Javadoc comment.

### Use of Tuple Objects `<A,B>`
* Use of `Pair<A,B>`, `Triple<A,B,C>`, etc. should be avoided. If the multiple values being returned
  are related, then the method is conceptually returning a higher level object/record and so should 
  return that. Otherwise, the method should be redesigned.

### Use of `var` Keyword
* Always favor declaring a variable with its type instead of the `var` keyword.

### Exception Handling
* Exceptions should never have empty code blocks. There should at least be a comment explaining why
  there is no code for the exception.
* If the caught exception is believed to be impossible to happen, the correct action is to throw an
  AssertException with a message explaining that it should never happen.

### Final
* Instance variables that are immutable should be declared final unless there is a compelling reason
  not to.

### Shadowing
* Avoid hiding/shadowing methods, variables, and type variables in outer scopes.

### Access Modifiers
* Class instance fields should not be public. They should be private whenever possible, but
  protected and package are acceptable.

### Java-specific Constructs
* Use the try-with-resources pattern whenever possible.
* Always parameterize types when possible (e.g., `JComboBox<String>` vs. `JComboBox`).
* If an object has an `isEmpty()` method, use it instead of checking its `size == 0`.

### Miscellaneous
* Mutating method parameters is discouraged.
* Magic numbers should not appear in the code. Other than 0 or 1, the number should be declared as
  a constant.
* Avoid creating a new Utilities class **every time you need to share code**. Try to add to an
  existing utilities class OR take advantage of code re-use via inheritance.

## Notes

### Complexity
>The McCabe measure of complexity isn't the only sound measure, but it's the measure most discussed
in computing literature and it's especially helpful when you're thinking about control flow. Other
measures include the amount of data used, the number of nesting levels in control constructs, the
number of lines of code, the number of lines between successive references to variables ("span"),
the number of lines that a variable is in use ("live time"), and the amount of input and output.
Some researchers have developed composite metrics based on combinations of these simpler ones.
(McCabe)

>Moving part of a routine into another routine doesn't reduce the overall complexity of the program;
it just moves the decision points around. But it reduces the amount of complexity you have to deal
with at any one time. Since the important goal is to minimize the number of items you have to juggle
mentally, reducing the complexity of a given routine is worthwhile. (McCabe)

>Excessive indentation, or "nesting," has been pilloried in computing literature for 25 years and is
still one of the chief culprits in confusing code. Studies by Noam Chomsky and Gerald Weinberg
suggest that few people can understand more than three levels of nested ifs (Yourdon 1986a), and
many researchers recommend avoiding nesting to more than three or four levels (Myers 1976, Marca
1981, and Ledgard and Tauer 1987a). Deep nesting works against what Chapter 5, describes as
Software's Primary Technical Imperative: Managing Complexity. That is reason enough to avoid deep
nesting. (McCabe)

>There is no code so big, twisted, or complex that maintenance can't make it worse. (Gerald 
Weinberg)

## References
* [Google Java Style Guide](https://google.github.io/styleguide/javaguide.html)
* [OpenJDK Style Guide](https://cr.openjdk.org/~alundblad/styleguide/index-v6.html)
* [Java Programming Style Guidelines - Geotechnical Software Services](https://geosoft.no/javastyle.html)
* Code Complete, Steve McConnell
* [Java Code Conventions](https://www.oracle.com/technetwork/java/codeconventions-150003.pdf)
* Netscape's Software Coding Standards for Java
* C / C++ / Java Coding Standards from NASA
* [Coding Standards for Java from AmbySoft](https://ambysoft.com/essays/javacodingstandards.html)
* Clean Code, Robert Martin (Uncle Bob)
