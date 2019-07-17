****************************************************************************************************
Introduction to the MicrosoftDmang project:
  This code base is both an artifact and an outcome of the Microsoft Demangler effort.  It is an
    outcome in that we drove ourselves to create our own Microsoft Demangler not constrained by
    others' intellectual property.  However, part of coming up with our own demangler is first to
    understand Microsoft objects, mangling process, and demangling process; we are trying to mimic
    this understanding in our end product, but we need a tool or framework to tease out this
    understanding by:
    1) Performing hand-tweaked fuzzing of the input to undname,
    2) Performing forward programming and checking/analyzing what is produced in terms of code and
       symbols,
    3) Utilizing limited information that we can find--we started with "Visual C++ name mangling"
       which is now on wikibooks (moved from wikipedia).
  This code base serves as a reflection of our continual understanding of mangled symbols and how
    to process them as we adapt our understanding over time. This code base is not necessarily
    "the truth" in terms of a representation, but it is our current codification of "our truth,"
    which can still morph over time.

****************************************************************************************************
Precepts and Goals:
  Some precepts and goals of this project follow:
    1) Create a Microsoft symbol demangler not tied to others' intellectual property,
    2) Try to make this code separable from the rest of the code base--so it could be a stand-alone
       deliverable.  Currently, some of the "test" software is tied to the rest of the code
       base--the tests extend "genericTestCase" and use the public variable BATCH_MODE.
    3) Knowing that other utilities (e.g., undname) are far from perfect in demangling symbols, we
       created a demangler that can present differing processing/output rules.  This allows us to
       create a better set of processing/output rules than currently exist while still creating
       a set of rules that mimic existing utilities, which allows us to process bulk sets of
       symbols into bulk sets of test data (mangled/demangled pairs).  Because of this, we have
       better faith in our better demangler because we can see how well we do with the demangler
       rule set that mimics the results of many of the 2.7 million Windows 7 symbols and 6.8
       million Windows 10 symbols in our bulk test sets.
    4) In order to mimic the Microsoft rules, we often have to adhere to odd white space rules,
       which includes some cases where the are no spaces after commas and in which there are
       dangling white spaces.  We put much effort in trying to mimic these odd spacing rules--to
       all for the bulk testing AND because it also sheds light on what we believe could be
       internal software architecture.
  
****************************************************************************************************
MicrosoftDmang Development and Testing Overview:
  The software architecture of this project is continually in flux with some classes being better
    defined and "cleaner" than others.  Not having real software requirements, but being test
    driven, there are many times where there have been grand scale software changes which rely upon
    a nimble environment.  For example there could be a case where I could make a change in order to
    cause 50 more tests to pass, but 200 others fail, yet it might have been the correct change
    that requires 13 other changes with numerous tests moving back and forth between pass and fail
    states until I finally settle at the state where all previously passing tests pass again and
    I've gotten one additional failing test to now pass.  This is not an unrealistic description,
    and we have come a very long way, which has allowed to to focus more now on cleaning up the
    code, but there are some areas where the code looks like spaghetti.  This is primarily in the
    section of "modified" types.  Tests have also been continually added to either provide the
    data from a new fuzzing experience or to create additional bounds on a new test case.
  Individual tests are found in MDMangBaseTest.  There are also tests in the MDMangListTest,
    which has various mechanisms for pulling test data from a file.  One of these has
    mangled/demangled pairs, others might might just have mangled symbols only, but we are looking
    for cases where the demangler could "blow up."  These file tests often provide a data record
    for creating a new individual test.
  There is also MDMangBaseTest, which uses MDMangBaseTestSuite as the junit-4 testSuite, but
    which also uses the runWith(Categories) junit runner to exclude test from running that have
    been given the correct MDMangFailingTests annotation in the MDMangBaseTest file.  The
    MDMangBaseTestSuite, which excludes failing tests, is geared toward being the nightly test
    to be run, as no error are expected to be seen.
  
****************************************************************************************************
MicrosoftDmang Architecture:
  MDMang is the basic interface and driver of the demangler action (perhaps these should be
    separated).  It takes a symbols and returns a MDParsableItem (*in most cases), from which we
    can retrieve a demangled string or from which we can ask questions.  There are additional
    demanglers that derive from MDMang, which produce the results of other processing/output
    rules.  These include MDMangVS2015 and MDMangVS2013.  *The Ghidra-specific demangler does not
    directly return an MDMParsableItem (it can be requested post-processing), but instead
    an output specific to the needs to Ghidra.  Also within MDMang lies various public methods
    intended for use by the driver side of the project (again, another reason to break this class
    into pieces).
  
  MDException: The exception class for internal exception handling.
  
  MDContext: A class containing a single context that is pushed or popped to/from a context stack
    in MDMang.  A context contains "backreferences" (as we currently understand backreferences and
    a context of them--simplified from more complicated contexts, we are trying to whittle this
    away toward non-existence).  There are backrefNames, backrefParameters, and
    backrefTemplateParameters.  A context is created from a previous context using particular
    rules that are dictated by an enumerated MDMcontext annotation.  These, too, might go away,
    but we have boiled them down to what currently exists.  In the future, the MDContext class
    might go away and backreferences could be part of the class for which the context has been
    created--but we started with this current model while we were trying to understand when there
    was a context change and what required the change; in fact, there are still questions that
    arise in my mind, yet I have not yet created tests that might tease the answer out.  I do
    know, however, that one or more tests in the MDMangBaseTest class had helped define what
    we have--I no longer have record of which tests were solely responsible for revealing some of
    the special context/backreference cases (e.g., could have been that a backreference to an
    internal template argument got used in a certain way).
  
  MDFuzzyFit: Not currently used (only in an @Ignore case in one of the tests at this time).  The
    currently goal is to potentially make this into an MDMang extension.  Then create a utility
    that exposes the functionality.
  
  MDParsableItem: This is the base class for any internal object that has a mangled/demangled
    representation.  All parsable items derive from MDParsableItem.
  
  MDObject: This class represents a fully presentable symbol as would be expected to be found in
    a list of symbols for a binary.  It contains a name and and MDTypeinfo.  An MDObject could
    probably be an abstract class (not one at the moment).  The MDObjectCPP (below) is the
    primary derived object of interest for us.  Other than MDObjectC, the others (MDObjectBracket
    and MDObjectCodeView) may or may not be true representations of the MSFT architecture.  (The
    "object" itself might not be representative of the MSFT architecture, but it is what works
    for me at the moment.) An MDobject is composed of a name (either MDFragmentName or
    MDQualifiedName) and an MDTypeInfo, which can be a derived class.
  
  MDFragmentName: This class represents a single string part of a name--it is nearly as simple as
    a C-language name.
  
  MDQualifiedName: represents a complicated C++-style name that has an MDBasicName and an
    MDQualification.
  
  MDBasicName: Can be a template name with arguments (MDTemplateNameAndArguments); the name of an
    embedded object; a simple, reusable name fragment; or a special operator name.
  
  MDQualification: represents the scope of a name or other construct.  A qualification is an
    ordered list of qualifiers (MDQual--internal class of MDQualification), which can be further
    parsed from other complicated constructs.
  
  MDTypeInfo: This represents something about the type of the object (the MDObject).  Recently, we
    created derived types from the MDTypeInfo to represent a "Variable" type versus a "Function"
    type versus one of many other C++ types, such as virtual function calls and virtual function
    tables.  In most cases MDTypeInfo contains an MDType, which is the base type of all "types,"
    whether data types or function types.  I'm not necessarily happy with the separate constructs
    of MDTypeInfo and MDType, but the code was much more easy to work with, in terms of getting
    the correct parsing and output order in place.  While they are seemingly at opposite ends
    of the details, there's a chance that they are one in the same, and this will take more study.
  
  MDType: This is the base type of all "types" (see documentation for MDTypeInfo), whether data
    types or function types.  There is currently a large set of commented-out code in MDType,
    which might eventually get deleted, but I'm still trying to find the commonality of types,
    trying to get them as low as possible and also see where MDType and MDTypeinfo overlap.
  
  MDDataType: This is the "data" type derived from MDType.  There are many leaf-level derived
    types of MDDataType, such as "int," but there are also a good number of derived intermediate
    type classes for MDDataType.  Currently, as for MDType, there is a large set of commented-out
    code for MDDataType which is being worked for possible solution of consolidating information
    into lower base classes from higher classes.
  
  MDFunctionType: This is the "function" type derived from MDType.  There are instances of
    MDFunctionType as well as derived classes.

  There are many more details and derived types not specified here, but there are a host of other
    miscellaneous MDParsableItem-derived classes that include: MDEncodedNumber,
    MDSignedEncodedNumber, and MDString.
  
  There are a number of parsers that parse parts of a mangled string and created various
    MDParsableItems (those documented above, as well as many other).  These parses tend to be
    large switch statements.  At times, some cases of the switch make calls out to other methods
    that further refine the parsing.

****************************************************************************************************
****************************************************************************************************

