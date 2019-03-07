# Contributors Guide

Ghidra is an open source project. If you are interested in making it better,
there are many ways you can contribute. For example, you can:

- Submit a bug report
- Suggest a new feature
- Provide feedback by commenting on feature requests/proposals
- Propose a patch by submitting a pull request
- Suggest or submit documentation improvements
- Review outstanding pull requests
- Answer questions from other users
- Share the software with other users who are interested
- Teach others to use the software
- Package and distribute the software in a downstream community (such as your
  preferred Linux distribution)

## Bugs and Feature Requests

If you believe that you have found a bug or wish to propose a new feature,
please first search the existing [issues] to see if it has already been
reported. If you are unable to find an existing issue, consider using one of
the provided templates to create a new issue and provide as many details as you
can to assist in reproducing the bug or explaining your proposed feature.

## Patch Submission tips

Patches should be submitted in the form of Pull Requests to the Ghidra
[repository] on GitHub. But first, consider the following tips to ensure a
smooth process when submitting a patch:

- Ensure that the patch compiles and does not break any build-time tests
- Be understanding, patient, and friendly; developers may need time to review
  your submissions before they can take action or respond. This does not mean
  your contribution is not valued. If your contribution has not received a
  response in a reasonable time, consider commenting with a polite inquiry for
  an update.
- Limit your patches to the smallest reasonable change to achieve your intended
  goal. For example, do not make unnecessary indentation changes; but don't go
  out of your way to make the patch so minimal that it isn't easy to read,
  either. Consider the reviewer's perspective.
- Before submission, please squash your commits to using a message that starts
  with the issue number and a description of the changes.
- Isolate multiple patches from each other. If you wish to make several
  independent patches, do so in separate, smaller pull requests that can be
  reviewed more easily.
- Be prepared to answer questions from reviewers. They may have further
  questions before accepting your patch, and may even propose changes. Please
  accept this feedback constructively, and not as a rejection of your proposed
  change.

## Review

- We welcome code reviews from anyone. A committer is required to formally
  accept and merge the changes.
- Reviewers will be looking for things like threading issues, performance
  implications, API design, duplication of existing functionality, readability
  and code style, avoidance of bloat (scope-creep), etc.
- Reviewers will likely ask questions to better understand your change.
- Reviewers will make comments about changes to your patch:
    - MUST means that the change is required
    - SHOULD means that the change is suggested, further discussion on the
      subject may be required
    - COULD means that the change is optional

## Getting Started

Once available, please see the [developer's guide][devguide] for instructions to set up a suitable development environment.

## Legal

Consistent with Section D.6. of the GitHub Terms of Service as of 2019, and Section 5. of the Apache License, Version 2.0, the project maintainer for this project accepts contributions using the inbound=outbound model.
When you submit a pull request to this repository (inbound), you are agreeing to license your contribution under the same terms as specified in [LICENSE] (outbound).

This is an open source project.
Contributions you make to this public U.S. Government ("USG") repository are completely voluntary.
When you submit an issue, bug report, question, enhancment, pull request, etc., you are offering your contribution without expectation of payment, you expressly waive any future pay claims against the USG related to your contribution, and you acknowledge that this does not create an obligation on the part of the USG of any kind.
Furthermore, your contributing to this project does not create an employer-employee relationship between the United States ("U.S.") Government and the contributor.

[issues]: https://github.com/NationalSecurityAgency/ghidra/issues
[repository]: https://github.com/NationalSecurityAgency/ghidra/
[devguide]: DevGuide.md
[LICENSE]: LICENSE
