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

## Legal

The project maintainer for this project will only accept contributions using the [Developer's Certificate of Origin 1.1][dco] located at https://developercertificate.org ("DCO").
The DCO is a legally binding statement asserting that the contributor is the creator of the contribution, or otherwise has the authority to distribute the contribution, and that they are intentionally making the contribution available under the license(s) associated with the Project ("License").

This is an open source project.
Contributions you make to this public U.S. Government ("USG") repository are completely voluntary.
When you submit a pull request, you are offering your contribution without expectation of payment, you expressly waive any future pay claims against the USG related to your contribution, and you acknowledge that this does not create an obligation on the part of the USG of any kind.
Furthermore, your contributing to this project does not create an employer-employee relationship between the United States ("U.S.") Government and the contributor.

### Developer Certificate of Origin (DCO) Process

This project implements a Lite version of the DCO process.
When you submit a pull request to this repository for the first time, you need to sign the DCO.
To indicate you have read and agree to the DCO, you need to add the following information to the [contributors] file:

- Name
- Email address or other contact (required)
- Copyright year(s) (required)

This essentially affirms that you have the right to submit the work you are contributing in your pull requests and that you consent to us treating the contribution in a way consistent with the License.
Please see the [licensing intent][intent] for details.
The primary License for this Project is the Apache License, Version 2.0 ("Apache 2.0").
The project composes a number of software modules with documentation ("Modules").
Each module may have additional licensing restrictions imposed by its dependencies, or because some portion of it was derived from software requiring the application of these restrictions.
In most cases, these licenses do not introduce any restrictions beyond those already required by Apache 2.0, e.g., BSD-style licenses.
In general, we intend to indicate within each Module the applicable license(s), whether or not they are more restrictive than the Project's License.
When you sign the DCO and submit a pull request containing contributions to such a module, please keep in mind you are asserting you have the authority to submit the work, and that the work will be made available under those license(s).

### Important Points

You are not required to provide your name, but you must provide a valid and functional means to contact you.
If you are a U.S. Federal Government employee and use a .mil or .gov email address to agree to the DCO, or you otherwise indicate that you are a U.S. Federal Government employee, we interpret your signed DCO to mean that the contribution was created in whole or in part by you in your official capacity as a U.S. Federal Government Employee.
This implies your contribution is not subject to copyright protections within the United States.
If you wish to contribute in your own capacity, that is, on your own personal time, you must sign the DCO in that capacity, using an appropriate email address or other means of contact.

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

[issues]: https://github.com/NationalSecurityAgency/ghidra/issues
[repository]: https://github.com/NationalSecurityAgency/ghidra/
[dco]: https://developercertificate.org
[intent]: INTENT.md
[contributors]: Contributors.md
[devguide]: DevGuide.md
