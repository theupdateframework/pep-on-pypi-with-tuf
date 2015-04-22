PEP: 458
Title: Securing the Link from PyPI to the End User
Version: $Revision$
Last-Modified: $Date$
Author: Trishank Karthik Kuppusamy <trishank@nyu.edu>,
Vladimir Diaz <vladimir.diaz@nyu.edu>, Donald Stufft <donald@stufft.io>,
Justin Cappos <jcappos@nyu.edu>
BDFL-Delegate: Richard Jones <r1chardj0n3s@gmail.com>
Discussions-To: DistUtils mailing list <distutils-sig@python.org>
Status: Draft
Type: Standards Track
Content-Type: text/x-rst
Created: 27-Sep-2013


Abstract
========

This PEP proposes how the Python Package Index [1]_ (PyPI) infrastructure can
be amended to better protect end users from altered or malicious packages, and
to minimize the extent of PyPI compromises against affected users.  The
proposed integration allows package managers such as pip [3]_ to be more secure
against various types of security attacks on PyPI and defend end users from
attackers responding to package requests. Specifically, this PEP describes how
PyPI processes should be adapted to generate and incorporate repository
metadata, which are signed text files that describe the packages and metadata
available on PyPI.  Package managers request, along with the packages, the
metadata on PyPI to verify the authenticity of packages before they are
installed.  The changes to PyPI and tools will be minimal by leveraging a
library, The Update Framework [2]_ (TUF), that generates and transparently
validates the relevant metadata.

The proposed integration utilizes a basic security model that supports
verification of PyPI packages signed with cryptographic keys stored on PyPI,
requires no action from developers and end users, and protects against
malicious CDNs and public mirrors. To support continuous delivery of uploaded
packages, PyPI administrators sign for uploaded packages with an on-pypi key
stored on PyPI infrastructure. This level of security prevents packages from
being accidentally or deliberately tampered with by a mirror or a CDN because
the mirror or CDN will not have any of the keys required to sign for projects.  

This PEP does not prescribe how package managers such as pip should be adapted
to install projects from PyPI with TUF metadata.   Package managers interested
in adopting TUF on the client side may consult TUF's `library documentation`__,
which exists for this purpose.  Support for project distributions that are
signed by developers is also not discussed in this PEP, but is outlined in the
appendix as a possible future extension, and covered in detail in PEP 480
[26]_.  The PEP 480 extension focuses on the end-to-end security model that
requires more PyPI administrative work and none by clients.  End-to-end signing
allows both PyPI and developers to sign for the packages that are downloaded by
end users.  The extension also proposes an easy-to-use key management solution
for developers, how to interface with a potential future build farm on PyPI
infrastructure, and discusses the security benefits of end-to-end signing.

__ https://github.com/theupdateframework/tuf/tree/develop/tuf/client#updaterpy


Motivation
==========

In January 2013, the Python Software Foundation (PSF) announced [4]_ that the
python.org wikis for Python, Jython, and the PSF were subjected to a security
breach that caused all of the wiki data to be destroyed on January 5, 2013.
Fortunately, the PyPI infrastructure was not affected by this security breach.
However, the incident is a reminder that PyPI should take defensive steps to
protect users as much as possible in the event of a compromise.  Attacks on
software repositories happen all the time [5]_.  The PSF must accept the
possibility of security breaches and prepare PyPI accordingly because it is a
valuable resource used by thousands, if not millions, of people.

Before the wiki attack, PyPI used MD5 hashes to tell package managers, such as
pip, whether or not a package was corrupted in transit.  However, the absence
of SSL made it hard for package managers to verify transport integrity to PyPI.
It was therefore easy to launch a man-in-the-middle attack between pip and
PyPI, and change package content arbitrarily.  Users could be tricked into
installing malicious packages with man-in-the-middle attacks.  After the wiki
attack, several steps were proposed (some of which were implemented) to deliver
a much higher level of security than was previously the case: requiring SSL to
communicate with PyPI [6]_, restricting project names [7]_, and migrating from
MD5 to SHA-2 hashes [8]_.

These steps, though necessary, are insufficient because attacks are still
possible through other avenues.  For example, a public mirror is trusted to
honestly mirror PyPI, but some mirrors may misbehave due to malice or accident.
Package managers such as pip are supposed to use signatures from PyPI to verify
packages downloaded from a public mirror [9]_, but none are known to actually
do so [10]_.  Therefore, it would be wise to add more security measures to
detect attacks from public mirrors or content delivery networks [11]_ (CDNs).

Even though official mirrors are being deprecated on PyPI [12]_, there remain a
wide variety of other attack vectors on package managers [13]_.  These attacks
can crash client systems, cause obsolete packages to be installed, or even
allow an attacker to execute arbitrary code.  In `September 2013`__, a post was
made to the Distutils mailing list showing that the latest version of pip (at
the time) was susceptible to such attacks, and how TUF could protect users
against them [14]_.  Specifically, testing was done to see how pip would
respond to these attacks with and without TUF.  Attacks tested included replay
and freeze, arbitrary packages, slow retrieval, and endless data.  The post
also included a demonstration of how pip would respond if PyPI were
compromised.

__ https://mail.python.org/pipermail/distutils-sig/2013-September/022755.html

With the intent to protect PyPI against infrastructure compromises, this PEP
proposes integrating PyPI with The Update Framework [2]_ (TUF).  TUF helps
secure new or existing software update systems. Software update systems are
vulnerable to many known attacks, including those that can result in clients
being compromised or crashed. TUF solves these problems by providing a flexible
security framework that can be added to software updaters.


Threat Model
============

The threat model assumes the following:

* Keys not kept on PyPI infrastructure are safe and securely stored.

* Attackers can compromise at least one of PyPI's trusted keys stored on the
  PyPI infrastructure, and may do so at once or over a period of time.

* Attackers can respond to client requests.

An attacker is considered successful if they can cause a client to install (or
leave installed) something other than the most up-to-date version of the
software the client is updating. If the attacker is preventing the installation
of updates, they want clients to not realize there is anything wrong.


Definitions
===========

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC `2119`__.

__ http://www.ietf.org/rfc/rfc2119.txt

This PEP focuses on integrating TUF with PyPI; however, the reader is
encouraged to read about TUF's design principles [2]_.  It is also RECOMMENDED
that the reader be familiar with the TUF specification [16]_.

Terms used in this PEP are defined as follows:

* Projects: Projects are software components that are made available for
  integration.  Projects include Python libraries, frameworks, scripts,
  plugins, applications, collections of data or other resources, and various
  combinations thereof.  Public Python projects are typically registered on the
  Python Package Index [17]_.

* Releases: Releases are uniquely identified snapshots of a project [17]_.

* Distributions: Distributions are the packaged files that are used to publish
  and distribute a release [17]_.

* Simple index: The HTML page that contains internal links to the
  distributions of a project [17]_.

* Roles: There is one *root* role in PyPI.  There are multiple roles whose
  responsibilities are delegated to them directly or indirectly by the *root*
  role. The term **top-level** role refers to the *root* role and any role
  delegated by the *root* role. Each role has a single metadata file that it is
  trusted to provide.

* Metadata: Metadata are signed files that describe roles, other metadata, and
  target files.

* Delegation: A role may delegate trust of some or all of its responsibilities
  to another role.  A delegation is denoted by modifying the metadata of the
  role that is designating responsibility.  Delegated roles may provide their
  own metadata once the delegation has been performed, and according to the
  privileges specified by the parent role.

* Repository: A repository is a resource comprised of named metadata and target
  files.  Clients request metadata and target files stored on a repository.

* Consistent snapshot: A set of TUF metadata and PyPI targets that capture the
  complete state of all projects on PyPI as they existed at some fixed point in
  time.

* The *snapshot* (*release*) role: In order to prevent confusion due to the
  different meanings of the term "release" used in PEP 426 [17]_ and the TUF
  specification [16]_, the *release* role is renamed as the *snapshot* role.

* Developer: Either the owner or maintainer of a project who is allowed to
  update the TUF metadata as well as distribution metadata and files for the
  project.

* On-pypi key: A private cryptographic key that MUST be stored on the PyPI
  infrastructure.  This is usually to allow automated signing with the key.
  However, an attacker who compromises the PyPI infrastructure will be able to
  read these keys.

* Off-pypi key: A private cryptographic key that MUST be stored independent of
  the PyPI server infrastructure.  This prevents automated signing with the
  key.  An attacker who compromises the PyPI infrastructure will not be able to
  immediately read these keys.

* Threshold signature scheme: A role can increase its resilience to key
  compromises by specifying that at least t out of n keys are REQUIRED to sign
  its metadata.  A compromise of t-1 keys is insufficient to compromise the
  role itself.  Saying that a role requires (t, n) keys denotes the threshold
  signature property.


Overview of TUF
===============

At its highest level, TUF provides applications with a secure method of
obtaining files and knowing when new versions of files are available. On the
surface, this all sounds simple. The basic steps for updating applications are:

* Knowing when an update exists.

* Downloading a correct copy of the latest version of an updated file.

The problem is that updating applications is only simple when there are no
malicious activities in the picture. If an attacker is trying to interfere with
these seemingly simple steps, there is plenty they can do.

Assume a software updater takes the approach of most systems (at least the ones
that try to be secure). It downloads both the file it wants and a cryptographic
signature of the file. The software updater already knows which key it trusts
to make the signature. It checks that the signature is correct and was made by
this trusted key. Unfortunately, the software updater is still at risk in many
ways, including:

* An attacker keeps giving the software updater the same update file, so it
  never realizes there is an update.

* An attacker gives the software updater an older, insecure version of a file
  that it already has, so it downloads that one and blindly uses it thinking it
  is newer.

* An attacker gives the software updater a newer version of a file it has but
  it is not the newest one.  The file is newer to the software updater, but it
  may be insecure and exploitable by the attacker.

* An attacker compromises the key used to sign these files and now the software
  updater downloads a malicious file that is properly signed.

TUF is designed to address these attacks, and others, by adding signed metadata
(text files that describe the repository's files) to the repository and
referencing the metadata files during the update procedure.  Repository files
are verified against the information included in the metadata before they are
transferred to the software update system.  The framework also provides
multi-signature trust, explicit and implicit revocation of cryptograhic keys,
responsibility separation of the metadata, and minimizes key risk.  For a full
list and outline of the repository attacks and software updater weaknesses
addressed by TUF, see Appendix A.

In addition to requiring that TUF metadata exist on the repository,
software updaters must download and reference TUF metadata in a particular
order to guarantee they are also updated securely. Verifying and fetching
metadata is managed by TUF once an update is initiated by the software
updater.

Overview of the update process:

The following steps are performed by TUF during a software update.

1. TUF downloads and verifies *timestamp.json*.

2. If *timestamp.json* indicates that *snapshot.json* has changed, TUF
   downloads and verifies *release.json.*.

3. TUF determines which metadata files listed in *snapshot.json* differ from
   those described in the last *snapshot.json* that TUF has referenced. If
   *root.json* has changed, the update process starts over using the new
   *root.json*.

4. TUF provides the software update system with a list of available projects
   according to *targets.json*.

5. The software update system instructs TUF to download a specific package.


Integrating TUF with PyPI
=========================

A software update system must complete two main tasks to integrate with TUF.
First, it must add the framework to the client side of the update system.  For
example, TUF MAY be integrated with the pip package manager.  Second, the
repository on the server side MUST be modified to provide signed TUF metadata.
This PEP is concerned with the second part of the integration, and the changes
required on PyPI to support software updates with TUF.


What Additional Repository Files are Required on PyPI?
------------------------------------------------------

In order for package managers like pip to download and verify packages with
TUF, a few extra files MUST exist on PyPI. These extra repository files are
called TUF metadata. TUF metadata contains information such as which keys are
trustable, the cryptographic hashes of files, signatures to the metadata,
metadata version numbers, and the date after which the metadata should be
considered expired.

When a package manager wants to check for updates, it asks TUF to do the work.
That is, a package manager never has to deal with this additional metadata or
understand what's going on underneath. If TUF reports back that there are
updates available, a package manager can then ask TUF to download these files
from PyPI. TUF downloads them and checks them against the TUF metadata that it
also downloads from the repository. If the downloaded target files are
trustworthy, TUF then hands them over to the package manager.

The `Metadata`__ document provides information about each of the required
metadata and their expected content.  The next section covers the different
kinds of metadata RECOMMENDED for PyPI.

__ https://github.com/theupdateframework/tuf/blob/develop/METADATA.md


PyPI and TUF Metadata
=====================

TUF metadata provides information that clients can use to make update
decisions.  For example, a *targets* metadata lists the available distributions
on PyPI and includes the distribution's signatures, cryptographic hashes, and
file sizes.  Different metadata files provide different information.  The
various metadata files are signed by different roles, which are indicated by
the *root* role.  The concept of roles allows TUF to delegate responsibilities
to multiple roles and minimizes the impact of a compromised role.

TUF requires four top-level roles.  These are *root*, *timestamp*, *snapshot*,
and *targets*.  The *root* role specifies the public cryptographic keys of the
top-level roles (including its own).  The *timestamp* role references the
latest *snapshot* and can signify when a new snapshot of the repository is
available.  The *snapshot* role indicates the latest version of all the TUF
metadata files (other than *timestamp*).  The *targets* role lists the
available target files (in our case, it will be all files on PyPI under the
/simple and /packages directories).  Each top-level role will serve its
responsibilities without exception.  Figure 1 provides a table of the roles
used in TUF.  Figure 2 illustrates the relationships between the different
roles and the content of TUF metadata. 

.. image:: pep-0458-1.png

Figure 1: An overview of the TUF roles.

Roles with different capabilities are used by TUF to compartmentalize trust.
Metadata on the repository includes information about which keys are valid, the
cryptographic hashes of packages and metadata, and the timeliness of available
repository updates. Different roles sign for each type of metadata so that an
attacker acquiring the key that specifies timeliness (which is kept on the PyPI
infrastructure) does not also gain access to the key that signs for the trusted
hashes of packages, or to the key that signs for the trusted repository keys.
Utilizing multiple roles allows TUF to delegate responsibilities and minimize
the impact of a compromised role.

.. image:: pep-0458-2.png

Figure 2: An illustration of example TUF metadata.


Repository Management
---------------------

The roles that change most frequently are *timestamp*, *snapshot* and delegated
roles.  The *timestamp* and *snapshot* metadata MUST be updated whenever
*root*, *targets* or delegated metadata are updated.  Observe, though, that
*root* and *targets* metadata are much less likely to be updated as often as
delegated metadata.  Therefore, *timestamp* and *snapshot* metadata will most
likely be updated frequently (possibly every minute) due to delegated metadata
being updated frequently in order to support continuous delivery of projects.
Continuous delivery is a set of processes that PyPI uses produce snapshots that
can safely coexist and be deleted independent of other snapshots [18]_.

Figure 3 provides an overview of the roles available within PyPI, which
includes the top-level roles and the roles delegated by *targets*.  The figure
also indicates the types of keys used to sign each role and which roles are
trusted to sign for files available on PyPI.  The next two sections cover the
details of signing repository files and the types of keys used for each role.

.. image:: pep-0458-3.png

Figure 3: An overview of the role metadata available on PyPI.

The top-level *root* role signs for the keys of the top-level *timestamp*,
*snapshot*, *targets*, and *root* roles.  The *timestamp* role signs for every
new snapshot of the repository metadata.  The *snapshot* role signs for *root*,
*targets*, and all delegated roles.  The *pypi-signed* roles (delegated roles)
sign for all distributions belonging to registered PyPI projects.

Every year, PyPI administrators SHOULD sign for *root* and *targets* role keys.
Automation will continuously sign for a timestamped, snapshot of all projects.
A `repository management`__ tool is available that can generate and sign
metadata for all roles, generate cryptographic keys, revoke keys, and sign
releases.  The top-level roles are required and are available by default in the
repository management tool, but the other delegated roles used in PyPI must be
manually specified.

__ https://github.com/theupdateframework/tuf/tree/develop/tuf#repository-management


Specifying Delegations
----------------------

In order to specify role delegations, TUF metadata must be updated to include
information about the delegation (i.e., the name of the role being delegated,
its public keys, and the packages the delegatee is trusted to sign).  PyPI
administrators may use the repository management tool to specify the other
delegated roles as outlined in figure 3.

Specifying a delegation with the repository management tool updates the
metadata of the parent role by adding a *delegations* entry to its metadata
file.  The parent role specifies the public keys of the delegated role, its
role name, and the paths it is trusted to provide. Once a parent role has
delegated trust, delegated roles may add targets and generate signed metadata
according to the keys and paths allowed by the parent. Figure 2 illustrates the
relationships between roles in TUF. A nested delegation is made from the
top-level projects role to the delegated roles named *targets/foo* and
*targets/bar*.

An example of specifying a delegation with the repository management tool:

.. code-block:: python

  from tuf.repository_tool import *

  repository = load_repository("path/to/repository")
  pypi_signed_pub = import_ed25519_publickey_from_file("keystore/pypi-signed.pub")
  pypi_signed_key = import_ed25519_privatekey_from_file("keystore/pypi-signed", password="pw")
  repository.targets.delegate("pypi-signed", [pypi_signed_pub], [],
                     restricted_paths=["path/to/repository/targets/packages/"])
  repository.targets("pypi-signed").load_signing_key(pypi_signed_key)
  
  ...
  
  repository.write()

The repository management documentation includes more information on
specifying `delegations`__.

__ https://github.com/theupdateframework/tuf/tree/develop/tuf#delegations


File Formats of the PyPI JSON Metadata
--------------------------------------

This section presents the format of the JSON metadata files.  Examples of the
roles and their formats are available for review in the "pep-0458-repository"
subdirectory (alongside the "pep-0458.txt" PEP).


root.JSON
~~~~~~~~~

The root.json file is signed by the *root* role's keys.  It indicates which
keys are authorized for the top-level roles, including the root role itself.
To revoke any of the top-level role keys, the keys listed in root.json may be
replaced.

The format of root.json is as follows:

.. code-block::

  {
    "_type" : "Root",
    "version" : VERSION,
    "expires" : EXPIRES,
    "keys" : {
      KEYID : KEY
      , ... },
    "roles" : {
      ROLE : {
        "keyids" : [ KEYID, ... ] ,
        "threshold" : THRESHOLD },
      ...
    }
  }

VERSION is an integer that is greater than 0.  Clients MUST NOT replace a
metadata file with a version number less than the one currently trusted.

EXPIRES determines when metadata should be considered expired and no longer
trusted by clients.  Clients MUST NOT trust an expired file.

A ROLE may be "root", "snapshot", "targets", "timestamp", or "mirrors".  A role
for each of "root", "snapshot", "timestamp", and "targets" MUST be specified in
the key list. The role of "mirror" is optional.  If not specified, the mirror
list will not need to be signed even if mirror lists are being used.

The KEYID must be correct for the specified KEY.  Clients MUST calculate each
KEYID to verify this is correct for the associated key.  Clients MUST ensure
that for any KEYID represented in this key list and in other files, only one
unique key has that KEYID.

The THRESHOLD for a role is an integer of the number of keys of that role whose
signatures are required in order to consider a file as being properly signed by
that role.

Metadata date-time data follows the ISO 8601 standard.  The expected format of
the combined date and time string is "YYYY-MM-DDTHH:MM:SSZ".  Time is always in
UTC, and the "Z" time zone designator is attached to indicate a zero UTC
offset.  An example date-time string is "1985-10-21T01:21:00Z".


snapshot.JSON
~~~~~~~~~~~~~

The snapshot.json file is signed by the snapshot role.  It lists hashes and
sizes of all metadata on the repository, excluding timestamp.json and
mirrors.json.

The format of snapshot.json is as follows:

.. code-block::

  {
    "_type" : "Snapshot",
    "version" : VERSION,
    "expires" : EXPIRES,
    "meta" : METAFILES
  }

METAFILES is an object whose format is the following:

.. code-block::
  
  {
    METAPATH : {
      "length" : LENGTH,
      "hashes" : HASHES,
      ("custom" : { ... }) },
    ...
  }

METAPATH is the metadata file's path on the repository relative to the
metadata base URL.


targets.JSON and delegated target roles
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The targets.json metadata file lists the hashes and sizes of target files.
Target files are the actual files that clients are intending to download (for
example, the software updates they are trying to obtain).

This file can optionally define other roles to which it delegates trust.
Delegating trust means that the delegated role is trusted for some or all of
the target files available from the repository. When delegated roles are
specified, it is done similar to how the Root role specifies the top-level
roles: the trusted keys and signature threshold for each role is given.
Additionally, one or more patterns are specified that indicate the target file
paths for which clients should trust each delegated role.


The format of targets.json is as follows:

.. code-block::
  
  {
    "_type" : "Targets",
    "version" : VERSION,
    "expires" : EXPIRES,
    "targets" : TARGETS,
    ("delegations" : DELEGATIONS)
  }

TARGETS is an object whose format is the following:

.. code-block::

  {
    TARGETPATH : {
      "length" : LENGTH,
      "hashes" : HASHES,
      ("custom" : { ... }) },
    ...
  }

Each key of the TARGETS object is a TARGETPATH.  A TARGETPATH is a path to
a file that is relative to a mirror's base URL of targets.

It is allowed to have a TARGETS object with no TARGETPATH elements.  This can
be used to indicate that no target files are available.

The HASH and LENGTH are the hash and length of the target file. If defined, the
elements and values of "custom" will be made available to the client
application.  The information in "custom" is opaque to the framework and can
include version numbers, dependencies, requirements, and any other data that
the application wants to include to describe the file at TARGETPATH.  The
application may use this information to guide download decisions.

DELEGATIONS is an object whose format is the following:

.. code-block::

  {
    "keys" : {
      KEYID : KEY,
      ...
    },
    "roles" : [{
      "name": ROLE,
      "keyids" : [ KEYID, ... ] ,
      "threshold" : THRESHOLD,
      ("path_hash_prefixes" : [ HEX_DIGEST, ... ] |
      "paths" : [ PATHPATTERN, ... ])},
    ...
    ]
  }

In order to discuss target paths, a role MUST specify only one of the
"path_hash_prefixes" or "paths" attributes, each of which we discuss next.

The "path_hash_prefixes" list is used to succinctly describe a set of target
paths. Specifically, each HEX_DIGEST in "path_hash_prefixes" describes a set of
target paths.  The target paths must meet this condition: each target path,
when hashed with the SHA-256 hash function to produce a 64-byte hexadecimal
digest (HEX_DIGEST), must share the same prefix as one of the prefixes in
"path_hash_prefixes". This is useful to split a large number of targets into
separate bins identified by consistent hashing.

The "paths" list describes paths that the role is trusted to provide.  Clients
MUST check that a target is in one of the trusted paths of all roles in a
delegation chain, not just in a trusted path of the role that describes the
target file.  The format of a PATHPATTERN may be either a path to a single
file, or a path to a directory to indicate all files and/or subdirectories
under that directory.


timestamp.JSON
~~~~~~~~~~~~~~

The timestamp file is signed by a timestamp key.  It indicates the
latest versions of other files and is frequently resigned to limit the
amount of time a client can be kept unaware of interference with obtaining
updates.

Timestamp files will potentially be downloaded very frequently.  Unnecessary
information in them will be avoided.

The format of the timestamp file is as follows:

.. code-block::

  {
    "_type" : "Timestamp",
    "version" : VERSION,
    "expires" : EXPIRES,
    "meta" : METAFILES
  }

METAFILES has the same format as the "meta" object of the snapshot.json file.
In the case of the timestamp.json file, this will commonly include only a
description of the snapshot.json file.


How to Establish Initial Trust in the PyPI Root Keys
----------------------------------------------------

Package managers like pip need to ship a file named "root.json" with the
installation files that users initially download. This file includes
information about the keys trusted for certain roles, as well as the root keys
themselves.  Any new version of "root.json" that clients may download are
verified against the root keys that client's initially trust. If a root key is
compromised, but a threshold of keys are still secured, the PyPI administrator
MUST push a new release that revokes trust in the compromised keys. If a
threshold of root keys are compromised, then "root.json" should be updated
out-of-band, however the threshold should be chosen so that this is extremely
unlikely. The TUF client library does not require manual intervention if root
keys are revoked or added: the update process handles the cases where
"root.json" has changed.

To bundle the software, "root.json" MUST be included in the version of pip
shipped with CPython (via ensurepip). The TUF client library then loads the
root metadata and downloads the rest of the roles, including updating
"root.json" if it has changed.  An `outline of the update process`__ is
available.

__ https://github.com/theupdateframework/tuf/tree/develop/tuf/client#overview-of-the-update-process.


Minimum Security Model
----------------------

There are two security models to consider when integrating TUF with PyPI.  The
one proposed in this PEP is the minimum security model, which supports
verification of PyPI distributions that are signed with private cryptographic
keys stored on PyPI.  Distributions uploaded by developers are signed by PyPI
and immediately available for download.  A possible future extension to this
PEP, discussed in Appendix B, proposes the maximum security model and allows a
developer to sign for his/her project.  Developer keys are not stored on the PyPI
infrastructure: therefore, projects are safe from PyPI compromises.

The minimum security model requires no action from a developer and protects
against malicious CDNs [19]_ and public mirrors.  To support continuous
delivery of uploaded packages, PyPI signs for projects with an on-pypi key.
This level of security prevents projects from being accidentally or
deliberately tampered with by a mirror or a CDN because the mirror or CDN will
not have any of the keys required to sign for projects.  However, it does not
protect projects from attackers who have compromised PyPI, since attackers can
manipulate TUF metadata using the keys stored on PyPI infrastructure.

This PEP proposes that the *pypi-signed* role (and its delegated roles) sign
for all PyPI projects with an on-pypi key.  The *targets* role, which only
signs with an off-pypi key, MUST delegate all PyPI projects to the
*pypi-signed* role.  This means that when a package manager such as pip (i.e.,
using TUF) downloads a distribution from a project on PyPI, it will consult the
*pypi-signed* role about the TUF metadata for the project.  If no bin roles
delegated by *pypi-signed* specify the project's distribution, then the project
is considered to be non-existent on PyPI.


Metadata Expiry Times
---------------------

The *root* and *targets* role metadata SHOULD expire in one year, because these
two metadata files are expected to change very rarely.

The *timestamp*, *snapshot*, and *pypi-signed* metadata SHOULD expire in one
day because a CDN or mirror SHOULD synchronize itself with PyPI every day.
Furthermore, this generous time frame also takes into account client clocks
that are highly skewed or adrift.


Metadata Scalability
--------------------

Due to the growing number of projects and distributions, TUF metadata will also
grow correspondingly.  For example, consider the *pypi-signed* role.  In August
2013, it was found that the size of the *pypi-signed* metadata was about 42MB
if the *pypi-signed* role itself signed for about 220K PyPI targets (which are
simple indices and distributions).  This PEP does not delve into the details,
but TUF features a so-called "`lazy bin walk`__" scheme that splits a large
*targets* metadata file into many small ones (bins).  Targets are then
referenced in these smaller bins, and which bin a target should go in is based
on the hash value of the target's file name.  For example, a target's file name
whose hash value starts with *7F* is referenced in the
*targets/pypi-signed/00-7F* role (i.e., this role references all targets whose
hash value prefix falls between 00 and 7F).  The *lazy bin walk* scheme allows
a TUF client updater to intelligently download only a small number of TUF
metadata files in order to update any project signed for by the *pypi-signed*
role.  For instance, applying this scheme to the previous repository resulted
in pip downloading between 1.3KB and 111KB to install or upgrade a PyPI project
via TUF.

__ https://github.com/theupdateframework/tuf/issues/39

Based on our findings as of the time of writing, PyPI SHOULD split all targets
in the *pypi-signed* role by delegating them to 1024 delegated roles, each of
which would sign for PyPI targets whose hashes fall into that "bin" or
delegated role (see Figure 2).  It was found that 1024 *pypi-signed* bins would
result in the *pypi-signed* metadata, and each of its delegated roles, being
about the same size (40-50KB) for about 220K PyPI targets (simple indices and
distributions).

It is possible to make TUF metadata more compact by representing it in a binary
format as opposed to the JSON text format.  Nevertheless, a sufficiently large
number of projects and distributions will introduce scalability challenges at
some point, and therefore the *pypi-signed* role will still need delegations
(as outlined in figure 2) in order to address the problem.  Furthermore, the
JSON format is an open and well-known standard for data interchange.  Due to
the large number of delegated metadata, compressed versions of *snapshot*
metadata SHOULD also be made available to clients.


PyPI and Key Requirements
=========================

The number of keys, and key type, required to sign the TUF metadata are
discussed in this section.  TUF is agnostic with respect to the digital
signature algorithms allowed to sign the TUF metadata, however, the Ed25519
signature scheme [25]_ SHOULD be used by PyPI administrators.

Ed25519 is a public-key signature system that uses small cryptographic
signatures and keys.  It is an elliptic curve digital signature algorithm based
on Twisted Edwards curves.  A pure-Python implementation [27]_ of the Ed25519
signature scheme is available, and verification of Ed25519 signatures is fast
even when performed in Python.

The package manager (pip) shipped with CPython MUST work on non-CPython
interpreters and cannot have dependencies that have to be compiled (i.e., the
PyPI + TUF integration MUST NOT require compilation of C extensions in order to
verify cryptographic signatures). Verification of signatures MUST be done in
Python, and verifying RSA [20]_ signatures in pure-Python may be impractical
due to speed. Therefore, PyPI SHOULD use the Ed25519 signature scheme.


Cryptographic Key Files
-----------------------

Cryptographic keys MAY be stored in password-protected, encrypted key files.
Administrators MAY use the repository tool to encrypt key files with
AES-256-CTR-Mode and strengthen passwords with PBKDF2-HMAC-SHA256 (100K
iterations by default, but this may be overridden by the developer). The
current Python implementation of TUF can use any cryptographic library
(PyCrypto [24]_ is currently used to encrypt the TUF key files, but support for
PyCA Cryptography can be added in the future), may override the default number
of PBKDF2 iterations, and the KDF may be tweaked to preference.  However, the
exact cryptographic constructions can be adjusted to include future primitives
added to the cryptographic libraries supported by framework.


Key objects stored in encrypted key files and in metadata have the format:

.. code-block::

  {
    "keytype" : KEYTYPE,
    "keyval" : KEYVAL
  }

All keys have the format:

.. code-block::

  {
    "keytype" : KEYTYPE,
    "keyval" : KEYVAL
  }

where KEYTYPE is a string describing the type of the key ("ed25519") and how
it's used to sign documents.  The type determines the interpretation of KEYVAL.

The 'ed25519' key format is:

.. code-block::

  {
    "keytype" : "ed25519",
    "keyval" :
      { "public" : PUBLIC,
        "private" : PRIVATE
      }
  }

where PUBLIC and PRIVATE are both 32-byte strings.

Metadata does not include the private portion of the key object:

.. code-block::

  {
    "keytype" : "ed25519",
    "keyval" :
      { "public" : PUBLIC}
  }

The KEYID of a key is the hexdigest of the SHA-256 hash of the canonical JSON
form of the key, where the "private" object key is excluded.


Generating Cryptographic Keys and Signing Metadata
--------------------------------------------------

The repository management tool may be used to generate the cryptographic keys
and sign the PyPI metadata downloaded by end users.  The following Python code
demonstrates how to generate and import cryptographic keys with the repository
management tool:

.. code-block::

  >>> from tuf.repository_tool import *

  # Generate and write an ed25519 key pair.  The private key is encrypted
  # before it is saved.  A 'password' argument may be supplied, otherwise a
  # prompt is presented.
  >>> generate_and_write_ed25519_keypair('/path/to/ed25519_key')
  Enter a password for the ED25519 key: 
  Confirm:

  # Import the ed25519 public key just created . . .
  >>> public_ed25519_key = import_ed25519_publickey_from_file('/path/to/ed25519_key.pub')

  # and its corresponding private key.
  >>> private_ed25519_key = import_ed25519_privatekey_from_file('/path/to/ed25519_key')
  Enter a password for the encrypted ED25519 key: 


The repository tool can use the imported cryptographic keys to sign particular
roles.  In the code sample that follows, an 'on-pypi' key is loaded for the
*snapshot* role and the signed *snapshot* metadata file written to disk with
**repository.write()**:

.. code-block::
  
  repository.snapshot.load_signing_key(import_ed25519_privatekey_from_file("keystore/snapshot", password='pw'))
  repository.write()


How are signatures generated?
-----------------------------

Using the Ed25519 signature scheme, the "signed" dictionary entry of JSON
metadata is transformed to its `canonical JSON`__ form to produce repeatable
signatures and hashes.  The generated Ed25519 signature is appended to the
"signatures" entry of JSON metadata.

__ http://wiki.laptop.org/go/Canonical_JSON


Signed JSON metadata has the following format:

.. code-block::

  {
    "signed" : ROLE,
    "signatures" : [
      { "keyid" : KEYID,
        "method" : METHOD,
        "sig" : SIGNATURE,
      },
      ...
    ]
  }

ROLE is a dictionary whose "_type" field describes the role type.  KEYID is the
identifier (64-byte hexstring) of the key that signs the ROLE dictionary.
METHOD is the key signing method used to generate the signature.  Specifically,
the string: "ed25519".  SIGNATURE is an Ed25519 signature (128-byte hexstring)
of the canonical JSON form of ROLE.


Number Of Keys Recommended
--------------------------

The *timestamp*, *snapshot*, and *pypi-signed* roles require continuous
delivery.  Even though their respective keys MUST be on-pypi, this PEP requires
that the keys be independent of each other.  Different keys for pypi-signed
roles allow for each of the keys to be placed on separate servers if need be,
and prevents the compromise of one key from automatically compromising the rest
of the keys.  Therefore, each of the *timestamp*, *snapshot*, and *pypi-signed*
roles MUST require (1, 1) keys.

The *pypi-signed* role MAY delegate targets in an automated manner to a number
of roles called "bins", as discussed in the previous section.  Each of the
"bin" roles SHOULD share the same key as the *pypi-signed* role, due to space
efficiency, and because there is no security advantage to requiring separate
keys.

The *root* role key is critical for security and should very rarely be used.
It is primarily used for key revocation, and it is the locus of trust for all
of PyPI.  The *root* role signs for the keys that are authorized for each of
the top-level roles (including its own).  Keys belonging to the *root* role are
intended to be very well-protected and used with the least frequency of all
keys.  It is RECOMMENDED that every PSF board member own a (strong) root key.
A majority of them can then constitute a quorum to revoke or endow trust in all
top-level keys.  Alternatively, the system administrators of PyPI could be
given responsibility for signing for the *root* role.  Therefore, the *root*
role SHOULD require (t, n) keys, where n is the number of either all PyPI
administrators or all PSF board members, and t > 1 (so that at least two
members must sign the *root* role).

The *targets* role will be used only to sign for the static delegation of all
targets to the *pypi-signed* role.  Since these target delegations must be
secured against attacks in the event of a compromise, the keys for the
*targets* role MUST be off-pypi and independent of other keys.  For simplicity
of key management, without sacrificing security, it is RECOMMENDED that the
keys of the *targets* role be permanently discarded as soon as they have been
created and used to sign for the role.  Therefore, the *targets* role SHOULD
require (1, 1) keys.  Again, this is because the keys are going to be
permanently discarded and more off-pypi keys will not help resist key recovery
attacks [21]_ unless diversity of keys is maintained.


On-pypi and off-pypi Keys Recommended for Each Role
---------------------------------------------------

In order to support continuous delivery, the *timestamp*, *snapshot*,
*pypi-signed* role keys MUST be stored on the PyPI infrastructure (on-pypi
keys).

As explained in the previous section, the *root* and *targets* role keys MUST
be off-pypi for maximum security: these keys will be off-pypi in the sense that
their private keys MUST NOT be stored on PyPI, though some of them MAY be
on-pypi in the private infrastructure of the project.


Management of Off-pypi Keys
---------------------------

The management of off-pypi keys, such as those expected to sign *root.json*,
can be burdensome to the PyPI administrators who are geographically distributed
around the world.  A security token, or software token, is a physical device
that authorized PyPI administrators can use to ease authentication and
management of keys not stored on PyPI infrastructure.  `Yubico`__ offers
physical devices, such as the `Yubikey`__ and YubiHSM (Hardware Security
Module), that can generate one-time passcodes, store secrets, and support
2-factor authentication & smart card functionality.  These devices are
inexpensive (typically $25 - $60) and small (the size of a regular USB thumb
drives, or smaller).  Yubico also provides `software projects`__ (many written
in Python) that developers can use to integrate Yubico products.

__ https://www.yubico.com/products/
__ https://www.yubico.com/products/yubikey-hardware/
__ https://github.com/Yubico/

Other security tokens available to PyPI adminisrators to assist in the
management of off-pypi keys include: `Plug-up`__ and `Digiflak`__.

__ http://sk.plug-up.com/
__ http://www.digiflak.com/product/


How Should Metadata be Generated?
=================================

Project developers expect the distributions they upload to PyPI to be
immediately available for download.  Unfortunately, there will be problems when
many readers and writers simultaneously access the same metadata and
distributions.  That is, there needs to be a way to ensure consistency of
metadata and repository files when multiple developers simultaneously update
the same metadata or distributions.  Without TUF, there are also issues with
consistency on PyPI, but the problem is more severe with signed metadata that
MUST keep track, in real-time, of the files available on PyPI.

Suppose that PyPI generates a *snapshot*, which describes the latest version of
every metadata (except *timestamp*), at specified version 1, and that a client
requests this *snapshot* from PyPI.  While the client is busy downloading this
*snapshot*, PyPI timestamps a new snapshot at, say, version 2.  Without
ensuring consistency of metadata, the client would find itself with a copy of
*snapshot* that is inconsistent with what is available on PyPI: this situation
is indistinguishable from arbitrary metadata injected by an attacker.  The
problem would also occur with mirrors that attempt to sync with PyPI.


Consistent Snapshots
--------------------

There are problems with consistency on PyPI with or without TUF.  TUF requires
that its metadata be consistent with the repository files, but how would the
metadata be kept consistent for projects that change all the time?  This
proposal addresses the problem of producing a consistent snapshot that captures
the state of all known projects at a given time.  Each snapshot should safely
coexist with any other snapshot, and be able to be deleted independently,
without affecting any other snapshot.

The strategy or method presented in this PEP is that every metadata or data
file managed by PyPI and written to disk MUST include in its filename the `hash
value`__ of the file.  How would this help clients that use the TUF protocol to
securely and consistently install or update a project from PyPI?

__ https://en.wikipedia.org/wiki/Cryptographic_hash_function

The first step of the TUF protocol requires the client to download the latest
*timestamp* metadata.  However, the client would not know in advance the hash
of the *timestamp* associated with the latest snapshot.  Therefore, PyPI MUST
redirect all HTTP GET requests for *timestamp* to the *timestamp* referenced in
the latest snapshot.  The *timestamp* role is the root of a tree of
cryptographic hashes that points to every other metadata that is meant to be
grouped together (i.e., clients request metadata in timestamp -> snapshot ->
root -> targets order).  Clients are able to retrieve any file from a snapshot
by deterministically including, in the request for the file, the hash of the
filename.  Assuming infinite disk space and no `hash collisions`__, a client
may safely read from one snapshot while PyPI produces another snapshot.

__ https://en.wikipedia.org/wiki/Collision_(computer_science)

In this simple but effective manner, PyPI is able to capture a consistent
snapshot of all projects and the associated metadata at a given time.  The next
subsection provides implementation details of this idea.

Note: This PEP does not prohibit using advanced file systems or tools to
produce consistent snapshots. There are two important reasons for why this PEP
proposes the simple solution.  First, the solution does not mandate that PyPI
use any particular file system or tool.  Second, the generic file-system based
approach allows mirrors to use extant file transfer tools such as rsync to
efficiently transfer consistent snapshots from PyPI.


Producing Consistent Snapshots
------------------------------

Given a project, PyPI is responsible for updating the *pypi-signed* metadata
(roles delegated by the *pypi-signed* role and signed with an on-pypi key).
Every project MUST upload its release in a single transaction.  The uploaded
set of files is called the "project transaction".  How PyPI MAY validate the
files in a project transaction is discussed in a later section.  For now, the
focus is on how PyPI will respond to a project transaction.

Every metadata and target file MUST include in its filename the `hex digest`__
of its `SHA-256`__ hash.  For this PEP, it is RECOMMENDED that PyPI adopt a
simple convention of the form: digest.filename, where filename is the original
filename without a copy of the hash, and digest is the hex digest of the hash.

__ http://docs.python.org/2/library/hashlib.html#hashlib.hash.hexdigest
__ https://en.wikipedia.org/wiki/SHA-2

When a project uploads a new transaction, the project transaction process MUST
add all new targets and relevant delegated *pypi-signed* metadata.  (It is
shown later in this section why the *pypi-signed* role will delegate targets to
a number of delegated *pypi-signed* roles.)  Finally, the project transaction
process MUST inform the snapshot process about new delegated *pypi-signed*
metadata.

Project transaction processes SHOULD be automated and MUST also be applied
atomically: either all metadata and targets -- or none of them -- are added.
The project transaction and snapshot processes SHOULD work concurrently.
Finally, project transaction processes SHOULD keep in memory the latest
*pypi-signed* metadata so that they will be correctly updated in new consistent
snapshots.

All project transactions MAY be placed in a single queue and processed
serially.  Alternatively, the queue MAY be processed concurrently in order of
appearance, provided that the following rules are observed:

1. No pair of project transaction processes must concurrently work on the same
   project.

2. No pair of project transaction processes must concurrently work on
   *pypi-signed* projects that belong to the same delegated *pypi-signed*
   targets role.

These rules MUST be observed so that metadata is not read from or written to
inconsistently.


Snapshot Process
----------------

The snapshot process is fairly simple and SHOULD be automated.  The snapshot
process MUST keep in memory the latest working set of *root*, *targets*, and
delegated roles.  Every minute or so, the snapshot process will sign for this
latest working set.  (Recall that project transaction processes continuously
inform the snapshot process about the latest delegated metadata in a
concurrency-safe manner.  The snapshot process will actually sign for a copy of
the latest working set while the latest working set in memory will be updated
with information that is continuously communicated by the project transaction
processes.)  The snapshot process MUST generate and sign new *timestamp*
metadata that will vouch for the metadata (*root*, *targets*, and delegated
roles) generated in the previous step.  Finally, the snapshot process MUST make
available to clients the new *timestamp* and *snapshot* metadata representing
the latest snapshot.

A few implementation notes are now in order.  So far, we have seen only that
new metadata and targets are added, but not that old metadata and targets are
removed.  Practical constraints are such that eventually PyPI will run out of
disk space to produce a new consistent snapshot.  In that case, PyPI MAY then
use something like a "mark-and-sweep" algorithm to delete sufficiently old
consistent snapshots: in order to preserve the latest consistent snapshot, PyPI
would walk objects beginning from the root (*timestamp*) of the latest
consistent snapshot, mark all visited objects, and delete all unmarked objects.
The last few consistent snapshots may be preserved in a similar fashion.
Deleting a consistent snapshot will cause clients to see nothing except HTTP
404 responses to any request for a file within that consistent snapshot.
Clients SHOULD then retry (as before) their requests with the latest consistent
snapshot.

All clients, such as pip using the TUF protocol, MUST be modified to download
every metadata and target file (except for *timestamp* metadata) by including,
in the request for the file, the cryptographic hash of the file in the
filename.  Following the filename convention recommended earlier, a request for
the file at filename.ext will be transformed to the equivalent request for the
file at digest.filename.

Finally, PyPI SHOULD use a `transaction log`__ to record project transaction
processes and queues so that it will be easier to recover from errors after a
server failure.

__ https://en.wikipedia.org/wiki/Transaction_log


Key Compromise Analysis
=======================

This PEP has covered the minimum security model, the TUF roles that should be
added to support continuous delivery of distributions, and how to generate and
sign the metadata of each role.  The remaining sections discuss how PyPI
SHOULD audit repository metadata, and the methods PyPI can use to detect and
recover from a PyPI compromise.

Table 1 summarizes a few of the attacks possible when a threshold number of
private cryptographic keys (belonging to any of the PyPI roles) are
compromised.  The leftmost column lists the roles (or a combination of roles)
that have been compromised, and the columns to its right show whether the
compromised roles leaves clients susceptible to malicious updates, a freeze
attack, or metadata inconsistency attacks.

+-----------------+-------------------+----------------+--------------------------------+
| Role Compromise | Malicious Updates | Freeze Attack  | Metadata Inconsistency Attacks |
+=================+===================+================+================================+
| timestamp       | NO                | YES            | NO                             |
|                 | snapshot and      | limited by     | snapshot needs to cooperate    |
|                 | targets or any    | earliest root, |                                |
|                 | of the            | targets, or    |                                |
|                 | pypi-signed bins  | pypi-signed    |                                | 
|                 | need to cooperate | bins expiry    |                                |
|                 |                   | time           |                                |
|                 |                   |                |                                |
+-----------------+-------------------+----------------+--------------------------------+
| snapshot        | NO                | NO             | NO                             |
|                 | timestamp and     | timestamp      | timestamp needs to cooperate   |
|                 | targets or any of | needs to       |                                |
|                 | the pypi-signed   | cooperate      |                                |
|                 | bins need to      |                |                                |
|                 | cooperate         |                |                                |
+-----------------+-------------------+----------------+--------------------------------+
| timestamp       | NO                | YES            | YES                            |
| **AND**         | targets or any    | limited by     | limited by earliest root,      |
| snapshot        | of the            | the earliest , | targets, or pypi-signed        |
|                 | pypi-signed bins  | root, targets, | metadata expiry time           |
|                 | need to cooperate | or pypi-signed |                                |
|                 |                   | bins expiry    |                                |
|                 |                   | time           |                                |
+-----------------+-------------------+----------------+--------------------------------+
| targets         | NO                | NOT APPLICABLE | NOT APPLICABLE                 |
| **OR**          | timestamp and     | need timestamp | need timestamp and snapshot    |
| pypi-signed     | snapshot need to  | and snapshot   |                                |
|                 | cooperate         |                |                                |
+-----------------+-------------------+----------------+--------------------------------+
| timestamp       | YES               | YES            | YES                            |
| **AND**         |                   | limited by     | limited by earliest root,      |
| snapshot        |                   | earliest root, | targets, or pypi-signed        |
| **AND**         |                   | targets, or    | metadata expiry time           |
| pypi-signed     |                   | pypi-signed    |                                |
|                 |                   | expiry time    |                                |
+-----------------+-------------------+----------------+--------------------------------+
| root            | YES               | YES            | YES                            |
+-----------------+-------------------+----------------+--------------------------------+

Table 1: Attacks possible by compromising certain combinations of role keys.
In `September 2013`__, it was shown how the latest version (at the time) of pip
was susceptible to these attacks  and how TUF could protect users against them
[14]_.

__ https://mail.python.org/pipermail/distutils-sig/2013-September/022755.html

Note that compromising *targets* or any delegated role (except for project
targets metadata) does not immediately allow an attacker to serve malicious
updates.  The attacker must also compromise the *timestamp* and *snapshot*
roles (which are both on-pypi and therefore more likely to be compromised).
This means that in order to launch any attack, one must not only be able to
act as a man-in-the-middle but also compromise the *timestamp* key (or
compromise the *root* keys and sign a new *timestamp* key).  To launch any
attack other than a freeze attack, one must also compromise the *snapshot* key.

Finally, a compromise of the PyPI infrastructure MAY introduce malicious
updates to *pypi-signed* projects because the keys for these roles are on-pypi.
The maximum security model discussed in the appendix addresses this issue.  PEP
480 also covers the maximum security model and goes into more detail on
generating developer keys and signing uploaded distributions.


In the Event of a Key Compromise
--------------------------------

A key compromise means that a threshold of keys (belonging to the metadata
roles on PyPI), as well as the PyPI infrastructure, have been compromised and
used to sign new metadata on PyPI.

If a threshold number of *timestamp*, *snapshot*, or *pypi-signed* keys have
been compromised, then PyPI MUST take the following steps:

1. Revoke the *timestamp*, *snapshot* and *targets* role keys from
   the *root* role.  This is done by replacing the compromised *timestamp*,
   *snapshot* and *targets* keys with newly issued keys.

2. Revoke the *pypi-signed* keys from the *targets* role by replacing their
   keys with newly issued keys.  Sign the new *targets* role metadata and
   discard the new keys (because, as explained earlier, this increases the
   security of *targets* metadata).

3. All targets of the *pypi-signed* roles SHOULD be compared with the last
   known good consistent snapshot where none of the *timestamp*, *snapshot*, or
   *pypi-signed* keys were known to have been compromised.  Added, updated, or
   deleted targets in the compromised consistent snapshot that do not match the
   last known good consistent snapshot MAY be restored to their previous
   versions.  After ensuring the integrity of all *pypi-signed* targets, the
   *pypi-signed* metadata MUST be regenerated.

4. The *pypi-signed* metadata MUST have their version numbers incremented,
   expiry times suitably extended, and signatures renewed.

5. A new timestamped consistent snapshot MUST be issued.

Following these steps would preemptively protect all of these roles even though
only one of them may have been compromised.

If a threshold number of *root* keys have been compromised, then PyPI MUST take
the steps taken when the *targets* role has been compromised.  All of the
*root* keys must also be replaced.

In order to replace a compromised *root* key or any other top-level role key,
the *root* role signs a new *root.json* file that lists the updated trusted
keys for the role. When replacing *root* keys, PyPI will sign the new
*root.json* file with both the new and old root keys until all clients are
known to have obtained the new *root.json* file (a safe assumption is that this
will be a very long time or never).  Since *root.json* is only updated by
clients that already trust a threshold number of the keys included in the new
*root.json*, setting aside reserved off-pypi keys to sign *root.json*
specifically for outdated clients is an option.  There is no risk posed by
continuing to sign the *root.json* file with revoked keys because once clients
have updated they no longer trust the revoked key.  This is only to ensure that
outdated clients remain able to update. 

It is also RECOMMENDED that PyPI sufficiently document compromises with
security bulletins.  These security bulletins will be most informative when
users of pip-with-TUF are unable to install or update a project because the
keys for the *timestamp*, *snapshot* or *root* roles are no longer valid.  They
could then visit the PyPI web site to consult security bulletins that would
help to explain why they are no longer able to install or update, and then take
action accordingly.  When a threshold number of *root* keys have not been
revoked due to a compromise, then new *root* metadata may be safely updated
because a threshold number of existing *root* keys will be used to sign for the
integrity of the new *root* metadata.  TUF clients will be able to verify the
integrity of the new *root* metadata with a threshold number of previously
known *root* keys.  This will be the common case.  Otherwise, in the worst
case, where a threshold number of *root* keys have been revoked due to a
compromise, an end-user may choose to update new *root* metadata with
`out-of-band`__ mechanisms.

__ https://en.wikipedia.org/wiki/Out-of-band#Authentication


Auditing Snapshots
------------------

If a malicious party compromises PyPI, they can sign arbitrary files with any
of the on-pypi keys.  The roles with off-pypi keys (i.e., *root* and *targets*)
are still protected.  To safely recover from a repository compromise, snapshots
should be audited to ensure files are only restored to trusted versions.

When a repository compromise has been detected, the integrity of three types of
information must be validated:

1. If the on-pypi keys of the repository have been compromised, they can be
   revoked by having the *targets* role sign new metadata delegating to a new
   key.

2. If the role metadata on the repository has been changed, this would impact
   the metadata that is signed by on-pypi keys.  Any role information created
   since the last period should be discarded. As a result, developers of new
   projects will need to re-register their projects.

3. If the packages themselves may have been tampered with, they can be
   validated using the stored hash information for packages that existed at the
   time of the last period.

In order to safely restore snapshots in the event of a compromise, PyPI SHOULD
maintain a small number of its own mirrors to copy PyPI snapshots according to
some schedule.  The mirroring protocol can be used immediately for this
purpose.  The mirrors must be secured and isolated such that they are
responsible only for mirroring PyPI.  The mirrors can be checked against one
another to detect accidental or malicious failures.

Another approach is to generate the cryptographic hash of *snapshot*
periodically and tweet it.  Perhaps a user comes forward with the actual
metadata and the repository maintainers can verify the metadata's cryptographic
hash.  Alternatively, PyPI may periodically archive its own versions of
*snapshot* rather than rely on externally provided metadata.  In this case,
PyPI SHOULD take the cryptographic hash of every package on the repository and
store this data on an off-pypi device. If any package hash has changed, this
indicates an attack.

As for attacks that serve different versions of metadata, or freeze a version
of a package at a specific version, they can be handled by TUF with techniques
like implicit key revocation and metadata mismatch detection.


Appendix A: Repository Attacks Prevented by TUF
===============================================

* **Arbitrary software installation**: An attacker installs anything they want
  on the client system. That is, an attacker can provide arbitrary files in
  respond to download requests and the files will not be detected as
  illegitimate.

* **Rollback attacks**: An attacker presents a software update system with
  older files than those the client has already seen, causing the client to use
  files older than those the client knows about.

* **Indefinite freeze attacks**: An attacker continues to present a software
  update system with the same files the client has already seen. The result is
  that the client does not know that new files are available.

* **Endless data attacks**: An attacker responds to a file download request
  with an endless stream of data, causing harm to clients (e.g., a disk
  partition filling up or memory exhaustion).

* **Slow retrieval attacks**: An attacker responds to clients with a very slow
  stream of data that essentially results in the client never continuing the
  update process.

* **Extraneous dependencies attacks**: An attacker indicates to clients that in
  order to install the software they wanted, they also need to install
  unrelated software.  This unrelated software can be from a trusted source
  but may have known vulnerabilities that are exploitable by the attacker.

* **Mix-and-match attacks**: An attacker presents clients with a view of a
  repository that includes files that never existed together on the repository
  at the same time. This can result in, for example, outdated versions of
  dependencies being installed.

* **Wrong software installation**: An attacker provides a client with a trusted
  file that is not the one the client wanted.

* **Malicious mirrors preventing updates**: An attacker in control of one
  repository mirror is able to prevent users from obtaining updates from
  other, good mirrors.

* **Vulnerability to key compromises**: An attacker who is able to compromise a
  single key or less than a given threshold of keys can compromise clients.
  This includes relying on a single on-pypi key (such as only being protected
  by SSL) or a single off-pypi key (such as most software update systems use
  to sign files).


Appendix B: Extension to the Minimum Security Model
===================================================

The maximum security model and end-to-end signing have been intentionally
excluded from this PEP.  Although both improve PyPI's ability to survive a
repository compromise and allow developers to sign their distributions, they
have been postponed for review as a potential future extension to PEP 458.  PEP
480 [26]_, which discusses the extension in detail, is available for review to
those developers interested in the end-to-end signing option.  The maximum
security model and end-to-end signing are briefly covered in subsections that
follow.

There are several reasons for not initially supporting the features discussed
in this section:

1. A build farm (distribution wheels on supported platforms are generated for
   each project on PyPI infrastructure) may possibly complicate matters.  PyPI
   wants to support a build farm in the future.  Unfortunately, if wheels are
   auto-generated externally, developer signatures for these wheels are
   unlikely.  However, there might still be a benefit to generating wheels from
   source distributions that are signed by developers (provided that
   reproducible wheels are possible).  Another possibility is to optionally
   delegate trust of these wheels to an on-pypi role.

2. An easy-to-use key management solution is needed for developers.
   `miniLock`__ is one likely candidate for management and generation of keys.
   Although developer signatures can remain optional, this approach may be
   inadequate due to the great number of potentially unsigned dependencies each
   distribution may have.  If any one of these dependencies is unsigned, it
   negates any benefit the project gains from signing its own distribution
   (i.e., attackers would only need to compromise one of the unsigned
   dependencies to attack end-users).  Requiring developers to manually sign
   distributions and manage keys is expected to render key signing an unused
   feature.

   __ https://minilock.io/

3. A two-phase approach, where the minimum security model is implemented first
   followed by the maximum security model, can simplify matters and give PyPI
   administrators time to review the feasibility of end-to-end signing.


Maximum Security Model
----------------------

The maximum security model relies on developers signing their projects and
uploading signed metadata to PyPI.  If the PyPI infrastructure were to be
compromised, attackers would be unable to serve malicious versions of
developer-signed projects without access to the project's developer key.
Figure 3 depicts the changes made to figure 2, namely that developer roles are
now supported and that two new delegated roles exist: *developer-signed* and
*recently-developer-signed*.  The *pypi-signed* role has not changed and can
contain any projects that have not been added to *developer-signed*.  The
strength of this model (over the minimum security model) is in the off-pypi
keys provided by developers.  Although the minimum security model supports
continuous delivery, all of the projects are signed by an on-pypi key.  An
attacker can corrupt packages in the minimum security model, but not in the
maximum model, without also compromising a developer's key.

.. image:: pep-0458-4.png

Figure 3: An overview of the metadata layout in the maximum security model.
The maximum security model supports continuous delivery and survivable key
compromise.


End-to-End Signing
------------------

End-to-End signing allows both PyPI and developers to sign for the metadata
downloaded by clients.  PyPI is trusted to make uploaded projects available to
clients (they sign the metadata for this part of the process), and developers
can sign the distributions that they upload.

PEP 480 [26]_ discusses the tools available to developers who sign the
distributions that they upload to PyPI.  To summarize PEP 480, developers
generate cryptographic keys and sign metadata in some automated fashion, where
the metadata includes the information required to verify the authenticity of
the distribution.  The metadata is then uploaded to PyPI by the client, where
it will be available for download by package managers such as pip (i.e.,
package managers that support TUF metadata).  The entire process is transparent
to clients (using a package manager that supports TUF) who download
distributions from PyPI.


Appendix C: PEP 470 and Projects Hosted Externally
==================================================

How should TUF handle distributions that are not hosted on PyPI?  According to
`PEP 470`__, projects may opt to host their distributions externally and are
only required to provide PyPI a link to its external index, which package
managers like pip can use to find the project's distributions.  PEP 470 does
not mention whether externally hosted projects are considered unverified by
default, as projects that use this option are not required to submit any
information about their distributions (e.g., file size and cryptographic hash)
when the project is registered, nor include a cryptographic hash of the file
in download links.

__ http://www.python.org/dev/peps/pep-0470/

Potentional approaches that PyPI administrators MAY consider to handle
projects hosted externally:

1.  Download external distributions but do not verify them.  The targets
    metadata will not include information for externally hosted projects.

2.  PyPI will periodically download information from the external index.  PyPI
    will gather the external distribution's file size and hashes and generate
    appropriate TUF metadata.

3.  External projects MUST submit to PyPI the file size and cryptographic hash
    for a distribution.

4.  External projects MUST upload to PyPI a developer public key for the
    index.  The distribution MUST create TUF metadata that is stored at the
    index, and signed with the developer's corresponding private key.  The
    client will fetch the external TUF metadata as part of the package
    update process.

5.  External projects MUST upload to PyPI signed TUF metadata (as allowed by
    the maximum security model) about the distributions that they host
    externally, and a developer public key.  Package managers verify
    distributions by consulting the signed metadata uploaded to PyPI.

Only one of the options listed above should be implemented on PyPI.  Option
(4) or (5) is RECOMMENDED because external distributions are signed by
developers. External distributions that are forged (due to a compromised
PyPI account or external host) may be detected if external developers are
required to sign metadata, although this requirement is likely only practical
if an easy-to-use key management solution and developer scripts are provided
by PyPI.


References
==========

.. [1] https://pypi.python.org
.. [2] https://isis.poly.edu/~jcappos/papers/samuel_tuf_ccs_2010.pdf
.. [3] http://www.pip-installer.org
.. [4] https://wiki.python.org/moin/WikiAttack2013
.. [5] https://github.com/theupdateframework/pip/wiki/Attacks-on-software-repositories
.. [6] https://mail.python.org/pipermail/distutils-sig/2013-April/020596.html
.. [7] https://mail.python.org/pipermail/distutils-sig/2013-May/020701.html
.. [8] https://mail.python.org/pipermail/distutils-sig/2013-July/022008.html
.. [9] PEP 381, Mirroring infrastructure for PyPI, Ziadé, Löwis
       http://www.python.org/dev/peps/pep-0381/
.. [10] https://mail.python.org/pipermail/distutils-sig/2013-September/022773.html
.. [11] https://mail.python.org/pipermail/distutils-sig/2013-May/020848.html
.. [12] PEP 449, Removal of the PyPI Mirror Auto Discovery and Naming Scheme, Stufft
        http://www.python.org/dev/peps/pep-0449/
.. [13] https://isis.poly.edu/~jcappos/papers/cappos_mirror_ccs_08.pdf
.. [14] https://mail.python.org/pipermail/distutils-sig/2013-September/022755.html
.. [15] https://pypi.python.org/security
.. [16] https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt
.. [17] PEP 426, Metadata for Python Software Packages 2.0, Coghlan, Holth, Stufft
        http://www.python.org/dev/peps/pep-0426/
.. [18] https://en.wikipedia.org/wiki/Continuous_delivery
.. [19] https://mail.python.org/pipermail/distutils-sig/2013-August/022154.html
.. [20] https://en.wikipedia.org/wiki/RSA_%28algorithm%29
.. [21] https://en.wikipedia.org/wiki/Key-recovery_attack
.. [22] http://csrc.nist.gov/publications/nistpubs/800-57/SP800-57-Part1.pdf
.. [23] https://www.openssl.org/
.. [24] https://pypi.python.org/pypi/pycrypto
.. [25] http://ed25519.cr.yp.to/
.. [26] https://www.python.org/dev/peps/pep-0480/
.. [27] https://github.com/pyca/ed25519


Acknowledgements
================

This material is based upon work supported by the National Science Foundation
under Grants No. CNS-1345049 and CNS-0959138. Any opinions, findings, and
conclusions or recommendations expressed in this material are those of the
author(s) and do not necessarily reflect the views of the National Science
Foundation.

We thank Nick Coghlan, Daniel Holth and the distutils-sig community in general
for helping us to think about how to usably and efficiently integrate TUF with
PyPI.

Roger Dingledine, Sebastian Hahn, Nick Mathewson, Martin Peck and Justin Samuel
helped us to design TUF from its predecessor Thandy of the Tor project.

We appreciate the efforts of Konstantin Andrianov, Geremy Condra, Zane Fisher,
Justin Samuel, Tian Tian, Santiago Torres, John Ward, and Yuyu Zheng to to
develop TUF.

Vladimir Diaz, Monzur Muhammad and Sai Teja Peddinti helped us to review this
PEP.

Zane Fisher helped us to review and transcribe this PEP.

Copyright
=========

This document has been placed in the public domain.
