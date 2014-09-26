PEP: 458
Title: Surviving a Compromise of PyPI
Version: $Revision$
Last-Modified: $Date$
Author: Trishank Karthik Kuppusamy <trishank@nyu.edu>,
        Donald Stufft <donald@stufft.io>,
        Justin Cappos <jcappos@nyu.edu>
BDFL-Delegate: Nick Coghlan <ncoghlan@gmail.com>
Discussions-To: DistUtils mailing list <distutils-sig@python.org>
Status: Draft
Type: Standards Track
Content-Type: text/x-rst
Created: 27-Sep-2013


Abstract
========

This PEP describes how the Python Package Index (PyPI [1]_) may be integrated
with The Update Framework [2]_ (TUF).  TUF was designed to be a plug-and-play
security add-on to a software updater or package manager.  TUF provides
end-to-end security like SSL, but for software updates instead of HTTPS
connections.  The framework integrates best security practices such as
separating responsibilities, adopting the many-man rule for signing packages,
keeping signing keys offline, and revocation of expired or compromised signing
keys.

The proposed integration will render modern package managers such as pip [3]_
more secure against various types of security attacks on PyPI and protect users
against them.  Even in the worst case where an attacker manages to compromise
PyPI itself, the damage is controlled in scope and limited in duration.

Specifically, this PEP will describe how PyPI processes should be adapted to
incorporate TUF metadata.  It will not prescribe how package managers such as
pip should be adapted to install or update with TUF metadata projects from
PyPI.


Rationale
=========

In January 2013, the Python Software Foundation (PSF) announced [4]_ that the
python.org wikis for Python, Jython, and the PSF were subjected to a security
breach that caused all of the wiki data to be destroyed on January 5 2013.
Fortunately, the PyPI infrastructure was not affected by this security breach.
However, the incident is a reminder that PyPI should take defensive steps to
protect users as much as possible in the event of a compromise.  Attacks on
software repositories happen all the time [5]_.  The PSF must accept the
possibility of security breaches and prepare PyPI accordingly because it is a
valuable target used by thousands, if not millions, of people.

Before the wiki attack, PyPI used MD5 hashes to tell package managers such as
pip whether or not a package was corrupted in transit.  However, the absence of
SSL made it hard for package managers to verify transport integrity to PyPI.
It was easy to launch a man-in-the-middle attack between pip and PyPI to change
package content arbitrarily.  This can be used to trick users into installing
malicious packages.  After the wiki attack, several steps were proposed (some
of which were implemented) to deliver a much higher level of security than was
previously the case: requiring SSL to communicate with PyPI [6]_, restricting
project names [7]_, and migrating from MD5 to SHA-2 hashes [8]_.

These steps, though necessary, are insufficient because attacks are still
possible through other avenues.  For example, a public mirror is trusted to
honestly mirror PyPI, but some mirrors may misbehave due to malice or accident.
Package managers such as pip are supposed to use signatures from PyPI to verify
packages downloaded from a public mirror [9]_, but none are known to actually
do so [10]_.  Therefore, it is also wise to add more security measures to
detect attacks from public mirrors or content delivery networks [11]_ (CDNs).

Even though official mirrors are being deprecated on PyPI [12]_, there remain a
wide variety of other attack vectors on package managers [13]_.  Among other
things, these attacks can crash client systems, cause obsolete packages to be
installed, or even allow an attacker to execute arbitrary code.  In September
2013, we showed how the latest version of pip (at the time) was susceptible to
these attacks and how TUF could protect users against them [14]_.

Finally, PyPI allows for packages to be signed with GPG keys [15]_, although no
package manager is known to verify those signatures, thus negating much of the
benefits of having those signatures at all.  Validating integrity through
cryptography is important, but issues such as immediate and secure key
revocation or specifying a required threshold number of signatures still
remain.  Furthermore, GPG by itself does not immediately address the attacks
mentioned above.

In order to protect PyPI against infrastructure compromises, we propose
integrating PyPI with The Update Framework [2]_ (TUF).


Definitions
===========

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119__.

__ http://www.ietf.org/rfc/rfc2119.txt

In order to keep this PEP focused mostly on the application of TUF on PyPI, the
reader is encouraged to read about the design principles of TUF [2]_.  It is
also RECOMMENDED that the reader be familiar with the TUF specification [16]_.

* Projects: Projects are software components that are made available for
  integration.  Projects include Python libraries, frameworks, scripts, plugins,
  applications, collections of data or other resources, and various
  combinations thereof.  Public Python projects are typically registered on the
  Python Package Index [17]_.

* Releases: Releases are uniquely identified snapshots of a project [17]_.

* Distributions: Distributions are the packaged files that are used to publish
  and distribute a release [17]_.

* Simple index: The HTML page that contains internal links to the
  distributions of a project [17]_.

* Consistent snapshot: A set of TUF metadata and PyPI targets that capture the
  complete state of all projects on PyPI as they were at some fixed point in
  time.

* The *snapshot* (*release*) role: In order to prevent confusion due
  to the different meanings of the term "release" as employed by PEP 426 [17]_
  and the TUF specification [16]_, we rename the *release* role as the
  *snapshot* role.

* Continuous delivery: A set of processes with which PyPI produces consistent
  snapshots that can safely coexist and deleted independently [18]_.

* Developer: Either the owner or maintainer of a project who is allowed to
  update the TUF metadata as well as distribution metadata and data for the
  project.

* Online key: A key that MUST be stored on the PyPI server infrastructure.
  This is usually to allow automated signing with the key.  However, an
  attacker who compromises PyPI infrastructure will be able to read these keys.

* Offline key: A key that MUST be stored off the PyPI infrastructure.  This
  prevents automated signing with the key.  An attacker who compromises PyPI
  infrastructure will not be able to immediately read these keys.

* Threshold signature scheme: A role can increase its resilience to key
  compromises by specifying that at least t out of n keys are REQUIRED to sign
  its metadata.  A compromise of t-1 keys is insufficient to compromise the
  role itself.  Saying that a role requires (t, n) keys denotes the threshold
  signature property.


Overview of TUF
===============

TUF helps secure new or existing software update systems. Software update
systems are vulnerable to many known attacks, including those that can result
in clients being compromised or crashed. TUF solves these problem by providing
a flexible security framework that can be added to software updaters.

At the highest level, TUF simply provides applications with a secure method of
obtaining files and knowing when new versions of files are available. On the
surface, this all sounds simple. Securely obtaining updates just means:

  * Knowing when an update exists.
  * Downloading the updated file.

The problem is that this is only simple when there are no malicious parties
involved. If an attacker is trying to interfere with these seemingly simple
steps, there is plenty they can do.


Repository Attacks Prevented by TUF
-----------------------------------

* **Arbitrary software installation**: An attacker installs anything they want
  on the client system. That is, an attacker can provide arbitrary files in
  response to download requests and the files will not be detected as
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
  unrelated software.  This unrelated software can be from a trusted source but
  may have known vulnerabilities that are exploitable by the attacker.

* **Mix-and-match attacks**: An attacker presents clients with a view of a
  repository that includes files that never existed together on the repository
  at the same time. This can result in, for example, outdated versions of
  dependencies being installed.

* **Wrong software installation**: An attacker provides a client with a trusted
  file that is not the one the client wanted.

* **Malicious mirrors preventing updates**: An attacker in control of one
  repository mirror is able to prevent users from obtaining updates from other,
  good mirrors.

* **Vulnerability to key compromises**: An attacker who is able to compromise a
  single key or less than a given threshold of keys can compromise clients.
  This includes relying on a single online key (such as only being protected by
  SSL) or a single offline key (such as most software update systems use to
  sign files).


What Repository Changes are Required on PyPI?
---------------------------------------------

In order for package managers like pip to download and verify packages with
TUF, a few extra files are required to exist on PyPI. These extra repository
files are called TUF metadata. TUF metadata contains information like which
keys are trusted, the cryptographic hashes of files, signatures on the
metadata, metadata version numbers, and the date after which the metadata
should be considered expired.

When a package manager wants to check for updates, it asks TUF to do the work.
That is, a package manager never has to deal with this additional metadata or
understand what's going on underneath. If TUF reports back that there are
updates available, a package manager can then ask TUF to download these files
from PyPI. TUF downloads them and checks them against the TUF metadata that it
also downloads from the repository. If the downloaded target files are
trustworthy, TUF then hands them over to the package manager.

`Metadata`__ provides information about each of the required metadata files and
their expected content.  The next section covers the different kinds of
metadata recommended for PyPI.

__ https://github.com/theupdateframework/tuf/blob/develop/METADATA.md


PyPI and TUF Metadata
=====================

TUF metadata provides information that clients can use to make update
decisions.  For example, a targets metadata file can list the available
packages on PyPI and include their signatures, cryptographic hashes, and file
sizes.  Different metadata files provide different information.  The various
metadata files are signed by different roles as are indicated by the *root*
role.  The concept of roles allows TUF to delegate responsiblities to multiple
roles and minimize the impact of a compromised role.

TUF requires four top-level roles.  They are *root*, *timestamp*, *snapshot*
and *targets*.  The *root* role specifies the keys of the top-level roles
(including itself).  The *timestamp* role references the latest *snapshot* and
can signify when a new snapshot of the repository is available.  The *snapshot*
role indicates the latest version of all the TUF metadata files (other than
*timestamp*).  The *targets* role lists the available target files (in our
case, it will be all files on PyPI under the /simple and /packages
directories).  Each top-level role will serve its responsibilities without
exception.

Figure 1 provides an overview of the roles available on PyPI, which includes
the top-level roles and the roles delegated by *targets*.  The figure also
indicates the types of keys used to sign each role and which roles are trusted
to sign for the targets, or files, available on PyPI.  The next two sections
cover the details of signing repository files and the types of keys used for
each role.

.. image:: figure1.png

Figure 1: An overview of the role metadata available on PyPI.


How Should TUF Metadata be Signed?
----------------------------------

The top-level *root* role signs for the keys of the top-level *timestamp*,
*snapshot*, *targets* and *root* roles.  The *timestamp* role signs for every
new snapshot of the repository metadata.  The *snapshot* role signs for *root*,
*targets* and all delegated targets metadata.  The *bins* role signs for all
distributions belonging to registered PyPI projects.

The metadata files that change most frequently will be *timestamp*, *snapshot*
and delegated targets (*bins* projects) metadata.  The *timestamp* and
*snapshot* metadata MUST be updated whenever *root*, *targets* or delegated
targets metadata are updated.  Observe, though, that *root* and *targets*
metadata are much less likely to be updated as often as delegated targets
metadata.  Therefore, *timestamp* and *snapshot* metadata will most likely be
updated frequently (possibly every minute) due to delegated targets metadata
being updated frequently in order to drive continuous delivery of projects.

Every year, PyPI administrators are going to sign for *root* role keys.  After
that, automation will continuously sign for a timestamped, snapshot of all
projects.  There is a `repository management`__ tool available that can handle
signing metadata files, generating cryptographic keys, and managing a TUF
repository.

__ https://github.com/theupdateframework/tuf/tree/develop/tuf#repository-management


Minimum Security Model
----------------------

The minimum security model (this PEP) requires no action from a developer and
protects against malicious CDNs [19]_ and public mirrors.  To support
continuous delivery of uploaded packages, PyPI signs for projects with an
online key.  This level of security prevents projects from being accidentally
or deliberately tampered by a mirror or a CDN because the mirror or CDN will
not have any of the keys required to sign for projects.  It also does not
protect projects from attackers who have compromised PyPI, since attackers can
manipulate TUF metadata using the keys stored online.   An extension to this
PEP, discussed in Appendix A, offers the maximum security model and allows
a developer to sign for his/her project.  Developer keys are not stored online:
therefore, projects are safe from PyPI compromises.

This PEP proposes that the *bins* role (and its delegated roles) sign for all
PyPI projects with an online key.  The *targets* role, which only signs with an
offline key, MUST delegate all PyPI projects to the *bins* role.  This means
that when package manager such as pip (with TUF) downloads a distribution from
a project on PyPI, it will consult the *bins* role about the TUF metadata for
the project.  If none of bin roles delegated by *bins* specify the project's
distribution, then the project is considered to be non-existent on PyPI.


Metadata Expiry Times
---------------------

The *root* and *targets* role metadata SHOULD expire in a year, because these
two metadata files are expected to change very rarely.

The *timestamp*, *snapshot*, and *bins* metadata SHOULD expire in a day because
a CDN or mirror SHOULD synchronize itself with PyPI every day.  Furthermore,
this generous time frame also takes into account client clocks that are highly
skewed or adrift.


Metadata Scalability
--------------------

Due to the growing number of projects and distributions, TUF metadata will also
grow correspondingly.  For example, consider the *bins* role.  In August 2013,
it was found that the size of the *bins* metadata was about 42MB if the *bins*
role itself signed for about 220K PyPI targets (which are simple indices and
distributions).  We will not delve into details in this PEP, but TUF features a
so-called "`lazy bin walk`__" scheme that splits a large targets or delegated
targets metadata file into many small ones.  This allows a TUF client updater
to intelligently download only a small number of TUF metadata files in order to
update any project signed for by the *bins* role.  For example, applying this
scheme to the previous repository resulted in pip downloading between 1.3KB and
111KB to install or upgrade a PyPI project via TUF.

__ https://github.com/theupdateframework/tuf/issues/39

From our findings as of the time of writing, PyPI SHOULD split all targets in
the *bins* role by delegating it to 1024 delegated targets roles, each of which
would sign for PyPI targets whose hashes fall into that "bin" or delegated
targets role (see Figure 1).  We found that 1024 bins would result in the
*bins* metadata and each of its bins delegated targets metadata to be about the
same size (40-50KB) for about 220K PyPI targets (simple indices and
distributions).

It is possible to make TUF metadata more compact by representing it in a binary
format as opposed to the JSON text format.  Nevertheless, we believe that a
sufficiently large number of projects and distributions will induce scalability
challenges at some point, and therefore the *bins* role will then still need
delegations in order to address the problem.  Furthermore, the JSON format is
an open and well-known standard for data interchange.  Due to the large number
of delegated target metadata files, compressed versions of *snapshot* metadata
SHOULD also be made available.


PyPI and Key Requirements
=========================

In this section, the kinds of keys required to sign for TUF roles on PyPI is
examined.  TUF is agnostic with respect to choices of digital signature
algorithms.  For the purpose of discussion, we will assume that most digital
signatures will be produced with the well-tested and tried RSA algorithm [20]_.
Nevertheless, we do NOT recommend any particular digital signature algorithm in
this PEP because there are a few important constraints: firstly, cryptography
changes over time; secondly, package managers such as pip may wish to perform
signature verification in Python, without resorting to a compiled C library, in
order to be able to run on as many systems as Python supports; finally, TUF
recommends diversity of keys for certain applications.


Number Of Keys Recommended
--------------------------

The *timestamp*, *snapshot*, and *bins* roles will need to support continuous
delivery.  Even though their respective keys will then need to be online, this
PEP requires that the keys be independent of each other.  Different keys for
online roles allows for each of the keys to be placed on separate servers if
need be, and prevents side channel attacks that compromise one key from
automatically compromising the rest of the keys.  Therefore, each of the
*timestamp*, *snapshot*, and *bins* roles MUST require (1, 1) keys.

The *bins* role MAY delegate targets in an automated manner to a number of
roles called "bins", as we discussed in the previous section.  Each of the
"bin" roles SHOULD share the same key as the *bins* role, due
simultaneously to space efficiency of metadata and because there is no security
advantage in requiring separate keys.

The *root* role is critical for security and should very rarely be used.  It is
primarily used for key revocation, and it is the root of trust for all of PyPI.
The *root* role signs for the keys that are authorized for each of the
top-level roles (including itself).  The keys belonging to the *root* role are
intended to be very well-protected and used with the least frequency of all
keys.  We propose that every PSF board member own a (strong) root key.  A
majority of them can then constitute the quorum to revoke or endow trust in all
top-level keys.  Alternatively, the system administrators of PyPI (instead of
PSF board members) could be responsible for signing for the *root* role.
Therefore, the *root* role SHOULD require (t, n) keys, where n is the number of
either all PyPI administrators or all PSF board members, and t > 1 (so that at
least two members must sign the *root* role).

The *targets* role will be used only to sign for the static delegation of all
targets to the *bins* role.  Since these target delegations must be secured
against attacks in the event of a compromise, the keys for the *targets* role
MUST be offline and independent from other keys.  For simplicity of key
management without sacrificing security, it is RECOMMENDED that the keys of the
*targets* role be permanently discarded as soon as they have been created and
used to sign for the role.  Therefore, the *targets* role SHOULD require (1, 1)
keys.  Again, this is because the keys are going to be permanently discarded,
and more offline keys will not help against key recovery attacks [21]_ unless
diversity of keys is maintained.


Online and Offline Keys Recommended for Each Role
-------------------------------------------------

In order to support continuous delivery, the *timestamp*, *snapshot*, *bins*
role keys MUST be online.

As explained in the previous section, the *root*, and *targets* role keys MUST
be offline for maximum security.  Developers keys will be offline in the sense
that the private keys MUST NOT be stored on PyPI, though some of them may be
online on the private infrastructure of the project.


How Should Metadata be Generated?
=================================

Project developers expect the distributions they upload to PyPI to be
immediately available for download.  Unfortunately, there will be problems when
there are many readers and writers simultaneously accessing the same metadata
and distributions.  An example is a mirror attempting to sync with PyPI.
Suppose that PyPI has timestamped a *snapshot* at version 1.  A mirror is later
in the middle of copying PyPI at this snapshot.  While the mirror is copying
PyPI at this snapshot, PyPI timestamps a new snapshot at, say, version 2.
Without accounting for consistency, the mirror would then find itself with a
copy of PyPI in an inconsistent state, which is indistinguishable from
arbitrary metadata or package attacks.  The problem would also apply when the
mirror is substituted with a pip user.


Consistent Snapshots
--------------------

There are problems of consistency on PyPI with or without TUF.  TUF requires
its metadata to be consistent with the data, but how would the metadata be kept
consistent with projects that change all the time?  As a result, this proposal
MUST address the problem of producing a consistent snapshot that captures the
state of all known projects at a given time.  Each snapshot can safely coexist
with any other snapshot, and deleted independently without affecting any other
snapshot.

The solution presented in this PEP is that every metadata or data file written
to disk MUST include in its filename the `cryptographic hash`__ of the file.
How would this help clients that use the TUF protocol to securely and
consistently install or update a project from PyPI?

__ https://en.wikipedia.org/wiki/Cryptographic_hash_function

The first step in the TUF protocol requires the client to download the latest
*timestamp* metadata.  However, the client would not know in advance the hash
of the *timestamp* metadata file from the latest snapshot.  Therefore, PyPI
MUST redirect all HTTP GET requests for *timestamp* metadata to the *timestamp*
metadata file from the latest snapshot.  Since the *timestamp* metadata is the
root of a tree of cryptographic hashes pointing to every other metadata or
target file that are meant to exist together for consistency, the client is
then able to retrieve any file from this snapshot by deterministically
including, in the request for the file, the hash of the file in the filename.
Assuming infinite disk space and no `hash collisions`__, a client may safely
read from one snapshot while PyPI produces another snapshot.

__ https://en.wikipedia.org/wiki/Collision_(computer_science)

In this simple but effective manner, PyPI is able to capture a consistent
snapshot of all projects and the associated metadata at a given time.  The next
subsection will explicate the implementation details of this idea.

This PEP does not prohibit using advanced file systems or tools to produce
consistent snapshots (such solutions are mentioned in the Appendix). There are
two important reasons for why the PEP chose this simple solution.  Firstly, the
solution does not mandate that PyPI use any particular file system or tool.
Secondly, the generic file-system based approach allows mirrors to use extant
file transfer tools such as rsync to efficiently transfer consistent snapshots
from PyPI. 


Producing Consistent Snapshots
------------------------------

Given a project, PyPI is responsible for updating the *bins* metadata (roles
delegated by the *bins* role and signed with an online key).  Every project
MUST upload its release in a single transaction.  The uploaded set of files is
called the "project transaction".  How PyPI MAY validate the files in a project
transaction will be discussed soon.  For now, focuse is placed on how PyPI will
respond to a project transaction.

Every metadata and target file MUST include in its filename the `hex digest`__
of its `SHA-256`__ hash.  For this PEP, it is RECOMMENDED that PyPI adopt a
simple convention of the form: digest.filename.ext, where filename is the
original filename without a copy of the hash, digest is the hex digest of the
hash, and ext is the filename extension.

__ http://docs.python.org/2/library/hashlib.html#hashlib.hash.hexdigest
__ https://en.wikipedia.org/wiki/SHA-2

When a project uploads a new transaction, a project transaction process MUST
add all new targets and relevant delegated *bins* metadata.  (We will see later
in this section why the *bins* role will delegate targets to a number of
delegated *bins* roles.)  Finally, the project transaction process MUST inform
the snapshot process about new delegated *bins* metadata.

Project transaction processes SHOULD be automated.  Project transaction
processes MUST also be applied atomically: either all metadata and targets, or
none of them, are added.  The project transaction and snapshot processes SHOULD
work concurrently.  Finally, project transaction processes SHOULD keep in
memory the latest *bins* metadata so that they will be correctly updated in new
consistent snapshots.

All project transactions MAY be placed in a single queue and processed
serially.  Alternatively, the queue MAY be processed concurrently in order of
appearance provided that the following rules are observed:

1. No pair of project transaction processes must concurrently work on the same
   project.

2. No pair of project transaction processes must concurrently work on
   *bins* projects that belong to the same delegated *bins* targets
   role.

These rules MUST be observed so that metadata is not read from or written to
inconsistently.


Snapshot Process
----------------

The snapshot process is fairly simple and SHOULD be automated.  The snapshot
process MUST keep in memory the latest working set of *root*, *targets* and
delegated targets metadata.  Every minute or so, the snapshot process will sign
for this latest working set.  (Recall that project transaction processes
continuously inform the snapshot process about the latest delegated targets
metadata in a concurrency-safe manner.  The snapshot process will actually sign
for a copy of the latest working set while the actual latest working set in
memory will be updated with information continuously communicated by project
transaction processes.)  Next, the snapshot process MUST generate and sign new
*timestamp* metadata that will vouch for the *snapshot* metadata generated in
the previous step.  Finally, the snapshot process MUST add new *timestamp* and
*snapshot* metadata representing the latest snapshot.

A few implementation notes are now in order.  So far, we have seen only that
new metadata and targets are added, but not that old metadata and targets are
removed.  Practical constraints are such that eventually PyPI will run out of
disk space to produce a new consistent snapshot.  In that case, PyPI MAY then
use something like a "mark-and-sweep" algorithm to delete sufficiently old
consistent snapshots: in order to preserve the latest consistent snapshot, PyPI
would walk objects beginning from the root (*timestamp*) of the latest
consistent snapshot, mark all visited objects, and delete all unmarked
objects.  The last few consistent snapshots may be preserved in a similar
fashion.  Deleting a consistent snapshot will cause clients to see nothing
thereafter but HTTP 404 responses to any request for a file in that consistent
snapshot.  Clients SHOULD then retry their requests with the latest consistent
snapshot.

All clients, such as pip using the TUF protocol, MUST be modified to download
every metadata and target file (except for *timestamp* metadata) by including,
in the request for the file, the cryptographic hash of the file in the
filename.  Following the filename convention recommended earlier, a request for
the file at filename.ext will be transformed to the equivalent request for the
file at digest.filename.ext.

Finally, PyPI SHOULD use a `transaction log`__ to record project transaction
processes and queues so that it will be easier to recover from errors after a
server failure.

__ https://en.wikipedia.org/wiki/Transaction_log


Key Compromise Analysis
=======================

Table 1 summarizes the kinds of attacks rendered possible by compromising a
threshold number of keys belonging to the TUF roles on PyPI.  Except for the
*timestamp* and *snapshot* roles, the pairwise interaction of role compromises
may be found by taking the union of both rows.




+-----------------+-------------------+----------------+--------------------------------+
| Role Compromise | Malicious Updates | Freeze Attack  |  Metadata Inconsistency Attack |
+=================+===================+================+================================+
|    timetamp     |       NO          |       YES      |       NO                       |
|                 | snapshot and      | limited by     | snapshot needs to cooperate    |
|                 | targets or any    | earliest root, |                                |
|                 | of the bins need  | targets, or    |                                |
|                 | to cooperate      | bin expiry     |                                |
|                 |                   | time           |                                |
+-----------------+-------------------+----------------+--------------------------------+
|    snapshot     |       NO          |       NO       |       NO                       |
|                 | timestamp and     | timestamp      | timestamp needs to cooperate   |
|                 | targets or any of | needs to       |                                |
|                 | the bins need to  | cooperate      |                                |
|                 | cooperate         |                |                                |
+-----------------+-------------------+----------------+--------------------------------+
|    timestamp    |       NO          |       YES      |       YES                      |
|    **AND**      | targets or any    | limited by     | limited by earliest root,      |
|    snapshot     | of the bins need  | earliest root, | targets, or bin metadata       |
|                 | to cooperate      | targets, or    | expiry time                    |
|                 |                   | bin metadata   |                                |
|                 |                   | expiry time    |                                |
+-----------------+-------------------+----------------+--------------------------------+
|    targets      |       NO          | NOT APPLICABLE |        NOT APPLICABLE          |
|    **OR**       | timestamp and     | need timestamp | need timestamp and snapshot    |
|    bin          | snapshot need to  | and snapshot   |                                |
|                 | cooperate         |                |                                |
+-----------------+-------------------+----------------+--------------------------------+
|   timestamp     |       YES         |       YES      |       YES                      |
|   **AND**       |                   | limited by     | limited by earliest root,      |
|   snapshot      |                   | earliest root, | targets, or bin metadata       |
|   **AND**       |                   | targets, or    | expiry time                    |
|   bin           |                   | bin metadata   |                                |
|                 |                   | expiry time    |                                |
+-----------------+-------------------+----------------+--------------------------------+
|     root        |       YES         |       YES      |       YES                      |
+-----------------+-------------------+----------------+--------------------------------+

Table 1: Attacks possible by compromising certain combinations of role keys.


In September 2013, we showed how the latest version of pip (at the time) was
susceptible to these attacks and how TUF could protect users against them
[14]_.

Note that compromising *targets* or any delegated targets role (except for
project targets metadata) does not immediately endow the attacker with the
ability to serve malicious updates.  The attacker must also compromise the
*timestamp* and *snapshot* roles (which are both online and therefore more
likely to be compromised).  This means that in order to launch any attack, one
must be not only be able to act as a man-in-the-middle but also compromise the
*timestamp* key (or the *root* keys and sign a new *timestamp* key).  To launch
any attack other than a freeze attack, one must also compromise the *snapshot*
key.

Finally, a compromise of the PyPI infrastructure MAY introduce malicious
updates to *bins* projects because the keys for these roles are online.


In the Event of a Key Compromise
--------------------------------

A key compromise means that the key as well as PyPI infrastructure has been
compromised and used to sign new metadata on PyPI.

If a threshold number of *timestamp*, *snapshot*, or *bins* keys have
been compromised, then PyPI MUST take the following steps:

1. Revoke the *timestamp*, *snapshot* and *targets* role keys from
   the *root* role.  This is done by replacing the compromised *timestamp*,
   *snapshot* and *targets* keys with newly issued keys.

2. Revoke the *bins* keys from the *targets* role by replacing their keys
   with newly issued keys.  Sign the new *targets* role metadata and discard the
   new keys (because, as we explained earlier, this increases the security of
   *targets* metadata).

3. All targets of the *bins* roles SHOULD be compared with the last known
   good consistent snapshot where none of the *timestamp*, *snapshot*, or
   *bins* keys
   were known to have been compromised.  Added, updated or deleted targets in
   the compromised consistent snapshot that do not match the last known good
   consistent snapshot MAY be restored to their previous versions.  After
   ensuring the integrity of all *bins* targets, the *bins* metadata
   MUST be regenerated.

4. The *bins* metadata MUST have their version numbers incremented, expiry
   times suitably extended and signatures renewed.

5. A new timestamped consistent snapshot MUST be issued.

This would preemptively protect all of these roles even though only one of them
may have been compromised.

If a threshold number of the *root* keys have been compromised, then PyPI MUST
take the steps taken when the *targets* role has been compromised as well as
replace all of the *root* keys.

It is also RECOMMENDED that PyPI sufficiently document compromises with
security bulletins.  These security bulletins will be most informative when
users of pip-with-TUF are unable to install or update a project because the
keys for the *timestamp*, *snapshot* or *root* roles are no longer
valid.  They could then visit the PyPI web site to consult security bulletins
that would help to explain why they are no longer able to install or update,
and then take action accordingly.  When a threshold number of *root* keys have
not been revoked due to a compromise, then new *root* metadata may be safely
updated because a threshold number of existing *root* keys will be used to sign
for the integrity of the new *root* metadata so that TUF clients will be able
to verify the integrity of the new *root* metadata with a threshold number of
previously known *root* keys.  This will be the common case.  Otherwise, in the
worst case where a threshold number of *root* keys have been revoked due to a
compromise, an end-user may choose to update new *root* metadata with
`out-of-band`__ mechanisms.

__ https://en.wikipedia.org/wiki/Out-of-band#Authentication


Auditing Snapshots
------------------

If a malicious party compromises PyPI, they can sign arbitrary files with any
of the online keys.  The roles with offline keys (i.e., *root* and *targets*)
are still protected.  To safely recover from a repository compromise, snapshots
should be audited to ensure files are only restored to trusted versions.

When a repository compromise has been detected, the integrity of three types of
information must be validated:

1. If the online keys of the repository have been compromised, they can be
revoked by having the *targets* role sign new metadata delegating to a new key.

2. If the role metadata on the repository has been changed, this would impact
the metadata that is signed by online keys.  Any role information created since
the last period should be discarded. As a result, developers of new projects
will need to re-register their projects.

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
hash.  Alternatively, PyPI may also periodically archive its own versions of
*snapshot* rather than rely on externally provided metadata.  In this case,
PyPI SHOULD take the cryptographic hash of every package on the repository and
store this data on an offline device. If any package hash has changed, this
indicates an attack.

As for attacks that serve different versions of metadata, or freeze a version
of a package at a specific version, they can be handled by TUF with techniques
like implicit key revocation and metadata mismatch detection [81].


Appendix A: Extension
=====================

The maximum security model and end-to-end signing have been intentionally
excluded from this PEP.  Although both improve PyPI's ability to survive a
repository compromise and allow developers to sign their distributions, they
have been postponed as a potential future extension to PEP 458.  PEP XXX, which
discusses the extension in detail, is available for review to those developers
interested in the end-to-end signing option.  The maximum security model and
end-to-end signing are briefly covered in the subsections that follow.

There are several reasons for not initially supporting the features discussed
in this section:

1. A build farm (distribution wheels on supported platforms are generated on
PyPI infrastructure for each project) may possibly complicate matters.  PyPI
wants to support a build farm in the future.  Unfortunately, if wheels are
auto-generated externally, developer signatures for these wheels are unlikely.
However, there might still be a benefit to generating wheels from source
distributions that *are* signed by developers (provided reproducible wheels are
possible).  Another possibility is to optionally delegate trust of these wheels
to an online role.

2. An easy-to-use key management solution is needed for developers.
`miniLock`__ is one likely candidate for management and generation of keys.
Although developer signatures can be left as an option, this approach may be
insufficient due to the great number of unsigned dependencies that can occur
for a signed distribution requested by a client.  Requiring developers to
manually sign distributions and manage keys is expected to render key signing
an unused feature.

__ https://minilock.io/

3. A two-phase approach, where the minimum security model is first implemented
followed by the maximum security model, can simplify matters and give PyPI
administrators time to review the feasiblity of end-to-end signing.   


Maximum Security Model
----------------------

The maximum security model relies on developers signing their projects and
uploading signed metadata to PyPI.  If the PyPI infrastructure were to be
compromised, attackers would be unable to serve malicious versions of claimed
projects without access to the project's developer key.  Figure 2 depicts the
changes made to figure 1, namely that developer roles are now supported, and
that three new targets roles exist: *claimed*, *recently-claimed*, and
*unclaimed*.  The *bins* role has been renamed *unclaimed* and can contain any
projects that have not been added to *claimed*.  The strength of this model over
the minimum security model is in the offline keys provided by developers.  Although
the minimum securuity model supports continuous delivery, all of the projects
are signed by an online key.  An attacker can corrupt package in the first,
but not in the second without also compromising a developer's key.

.. image:: figure2.png

Figure 2: An overview of the metadata layout in the maximum security model.
The maximum Security model supports continuous delivery and survivable key
compromise.


End-to-End Signing
------------------

End-to-End signing allows both PyPI and developers to sign for the metadata
downloaded by clients.  PyPI is trusted to make uploaded projects available to
clients (they sign the metadata for this part of the process), and developers
can sign the distributions they upload.

PEP XXX will discuss the tools available to developers who sign the
distributions they upload to PyPI.  In summary, developers will generate
cryptographic keys and sign metadata in some automated fashion, where the
metadata includes the information required to verify the authenticity of the
distribution.  The metadata is then uploaded to PyPI where it will be available
for download by package managers such as pip (i.e., package managers that
support TUF metadata).  The entire process is transparent to clients (using a
package manager that supports TUF) who download distributions from PyPI.


Appendix: Rejected Proposals
============================

Alternative Proposals for Producing Consistent Snapshots
--------------------------------------------------------

The complete file snapshot (CFS) scheme uses file system directories to store
efficient consistent snapshots over time.  In this scheme, every consistent
snapshot will be stored in a separate directory, wherein files that are shared
with previous consistent snapshots will be `hard links`__ instead of copies.

__ https://en.wikipedia.org/wiki/Hard_link

The `differential file`__ snapshot (DFS) scheme is a variant of the CFS scheme,
wherein the next consistent snapshot directory will contain only the additions
of new files and updates to existing files of the previous consistent snapshot.
(The first consistent snapshot will contain a complete set of files known
then.)  Deleted files will be marked as such in the next consistent snapshot
directory.  This means that files will be resolved in this manner: First, set
the current consistent snapshot directory to be the latest consistent snapshot
directory.  Then, any requested file will be seeked in the current consistent
snapshot directory.  If the file exists in the current consistent snapshot
directory, then that file will be returned.  If it has been marked as deleted
in the current consistent snapshot directory, then that file will be reported
as missing.  Otherwise, the current consistent snapshot directory will be set
to the preceding consistent snapshot directory and the previous few steps will
be iterated until there is no preceding consistent snapshot to be considered,
at which point the file will be reported as missing.

__ http://dl.acm.org/citation.cfm?id=320484

With the CFS scheme, the trade-off is the I/O costs of producing a consistent
snapshot with the file system.  As of October 2013, we found that a fairly
modern computer with a 7200RPM hard disk drive required at least three minutes
to produce a consistent snapshot with the "cp -lr" command on the ext3__ file
system.  Perhaps the I/O costs of this scheme may be ameliorated with advanced
tools or file systems such as LVM__, ZFS__ or btrfs__.

__ https://en.wikipedia.org/wiki/Ext3
__ http://www.tldp.org/HOWTO/LVM-HOWTO/snapshots_backup.html
__ https://en.wikipedia.org/wiki/ZFS
__ https://en.wikipedia.org/wiki/Btrfs

While the DFS scheme improves upon the CFS scheme in terms of producing faster
consistent snapshots, there are at least two trade-offs.  The first is that a
web server will need to be modified to perform the "daisy chain" resolution of
a file.  The second is that every now and then, the differential snapshots will
need to be "squashed" or merged together with the first consistent snapshot to
produce a new first consistent snapshot with the latest and complete set of
files.  Although the merge cost may be amortized over time, this scheme is not
conceptually si




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


Acknowledgements
================

This material is based upon work supported by the National Science Foundation
under Grant No. CNS-1345049 and CNS-0959138. Any opinions, findings, and
conclusions or recommendations expressed in this material are those of the
author(s) and do not necessarily reflect the views of the National Science
Foundation.

Nick Coghlan, Daniel Holth and the distutils-sig community in general for
helping us to think about how to usably and efficiently integrate TUF with
PyPI.

Roger Dingledine, Sebastian Hahn, Nick Mathewson,  Martin Peck and Justin
Samuel for helping us to design TUF from its predecessor Thandy of the Tor
project.

Konstantin Andrianov, Geremy Condra, Vladimir Diaz, Zane Fisher, Justin Samuel,
Tian Tian, Santiago Torres, John Ward, and Yuyu Zheng for helping us to develop
TUF.

Vladimir Diaz, Monzur Muhammad and Sai Teja Peddinti for helping us to review
this PEP.

Zane Fisher for helping us to review and transcribe this PEP.


Copyright
=========

This document has been placed in the public domain.
