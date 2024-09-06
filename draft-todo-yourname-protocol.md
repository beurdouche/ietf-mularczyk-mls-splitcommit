---
###
# Internet-Draft Markdown Template
#
# Rename this file from draft-todo-yourname-protocol.md to get started.
# Draft name format is "draft-<yourname>-<workgroup>-<name>.md".
#
# For initial setup, you only need to edit the first block of fields.
# Only "title" needs to be changed; delete "abbrev" if your title is short.
# Any other content can be edited, but be careful not to introduce errors.
# Some fields will be set automatically during setup if they are unchanged.
#
# Don't include "-00" or "-latest" in the filename.
# Labels in the form draft-<yourname>-<workgroup>-<name>-latest are used by
# the tools to refer to the current version; see "docname" for example.
#
# This template uses kramdown-rfc: https://github.com/cabo/kramdown-rfc
# You can replace the entire file if you prefer a different format.
# Change the file extension to match the format (.xml for XML, etc...)
#
###
title: "TODO - Your title"
abbrev: "TODO - Abbreviation"
category: info

docname: draft-todo-yourname-protocol-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: AREA
workgroup: WG Working Group
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: WG
  type: Working Group
  mail: WG@example.com
  arch: https://example.com/WG
  github: USER/REPO
  latest: https://example.com/LATEST

author:
 -
    fullname: Your Name Here
    organization: Your Organization Here
    email: your.email@example.com

normative:

informative:
  HKP22: DOI.10.1145/3548606.35606
  HKPPW22: DOI.10.1145/3460120.3484817
  AHKM22: DOI.10.1145/3548606.3560632

--- abstract

This document describes an extension to the MLS protocol {{!RFC940}} that
improves its efficiency in terms of per-member download size. This comes at
esssentially no cost. In essence, this document defines a new message type
called split commit which replaces regular MLS commits. Unlike regular commits,
a split commit can be "split" by the Delivery Service (DS) into much smaller
split commits, one for each receiving member. The size of a downloaded split
commit is always logarithmic in the group size, while the size of a regular
MLS commit can be linear. This extension works in settings with a DS that can
do the splitting which can be demanding with encrypted MLS handshake messages.


--- middle

# Introduction

The MLS protocol requires a Delivery Service (DS), one function of which is to
distribute protocol packets between group members.

TODO Introduction

This is motivated by academic research {{HKP22}}, {{HKPPW22}}, {{AHKM33}}.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Transcript Hashes

TODO instead of the whole commit, use proposals. Everything else we care for is
in the context.  


# Split Commits

The following structure describes a split commit which group members upload and
download instead of regular commits.

~~~ tls-presentation
struct {
    opaque epoch_identifier<V>;
    ProposalOrRef proposals<V>;
    /* SignWithLabel(., "SplitCommitTBS", SplitCommitTBS) */
    opaque signature<V>;
    optional<UpdatePath> path; // TODO consider using MLS Commit struct
    optional<opaque> mac_tag<V>; // TODO how to make optional blob?
} SplitCommit;

struct {
    opaque epoch_identifier<V>;
    ProposalOrRef proposals<V>;
} SplitCommitTBS;
~~~

A committing group member generates SplitCommit using the following steps:
1. Perform a regular MLS commit, without message framing.
2. Export a secret `epoch_identifier` from the new epoch with the label
   "SplitCommit".
3. Generate `signature` using SignWithLabel(., "SplitCommitTBS",
   SplitCommitTBS) where SplitCommitTBS contains `epoch_identifier` from
   Step 2 and `proposals` from the commit generated in Step 1.
4. If the commit removes a member, compute `mac_tag = MAC(membership_key,
   SplitCommitTBS)`.
   [TODO: make new MAC key]
5. Output SplitCommit with `proposals` and `path` from the commit from Step 1,
   `epoch_identifier` from Step 2, `signature` from Step 3 and `mac_tag` from
   Step 4 if generated.

The DS processes a SplitCommit before delivering it to a receiver group member
as follows:
1. If the receiver remains in the group after the commit:
  * Remove from `path` all ciphertexts except the one that the receiver will
    decrypt.
  * Remove from `path` all nodes for which the receiver can derive public keys,
    that is all nodes on the path from the LCA of the receiver and the
    committer to the root (inclusive)
    [TODO: this will likely NOT work since AFAIR the NEW context is used to do
    HPKE encryption, so we need all path to decrypt. I don’t know how this
    helps security in any way.]
  * Remove the `mac_tag`
2. Else if the commit removes the receiver
  * Remove the `path`

A receiver group member who remains in the group after the commit processes a
SplitCommit using the following steps:
1. Verify that `path` contains exactly one ciphertext.
2. Process `path` and `proposals` as a regular MLS commit.
3. Export a secret `epoch_identifier` from the new epoch with the label
   "SplitCommit".
4. Verify `signature` on `SplitCommitTBS` containing `epoch_identifier` and
   `proposals`.

A receiver group member who is removed in the commit processes it by verifying
all of the following:
* `mac_tag` is a valid MAC on `SplitCommitTBS` and
* `signature` is a valid signature on `SplitCommitTBS` and
* one of `proposals` removes it.

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
