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
essentially no cost. In essence, this document defines a new message type
called split commit which replaces regular MLS commits. Unlike regular commits,
a split commit can be "split" by the Delivery Service (DS) into much smaller
per-member commits, one for each receiving member. The size of a per-member
commit is always logarithmic in the group size, while the size of a regular
MLS commit can be linear. This extension works in settings with a DS that can
do the splitting which can be demanding with encrypted MLS handshake messages.
This is motivated by academic research {{HKP22}}, {{HKPPW22}}, {{AHKM33}}.


--- middle

# Introduction

## Protocol Overview

Consider the example ratchet tree from {{Section 7.4 of !RFC9420}}:

~~~ aasvg
      Y
      |
    .-+-.
   /     \
  X       Z[C]
 / \     / \
A   B   C   D

0   1   2   3
~~~
{: #evolution-tree title="A Full Tree with One Unmerged Leaf" }

In a group with a ratchet tree of this form, if member 0 were to commit, they
would compute two updated path secrets X' and Y', and three encrypted versions
of these path secrets:

1. X' encrypted to B
2. Y' encrypted to C
3. Y' encrypted to D

With a normal MLS Commit, all three of these encrypted values are sent to each
other member -- even though each member can only decrypt one of the encrypted
values.  Since the number of encrypted values can grow linearly as the size of
the group, in the worst case, this creates quadratic data to be transmitted.

With split Commits, each member receives only what they decrypt.  The
committer can make individual messages for each member, or they can emit a
single message with all encrypted values, which the DS can use to construct
per-member messages.  We call the per-member messages PerMemberCommits, and the
message carrying all of the encrypted values a SplitCommit.

~~~ aasvg
A          B          C          D
| E(B; X') |          |          |
+--------->|          |          |
|          |          |          |
| E(C; Y') |          |          |
+-------------------->|          |
|          |          |          |
| E(D; Y') |          |          |
+------------------------------->|
|          |          |          |
~~~
{: #server-aided-direct title="A committer creates per-member commits" }

~~~ aasvg
A          DS         B          C          D
| E(B; X') |          |          |          |
| E(C; Y') |          |          |          |
| E(D; Y') |          |          |          |
+--------->|          |          |          |
|          |          |          |          |
|          | E(B; X') |          |          |
|          +--------->|          |          |
|          |          |          |          |
|          | E(C; Y') |          |          |
|          +-------------------->|          |
|          |          |          |          |
|          | E(D; Y') |          |          |
|          +------------------------------->|
|          |          |          |          |
~~~
{: #server-aided-ds title="The DS creates per-member commits" }


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Split Commits

A Split Commit uploaded to the DS consists of two parts.  First, it contains a
SplitUpdatePath object which is a regular UpdatePath defined in {!RFC9420}}
but without the committer's LeafNode. Second, it contains a `split_commit_message`
MlsMessage (PublicMessage or PrivateMessage) which includes an epoch identifier,
the committed list of proposals and the committer's LeafNode.

The `split_commit_message` is signed and encrypted, while SplitUpdatePath is not.
The reason is that the DS includes in per-member commits only parts of the
SplitUpdatePath and receivers can still verify authenticity and decrypt all that
is needed. (The `split_commit_message` must be delivered in full but its size is
worst-case logarithmic.) The lack of encryption for SplitUpdatePath is not a problem
because it contains only HPKE public keys and ciphertexts. The proposals and
LeafNode (the latter containing a credential) are encrypted. 

The purpose of the epoch identifier is to provide authenticity. In particular,
with Split Commit, the committer does not sign the HPKE keys they chose for their
updated path in the ratchet tree. However, we need authenticity for these keys
(else the adversary can replace them by their own). Thus, the committer signs instead
(as part of message framing) the epoch identifier that binds the tree hash of the new
epoch. In particular, the epoch identifier is derived from the new epoch's key
schedule.

~~~ tls-presentation
struct {
    UpdatePathNode nodes<V>;
} SplitUpdatePath;

struct {
    opaque epoch_identifier<V>;
    ProposalOrRef proposals<V>;
    optional<LeafNode> leaf_node;
} SplitCommit;

struct {
    // PrivateMessage or PublicMessage
    MLSMessage split_commit_message;
    optional<SplitUpdatePath> path;
} SplitCommitMessage;

struct {
    // PrivateMessage or PublicMessage
    // content_type = split_commit
    MLSMessage split_commit_message;

    optional<HPKECiphertext> encrypted_path_secret;
} PerMemberCommit;
~~~

The SplitCommit object is a new content type and SplitCommitMessage is a new
wire format. Other MLS objects account for this as specified below.

~~~ tls-presentation
enum {
    reserved(0),
    application(1),
    proposal(2),
    commit(3),
    split_commit(4),
    (255)
} ContentType;

struct {
    opaque signature<V>;
    select (FramedContent.content_type) {
        case commit:
            MAC confirmation_tag;
        case application:
        case proposal:
        case split_commit:
            struct{};
    };
} FramedContentAuthData;

struct {
    opaque group_id<V>;
    uint64 epoch;
    Sender sender;
    opaque authenticated_data<V>;

    ContentType content_type;
    select (FramedContent.content_type) {
        case application:
          opaque application_data<V>;
        case proposal:
          Proposal proposal;
        case commit:
          Commit commit;
        case split_commit:
          SplitCommit split_commit;
    };
} FramedContent;

struct {
    ProtocolVersion version = mls10;
    WireFormat wire_format;
    select (MLSMessage.wire_format) {
        case mls_public_message:
            PublicMessage public_message;
        case mls_private_message:
            PrivateMessage private_message;
        case mls_welcome:
            Welcome welcome;
        case mls_group_info:
            GroupInfo group_info;
        case mls_key_package:
            KeyPackage key_package;
        case mls_split_commit:
            SplitCommitMessage split_commit_message;
    };
} MLSMessage;
~~~

A committing group member generates a SplitCommitMessage using the following
steps:
1. Perform a regular MLS commit, without message framing.
2. Export a secret `epoch_identifier` from the new epoch with the label
   "SplitCommit".
3. Generate a SplitCommit object `split_commit` with `epoch_identifier` from
   Step 2 and `leaf_node` from `path` in the commit generated in Step 1.
4. Generate MlsMessage `split_commit_message` by framing `split_commit`.
5. Output SplitCommitMesage with `path` including `nodes` from `path` in the
   commit in Step 1, `epoch_identifier` from Step 2 and `split_commit_message`
   from Step 4.

If the DS knows the ratchet trees before and after the split commit, it
generates a PerMemberCommit for a receiver group member from a SplitCommit
member as follows by choosing from the SplitUpdatePath only the HPKECiphertext
for the receiver. If the SplitCommit does not contain the SplitUpdatePath
or the commit removes the receiver, the PerMemberCommit does not include
the HPKECiphertext.

{{Delivering Split Commits without the Ratchet Tree}} considers DS's that do not
know the ratchet tree.

A receiver group member processes a PerMemberCommit using the following steps:
1. Process the `split_commit_message` MLSMessage to recover `split_commit`.
2. Recover `path_secret` decrypting that HPKECiphertext.
3. Use `path_secret`, public keys from `path` and `proposals` to process the
   commit as specified in {{!RFC9420}}.
4. Verify that `epoch_identifier` in `split_commit` matches the secret exported
   from the new epoch with the label "SplitCommit" .


# Transcript Hashes

With split commits, the input to the confirmed transcript hash is the same as
in {{!RFC9420}}. In particular, it contains the FramedContent with a
SplitCommit object inside. Split commits contain no confirmation tags, so the
interim transcript hash is simply equal to the confirmed transcript hash.


# Delivering Split Commits without the Ratchet Tree

If the DS does not know the ratchet tree, then it cannot determine which
ciphertexts to deliver to which members. Dealing with this is outside the scope
of this document.

In general, there are several ways to deal with this. For example, the sender
can annotate the ciphertexts in the split commit. Alternatively, the receiver
can "pull" the split commit without `path`, identify the sender and indicate
the index of the ciphertext it expects before pulling it. However, most DS's
work in the push not pull model and are therefore incompatible with this
solution.


# Security Considerations

## Transcript Hashes

The transcript hash with split commits covers FramedContent with a SplitCommit
that contains `epoch_identifier`, `proposals` and `leaf_node`. The transcript
hash with regular commits covers FramedContent with a Commit that contains
`proposals`, `leaf_node` and `path`, as well as the confirmation tag.

Since `epoch_identifier` is derived from the key schedule and the tree hash of
the new epoch is mixed into the key schedule, the transcript hash with split
commits binds the public keys from `path`. There is no security-related reason
to agree on ciphertexts, so there is no reason to include `path` in the
transctipt hash. Note that group members do agree on *content* of the
ciphertexts in `path`. That is, they agree on the commit secret hashed into
the key schedule (and used to derive `epoch_identifier`), so they also agree
on all path secrets that they can derive (assuming no hash collisions).


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
