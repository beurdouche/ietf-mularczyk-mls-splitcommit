---
title: "Server Aided MLS"
abbrev: "SA-MLS"
category: info

docname: draft-mularczyk-mls-splitcommit-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: AREA
workgroup: MLS
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
    fullname: Marta Mularczyk
    organization: AWS Wickr
    email: mulmarta@amazon.com

normative:

informative:
  KKP22: DOI.10.1007/978-3-030-64837-4\_10
  HKPPW22: DOI.10.1145/3460120.3484817
  AHKM22: DOI.10.1145/3548606.3560632

--- abstract

This document describes an extension to the MLS protocol {{!RFC940}} that
improves MLS's efficiency by reducing the amount of data members must download.
This comes at essentially no cost as it has no impact on security nor the
computational cost of MLS. The extension consists of two new message types. The
first, a "splittable commit", replaces regular MLSCommits. Unlike regular
commits, a splittable commit can be split up by the Delivery Service (DS)
into much smaller "per-member commits"; one for each receiving member. The size
of a per-member commit is (at most) logarithmic in the group size, while the
size of regular MLSCommits can reach linear. This extension works in settings
with a DS that can do the splitting which can be demanding with encrypted MLS
handshake messages. The extension is based on academic research {{KKP22}},
{{HKPPW22}}, {{AHKM22}}.


--- middle

# Introduction

## Protocol Overview

The Server Aided MLS extension restructures how commits to allow the DS to only
forward to a given receiver, the minimal information about the commit needed
for the receiver to process the commit. The following scenario examplifies the
redundant data in a regular MLSCommit which this extension drops.

Consider the example ratchet tree from {{Section 7.4 of !RFC9420}}:

~~~~~
      Y
      |
    .-+-.
   /     \
  X       Z[C]
 / \     / \
A   B   C   D

0   1   2   3
~~~~~
{: #evolution-tree title="A Full Tree with One Unmerged Leaf" }

In an MLS group with a ratchet tree of this form, a commit by member 0 includes
computing two updated path secrets X' and Y', new public keys for nodes X and
Y and three HPKE ciphertexts:

1. X' encrypted to B
2. Y' encrypted to Z
3. Y' encrypted to C

A MLS's regular Commit message includes the both new public keys and
ciphertexts which is then all downloaded by each member. Yet, each receiver
decrypts no more than one of the ciphertexts and can compute at least one
(or even two, for party 1) of the new public keys themselves. Therefor, a
substantial amount of the downloaded data ends up being redundnat.

Instead, using this extension's individualized commit messages, each member
receives only the one ciphertext they will actually decrypt and only the new
public keys they cannot re-derive on their own. One way to do this (e.g. when
the DS is not tracking the ratchet tree for the group) is for the committer to
directly create and send the individualized commit messages. Alternatively, the
committer can create a single large commit message containing all ciphertexts
and new public keys. Then the DS can split the large commit into individualized
commit messages for download by recipients.

In this extension, an individualised commit is represented as an
PerMemberCommit object while the large commits carrying all ciphertexts and
new public keys is represented as an SCommit object.

~~~~~
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
~~~~~
{: #server-aided-direct title="A committer creates per-member commits" }

~~~~~
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
~~~~~
{: #server-aided-ds title="The DS creates per-member commits" }


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# SCommits

A split commit is represented as an SCommit object which consists of two
parts. The first, is an SUpdatePath object which is a regular UpdatePath
defined in {!RFC9420}} but without the committer's LeafNode. The second part is
an MlsMessage (either a PublicMessage or PrivateMessage) called
`scommit_broadcast_message`. It is created from a framed SCommitBroadcast
object which includes the information about the SCommit that should be
delivered to all receivers; namely, an epoch identifier, the committed list of
proposals and the committer's LeafNode. (The `scommit_broadcast_message` must
be delivered in full to all members but its size is usually independent of the
group size.) To accomodate framing an SCommitBroadcast object, the
FramedContent and FramedContentAuthData objects are extended to account for the
new content type `scommit_broadcast`.

An individualized commit is represented as a PerMemberCommit object. It is
identical to an SCommit except that, instead of the complete SUpdatePath, it
contains just the one HPKE ciphertext from SUpdatePath that the receiver can
actually decrypt and only those new HPKE public keys that the receiver cannot
re-derive on their own.

~~~ tls-presentation
struct {
    UpdatePathNode nodes<V>;
} SUpdatePath;

struct {
    opaque epoch_identifier<V>;
    ProposalOrRef proposals<V>;
    optional<LeafNode> leaf_node;
} SCommitBroadcast;

enum {
    reserved(0),
    application(1),
    proposal(2),
    commit(3),
    scommit_broadcast(4),
    (255)
} ContentType;

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
        case scommit_broadcast:
          SCommitBroadcast scommit_broadcast;
    };
} FramedContent;

struct {
    opaque signature<V>;
    select (FramedContent.content_type) {
        case commit:
            MAC confirmation_tag;
        case application:
        case proposal:
        case scommit_broadcast:
            struct{};
    };
} FramedContentAuthData;

struct {
    // PrivateMessage or PublicMessage
    MLSMessage scommit_broadcast_message;
    optional<SUpdatePath> path;
} SCommit;

struct {
   HPKECiphertext encrypted_path_secret;
   HPKPublicKey<V> new_pks;
} PartialSUpdatePath;

struct {
    // PrivateMessage or PublicMessage
    // content_type = scommit
    MLSMessage scommit_broadcast_message;
    optional<PartialSUpdatePath> partial_path;
} PerMemberCommit;
~~~

Finally, an SCommit (or PerMemberCommit) is sent by serializing it as an
MlsMessages. Accordingly, the MlsMessage struct has been extended to accomodate
the new `mls_scommit` and `mls_per_member_commit` content types.

~~~ tls-presentation
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
        case mls_scommit:
            SCommit scommit;
        case mls_per_member_commit
            PerMemberCommit
    };
} MLSMessage;
~~~

## Constructing a Splittable Commit.

A committing group member generates a SCommit object using the following steps:

1. Perform a regular MLSCommit, without message framing.
2. Generate an SCommitBroadcast object `scommit_broadcast` with the proposals
   and `leaf_node` from the commit in step 1. The `epoch_identifier` is
   exported from the new epoch with the label "SplittableCommit".
3. Create an SUpdatePath object `path` by removing the leaf node from the
   UpdatePath in the commit in step 1.
4. Frame the `scommit_broadcast` object and use it to create an MlsMessage
   `scommit_broadcast_message`.
6. Use the `scommit_broadcast_message` and `path` objects to populate an
   SCommit object. Serialize the SCommit object as an MlsMessaage with
   content type `mls_scommit`.

An SCommit without the optional SUPdatePath is essentially identical to the
corresponding PerMemberCommit for any receiver. If the SCommit does contain
an SUpdatePath then any party (e.g. the DS) who knows the ratchet tree created
by the splittable commit can convert an MlsMessage with an SCommit into an
MlSMessage with the PerMemberCommit for a designated receiver at leaf R.

1. The PerMemberCommit has the same `scommit_broadcast_message` as the SCommit.
2. The ciphertext in the `partial_path` is a copy of the (unique) ciphertext in
   the SUpdatePath of the SCommit which the receiver would decrypt were this a
   regular MLS Commit. (So either it is the ciphertext encrypted to leaf R
   because the receiver is still unmerged or a sibling of the committer, or it
   is encrypted to an ancestor of R on the commiter's co-path.)
3. The list of HPKEPublicKey elements in `partial_path` contains the new public
   keys which the receiver cannot compute on their own given the remaining
   data in the PerMemberCommit. That is, if D is the direct path of the
   committer in the new ratchet tree, then `partial_path` is the list of public
   keys of parent nodes on D that are not on the receiver's direct path. (The
   list order as the corresponding nodes appear in D.) For example, if the
   receiver is at the sibling leaf to the committer then `partial_path` has
   no new public keys at all.

No other new public keys are required in `partial_path`. The committer's leaf
(with its new public key) is already included in the
`scommit_broadcast_message` while the `path_secret` in the ciphertext in
`partial_path` can be used to derive the rest of the missing new public keys
along the receiver's own direct path.

{{delivering-scommits-without-the-ratchet-tree}} considers DS's that do not
know the ratchet tree.

A receiver group member processes a PerMemberCommit using the following steps:

1. Process the `scommit_broadcast` MLSMessage to recover `scommit`.
2. Recover `path_secret` decrypting that HPKECiphertext.
3. Use `path_secret`, public keys from `path` and `proposals` to process the
   commit as specified in {{!RFC9420}}.
4. Verify that `epoch_identifier` in `scommit` matches the secret exported
   from the new epoch with the label "SCommitBroadcast" .


# Transcript Hashes

With SCommits, the input to the confirmed transcript hash is the same as
in {{!RFC9420}}. In particular, it contains the FramedContent with a
SCommitBroadcast object inside. Split commits contain no confirmation tags, so
the interim transcript hash is simply equal to the confirmed transcript hash.


# Delivering SCommits without the Ratchet Tree

If the DS does not know the new epoch's ratchet tree, then it cannot determine
which ciphertexts and public keys to deliver to which members. Fortunately, if
the SCommit doesnt include an SUpdatePath then there's no need to convert it as
nothing needs to be filtered out for any receiver.

In general, there are several ways to help third parties split commits into
PerMemberCommits even without knowing the new epoch's ratchet tree.
For example, the sender can annotate the ciphertexts in the SCommit.
Alternatively, the receiver can "pull" the SCommit without `path`, identify the
sender and indicate the index of the ciphertext it expects before pulling it.
Further exploration of this case is outside the scope of this document.

# Security Considerations

## Transcript Hashes

The transcript hash for an SCommits includes the (framed) SCommitBroadcast
which includes the `epoch_identifier`, list of `proposals` and `leaf_node`. The
transcript hash for a regular MLS commit includes the framed Commit that
contains `proposals`, `leaf_node` and `path`, as well as the confirmation tag.

Since `epoch_identifier` is derived from the key schedule and the tree hash of
the new epoch is mixed into the key schedule, the transcript hash with split
commits binds the public keys from `path`. Agreeing on the exact ciphertext is
not required for MLS's security. More technically, the full `path` struct
does not have to be included in the transctipt hash.

Instead, its sufficent for group members to only agree on the *plaintexts* in
the `path` ciphertexts and the new public keys on the update path. Fortunately,
that information about `path` is bound by the `epoch_identifier` since the
`commit_secret` (which binds the plaintexts) and the `tree_hash` of the new
epoch (which binds the updated public keys) are both fed into the
key schedule from which `epoch_identifier` is exported.



## Authenticating and Encrypting Split Commits

Both in an SCommit and in a PerMemberCommit, the SCommitBroadcast objects are
signed and encrypted, while SUpdatePath and PartialSUpdatePath are not. This
lack of encryption compared to MLS is not a problem because the SUpdatePath
doesn't contain secrets (only public keys and ciphertexts). The (more
sensetive) proposals and LeafNode are encrypted as part of the
SCommitBroadcast.

The lack of signature (and MAC) for an SUpdatePath stems from the fact that
members receive individualized PerMemberCommit messages with different parts
of the original SUpdatePath object. Without the missing parts of SUPdatePath
they can not verify any signature (or MAC) over the full object. If instead,
a signature (or MAC) covering the PartialSUpdatePath then it becomes
impossible for third parties (such as the DS) to convert an SCommit into an
PerMemberCommit.

Fortunately, authenticating just the `scommit_broadcast` part does suffice to
still ensure the same security for splittable commits as provided by a
regular MLSCommit.

In MLS, commiters sign the confirmation tag (and the receivers recomputing them
to check the signature). This serves two purposes. First, it forces the sender
to demonstrate knowledge of the new epoch's key schedule to receivers
(preventing attacks where a commit is somehow manipulated while in transit by
an adversary knowing only the sender's signing key). Second, it ensures all
receivers that accept a given commit will always agree on any application
relevant properties about the new epoch.

SCommit's enjoy the same two properties by signing `scommit_broadcast` and
using epoch identifiers in place of confirmation tags. A confirmation tag in
MLS the confirmation binds everything about `path` (including the ciphertexts)
because `path` is fed into the new key schedule (via the transcript hash).
However, MLS only does this as way to get confirmation tags to bind the
*plaintexts* and public keys in `path`. (Since MLS does not use key-committing
encryption for payloads it also binds the keys used for decryption in the
confirmation tag.) Luckily, for an SCommit, An epoch identifier does bind those
values. After all, the identifier is derived from the new key schedule which is
derived (in part) from the previous `commit_secret` which binds the plaintexts
in `path`. Further, the new key schedule is also derived from the epoch's
`tree_hash` and that (together with the previous epoch's `tree_hash` which is
also in the derivation path) binds the new public keys in `path`.


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
